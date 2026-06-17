from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import wp


class WpCliTests(unittest.TestCase):
    def test_top_level_help(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = wp.main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("usage: wp <command> [options]", stdout.getvalue())

    def test_assess_help(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = wp.main(["assess", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("usage: wp assess [--fast|--full] [--use-api] [--out DIR] <URL>", stdout.getvalue())

    def test_normalize_target_requires_path(self) -> None:
        with self.assertRaises(wp.AssessError):
            wp.normalize_target_url("http://target/")
        self.assertEqual(
            wp.normalize_target_url("http://target/wordpress"),
            "http://target/wordpress/",
        )

    def test_parse_args_defaults(self) -> None:
        parsed = wp.parse_args(["http://target/wordpress/"])
        self.assertEqual(parsed["mode"], "normal")
        self.assertFalse(parsed["use_api"])
        self.assertEqual(parsed["out_dir"].name, "exports")

    def test_use_api_requires_token(self) -> None:
        with self.assertRaises(wp.AssessError):
            wp.run_wpscan("http://target/wordpress/", "fast", True, log_dir=Path("."))

    def test_render_markdown(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=False,
            wordpress_detected=True,
            login_page="200",
            wp_json="200",
            xmlrpc="unknown",
            xmlrpc_http_status="",
            xmlrpc_evidence="",
            version="6.4.3",
            plugins=[wp.Finding(name="akismet", version="5.2")],
            themes=[wp.Finding(name="twentytwentyfour", version="1.0")],
            users=[wp.UserFinding(username="admin")],
            http_checks=[wp.HttpCheck(path="wp-login.php", status="200")],
            exposure_checks=[wp.HttpCheck(path="readme.html", status="404")],
            next_actions=["XML-RPC enabled"],
            report_path=Path("report.md"),
            errors=[],
        )
        md = wp.render_markdown(result)
        self.assertIn("WordPress Assessment Report", md)
        self.assertIn("## Target", md)
        self.assertIn("Primary Source: `WPScan`", md)
        self.assertIn("Verification: `executed`", md)
        self.assertIn("## Report Mode", md)
        self.assertIn("Mode: Enumeration-only", md)
        self.assertIn("## Assessment", md)
        self.assertIn("## Warnings", md)
        self.assertIn("## Top Targets", md)
        self.assertIn("| Score | Target | Reason |", md)
        self.assertIn("| 70 | WordPress 6.4.3 | Version disclosure |", md)
        self.assertIn("| 55 | akismet 5.2 | Plugin detected |", md)
        self.assertIn("## Attack Surface", md)
        self.assertIn("## Investigation Queue", md)
        self.assertIn("### WordPress 6.4.3", md)
        self.assertIn("### User: admin", md)
        self.assertIn("## Server Information", md)
        self.assertNotIn("Evidence URL:", md)
        self.assertNotIn("Confidence: High\n\nEvidence:\n- Confidence:", md)
        self.assertIn("Attack Surface Count: `4`", md)
        self.assertIn("Verification: `executed`", md)
        self.assertNotIn("## Vulnerability Correlation", md)
        self.assertNotIn("## Vulnerability Summary", md)
        self.assertNotIn("## XML-RPC Assessment", md)
        self.assertNotIn("## Verification Result", md)
        self.assertIn("1. WordPress 6.4.3", md)
        self.assertNotIn("   - WordPress version identified", md)
        self.assertNotIn("### Critical\n- None", md)

    def test_top_targets_prioritize_upload_listing(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="full",
            use_api=False,
            wordpress_detected=True,
            login_page="200",
            wp_json="200",
            xmlrpc="reachable",
            xmlrpc_http_status="200",
            xmlrpc_evidence="XML-RPC response markers were returned",
            version="5.5.1",
            version_vulnerabilities=[],
            plugins=[],
            themes=[],
            users=[wp.UserFinding(username="elyana")],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            interesting_findings=[
                wp.InterestingFinding(
                    kind="upload_directory_listing",
                    title="Upload directory listing: /wp-content/uploads/",
                )
            ],
        )
        rows = wp.build_top_target_rows(result)
        self.assertEqual(rows[0][0], 70)
        self.assertEqual(rows[0][1], "WordPress 5.5.1")
        self.assertEqual(rows[1][1], "uploads directory listing")
        self.assertEqual(rows[2][1], "User: elyana")
        self.assertEqual(rows[3][1], "XML-RPC")
        self.assertEqual(len(rows), 4)
        self.assertEqual(
            wp.build_next_actions(result),
            ["WordPress 5.5.1", "uploads directory listing", "User: elyana"],
        )
        self.assertTrue(any(entry.title == "XML-RPC" for entry in wp.build_attack_surface(result)))

    def test_vulnerability_summary_marks_lfi_and_sqli_as_critical(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=True,
            wordpress_detected=True,
            login_page="200",
            wp_json="200",
            xmlrpc="reachable",
            xmlrpc_http_status="200",
            xmlrpc_evidence="XML-RPC response markers were returned",
            version="5.5.1",
            themes=[],
            users=[],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            plugins=[
                wp.Finding(
                    name="mail-masta",
                    version="1.0",
                    vulnerabilities=[
                        wp.VulnerabilityFinding(title="Mail Masta <= 1.0 - Unauthenticated Local File Inclusion"),
                        wp.VulnerabilityFinding(title="Mail Masta 1.0 - Multiple SQL Injection"),
                    ],
                )
            ],
        )
        summary = wp.build_vulnerability_summary(result)
        self.assertTrue(any("mail-masta 1.0" in item and "Local File Inclusion" in item for item in summary["Critical"]))
        self.assertTrue(any("mail-masta 1.0" in item and "Multiple SQL Injection" in item for item in summary["Critical"]))

    def test_readme_is_deduped_into_single_target(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=True,
            wordpress_detected=True,
            login_page="200",
            wp_json="200",
            xmlrpc="reachable",
            xmlrpc_http_status="200",
            xmlrpc_evidence="XML-RPC response markers were returned",
            version="5.5.1",
            plugins=[],
            themes=[],
            users=[],
            http_checks=[],
            exposure_checks=[
                wp.HttpCheck(path="readme.html", status="200"),
            ],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            interesting_findings=[
                wp.InterestingFinding(kind="readme", title="WordPress readme found: http://target/readme.html"),
            ],
        )
        rows = wp.build_top_target_rows(result)
        readme_rows = [row for row in rows if row[1] == "readme.html"]
        self.assertEqual(len(readme_rows), 1)

    def test_parse_wpscan_result_reflects_main_theme_and_api(self) -> None:
        payload = {
            "version": {
                "number": "6.4.3",
                "status": "insecure",
                "release_date": "2024-01-01",
                "vulnerabilities": [
                    {
                        "title": "WordPress < 6.4.4 - Example SQL Injection",
                        "cve": ["CVE-2024-0001"],
                        "edb": ["12345"],
                        "fixed_in": "6.4.4",
                    }
                ],
            },
            "main_theme": {
                "name": "twentytwentyfour",
                "version": "1.0",
                "latest_version": "1.1",
                "outdated": True,
            },
            "interesting_findings": [
                {
                    "type": "headers",
                    "data": {"Server": "Apache/2.4.41 (Ubuntu)"},
                    "found_by": ["headers"],
                }
            ],
            "vuln_api": {
                "plan": "free",
                "requests_used": "5",
                "requests_remaining": "0",
            },
        }

        result = wp.parse_wpscan_result(payload)
        self.assertEqual(result.version, "6.4.3")
        self.assertEqual(result.version_status, "insecure")
        self.assertEqual(result.version_release_date, "2024-01-01")
        self.assertEqual(len(result.version_vulnerabilities), 1)
        self.assertEqual(len(result.themes), 1)
        self.assertTrue(result.themes[0].is_main_theme)
        self.assertFalse(result.vuln_api.used)
        self.assertEqual(result.vuln_api.plan, "free")
        self.assertEqual(len(result.interesting_findings), 1)
        self.assertEqual(result.interesting_findings[0].kind, "headers")
        self.assertIn("Source: Headers (Passive Detection)", wp.build_server_information(result))

    def test_xmlrpc_without_http_verification_is_unknown(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=False,
            wordpress_detected=True,
            login_page="200",
            wp_json="200",
            xmlrpc="unknown",
            xmlrpc_http_status="",
            xmlrpc_evidence="",
            version="5.5.1",
            plugins=[],
            themes=[],
            users=[],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            interesting_findings=[
                wp.InterestingFinding(kind="xmlrpc", title="XML-RPC enabled"),
            ],
        )
        md = wp.render_markdown(result)
        self.assertNotIn("- XML-RPC:", md)
        self.assertIn("## Report Mode", md)
        self.assertIn("Mode: Enumeration-only", md)
        self.assertIn("### XML-RPC", md)
        self.assertEqual(md.count("### XML-RPC"), 1)
        self.assertNotIn("- State: unknown", md)
        self.assertNotIn("Found by: WPScan", md)
        self.assertTrue(any(entry.title == "XML-RPC" for entry in wp.build_attack_surface(result)))

    def test_api_disabled_summary_prefers_observable_findings(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=False,
            wordpress_detected=True,
            login_page="skipped",
            wp_json="skipped",
            xmlrpc="unknown",
            xmlrpc_http_status="",
            xmlrpc_evidence="",
            version="5.5.1",
            version_status="insecure",
            plugins=[],
            themes=[wp.Finding(name="twentytwenty", version="1.5", outdated=True)],
            users=[wp.UserFinding(username="elyana")],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            interesting_findings=[
                wp.InterestingFinding(kind="upload_directory_listing", title="uploads directory listing"),
                wp.InterestingFinding(kind="wp_cron", title="WP-Cron"),
                wp.InterestingFinding(kind="readme", title="readme.html"),
            ],
        )
        md = wp.render_markdown(result)
        self.assertIn("Attack Surface Count: `7`", md)
        self.assertIn("Overall Risk: High", md)
        self.assertIn("## Report Mode", md)
        self.assertIn("Mode: Enumeration-only", md)
        self.assertIn("1. WordPress 5.5.1", md)
        self.assertIn("WordPress 5.5.1", md)
        self.assertIn("uploads directory listing", md)
        self.assertIn("User: elyana", md)
        self.assertIn("Theme: twentytwenty 1.5", md)
        self.assertIn("WP-Cron", md)
        self.assertIn("readme.html", md)
        self.assertNotIn("## Enumeration Findings", md)
        self.assertNotIn("### Critical", md)
        self.assertNotIn("### High", md)
        self.assertNotIn("### Medium", md)
        self.assertNotIn("### Low", md)

    def test_confidence_values_preserve_raw_json_values(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=False,
            wordpress_detected=True,
            login_page="skipped",
            wp_json="skipped",
            xmlrpc="unknown",
            xmlrpc_http_status="",
            xmlrpc_evidence="",
            version="5.5.1",
            plugins=[],
            themes=[],
            users=[],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            interesting_findings=[
                wp.InterestingFinding(kind="readme", title="readme.html", confidence="100"),
            ],
        )
        attack_surface = wp.build_attack_surface(result)
        readme_entry = next(entry for entry in attack_surface if entry.title == "readme.html")
        self.assertEqual(readme_entry.confidence, "100")

    def test_plugin_vulnerabilities_render_cve_and_edb(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=True,
            wordpress_detected=True,
            login_page="200",
            wp_json="200",
            xmlrpc="reachable",
            xmlrpc_http_status="200",
            xmlrpc_evidence="XML-RPC response markers were returned",
            version="5.5.1",
            plugins=[
                wp.Finding(
                    name="mail-masta",
                    version="1.0",
                    vulnerabilities=[
                        wp.VulnerabilityFinding(
                            title="Mail Masta <= 1.0 - Unauthenticated Local File Inclusion",
                            cves=["CVE-2016-10956"],
                            edb_ids=["40290", "50226"],
                        )
                    ],
                )
            ],
            themes=[],
            users=[],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            vuln_api=wp.VulnApiInfo(used=True),
        )
        md = wp.render_markdown(result)
        self.assertIn("WPScan API used: `yes`", md)
        self.assertIn("## Report Mode", md)
        self.assertIn("Mode: Vulnerability correlation", md)
        self.assertIn("| 100 | mail-masta 1.0 | LFI |", md)
        self.assertIn("Primary Target: mail-masta 1.0", md)
        self.assertIn("1. mail-masta 1.0", md)
        self.assertIn("Overall Risk: Critical", md)
        self.assertIn("CVE-2016-10956", md)
        self.assertIn("40290", md)
        self.assertIn("50226", md)

    def test_report_mode_uses_api_usage_not_request_flag(self) -> None:
        result = wp.AssessResult(
            target_url="http://target/wordpress/",
            mode="normal",
            use_api=True,
            wordpress_detected=True,
            login_page="skipped",
            wp_json="skipped",
            xmlrpc="unknown",
            xmlrpc_http_status="",
            xmlrpc_evidence="",
            version="5.5.1",
            plugins=[],
            themes=[],
            users=[],
            http_checks=[],
            exposure_checks=[],
            next_actions=[],
            report_path=Path("report.md"),
            errors=[],
            vuln_api=wp.VulnApiInfo(used=False),
        )
        md = wp.render_markdown(result)
        self.assertIn("WPScan API requested: `yes`", md)
        self.assertIn("WPScan API used: `no`", md)
        self.assertIn("Mode: Enumeration-only", md)
        self.assertIn("Vulnerability correlation: Not Available", md)

    def test_assess_writes_report_even_if_wpscan_fails(self) -> None:
        def fake_run_wpscan(*args, **kwargs):
            raise wp.AssessError("wpscan not found in PATH")

        def fake_probe_path(base_url: str, path: str) -> wp.HttpCheck:
            status_map = {
                "": "200",
                "wp-login.php": "200",
                "wp-json": "200",
                "xmlrpc.php": "200",
                "readme.html": "404",
                "license.txt": "404",
            }
            return wp.HttpCheck(path=path, status=status_map.get(path, "404"))

        def fake_probe_xmlrpc(base_url: str) -> wp.XmlRpcAssessment:
            return wp.XmlRpcAssessment(
                get_check=wp.HttpCheck(path="xmlrpc.php", status="405", method="GET"),
                post_check=wp.HttpCheck(path="xmlrpc.php", status="200", method="POST"),
                state="reachable",
                evidence="XML-RPC response markers were returned",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            with mock.patch.object(wp, "run_wpscan", side_effect=fake_run_wpscan), mock.patch.object(
                wp, "probe_path", side_effect=fake_probe_path
            ), mock.patch.object(wp, "probe_xmlrpc", side_effect=fake_probe_xmlrpc):
                code = wp.assess(["--out", tmpdir, "http://target/wordpress/"])
            self.assertEqual(code, 1)
            reports = list(out_dir.glob("wp_assess_*.md"))
            self.assertEqual(len(reports), 1)
            self.assertTrue(reports[0].is_file())

    def test_assess_prints_progress(self) -> None:
        def fake_run_wpscan(*args, **kwargs):
            return {}, []

        def fake_probe_path(base_url: str, path: str) -> wp.HttpCheck:
            return wp.HttpCheck(path=path, status="200")

        def fake_probe_xmlrpc(base_url: str) -> wp.XmlRpcAssessment:
            return wp.XmlRpcAssessment(
                get_check=wp.HttpCheck(path="xmlrpc.php", status="405", method="GET"),
                post_check=wp.HttpCheck(path="xmlrpc.php", status="200", method="POST"),
                state="reachable",
                evidence="XML-RPC response markers were returned",
            )

        stdout = StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(wp, "run_wpscan", side_effect=fake_run_wpscan), mock.patch.object(
                wp, "probe_path", side_effect=fake_probe_path
            ), mock.patch.object(wp, "probe_xmlrpc", side_effect=fake_probe_xmlrpc), redirect_stdout(stdout):
                code = wp.assess(["--out", tmpdir, "http://target/wordpress/"])
            self.assertEqual(code, 0)
        text = stdout.getvalue()
        self.assertIn("[*] target: http://target/wordpress/", text)
        self.assertIn("[*] running WPScan...", text)
        self.assertIn("[*] api: disabled", text)
        self.assertIn("[+] report written", text)

    def test_wpscan_logs_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            completed = mock.Mock()
            completed.returncode = 0
            completed.stdout = ""
            completed.stderr = "warn line"
            raw_json = '{"plugins": {}, "themes": {}, "users": {}}'

            def fake_run(*args, **kwargs):
                cmd = args[0]
                output_index = cmd.index("--output") + 1
                Path(cmd[output_index]).write_text(raw_json, encoding="utf-8")
                return completed

            with mock.patch.object(wp.subprocess, "run", side_effect=fake_run):
                payload, errors = wp.run_wpscan(
                    "http://target/wordpress/",
                    "fast",
                    False,
                    log_dir=out_dir / "logs",
                )
            self.assertEqual(errors, [])
            self.assertIn("plugins", payload)
            raw_files = list((out_dir / "logs").glob("wpscan_*.json"))
            self.assertEqual(len(raw_files), 1)
            self.assertTrue(raw_files[0].is_file())

    def test_wpscan_scan_aborted_is_reported_as_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            completed = mock.Mock()
            completed.returncode = 0
            completed.stdout = ""
            completed.stderr = ""
            raw_json = (
                '{"banner":{"description":"WordPress Security Scanner by the WPScan Team"},'
                '"scan_aborted":"The url supplied \\"http://target/wordpress/\\" seems to be down (Timeout was reached)",'
                '"target_url":"http://target/wordpress/"}'
            )

            def fake_run(*args, **kwargs):
                cmd = args[0]
                output_index = cmd.index("--output") + 1
                Path(cmd[output_index]).write_text(raw_json, encoding="utf-8")
                return completed

            with mock.patch.object(wp.subprocess, "run", side_effect=fake_run):
                payload, errors = wp.run_wpscan(
                    "http://target/wordpress/",
                    "fast",
                    False,
                    log_dir=out_dir / "logs",
                )
            self.assertIn("scan_aborted", payload)
            self.assertEqual(len(errors), 1)
            self.assertIn("seems to be down", errors[0])

    def test_wpscan_reuses_exact_match_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            log_dir = out_dir / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            raw_json = '{"plugins": {}, "themes": {}, "users": {}}'
            expected = wp._wpscan_raw_path("http://target/wordpress/", "fast", False, log_dir)
            expected.write_text(raw_json, encoding="utf-8")

            def fail_run(*args, **kwargs):
                raise AssertionError("subprocess.run should not be called on cache hit")

            with mock.patch.object(wp.subprocess, "run", side_effect=fail_run):
                payload, errors = wp.run_wpscan(
                    "http://target/wordpress/",
                    "fast",
                    False,
                    log_dir=log_dir,
                )
            self.assertEqual(errors, [])
            self.assertIn("plugins", payload)

    def test_wpscan_strips_api_token_when_not_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            completed = mock.Mock()
            completed.returncode = 0
            completed.stdout = '{"plugins": {}, "themes": {}, "users": {}}'
            completed.stderr = ""

            def fake_run(*args, **kwargs):
                self.assertNotIn("WPSCAN_API_TOKEN", kwargs["env"])
                return completed

            with mock.patch.dict(os.environ, {"WPSCAN_API_TOKEN": "secret-token"}, clear=False):
                with mock.patch.object(wp.subprocess, "run", side_effect=fake_run):
                    payload, errors = wp.run_wpscan(
                        "http://target/wordpress/",
                        "fast",
                        False,
                        log_dir=out_dir / "logs",
                    )
            self.assertEqual(errors, [])
            self.assertIn("plugins", payload)


if __name__ == "__main__":
    unittest.main()
