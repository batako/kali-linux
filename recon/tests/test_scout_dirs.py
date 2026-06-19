#!/usr/bin/env python3
"""Tests for scout gobuster dir planning."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from db import dirs_job_host_matches
from scout_run import build_gobuster_dir_argv
from scout_run import is_dirs_path_arg
from scout_run import looks_like_vhost_hostname
from scout_run import build_web_url
from scout_run import coerce_web_url
from scout_run import parse_soft404_size_from_hits
from scout_run import parse_wildcard_exclude_length
from scout_run import probe_wildcard_exclude_length
from scout_run import resolve_dirs_target
from scout_run import resolve_dirs_targets


class ScoutDirsGobusterTest(unittest.TestCase):
    def test_build_gobuster_dir_argv_https_adds_k(self) -> None:
        argv = build_gobuster_dir_argv(
            "https://10.0.0.1:10000/",
            "/tmp/common.txt",
            40,
        )
        self.assertIn("-k", argv)
        self.assertIn("--timeout", argv)
        self.assertEqual(argv[argv.index("-u") + 1], "https://10.0.0.1:10000/")

    def test_build_gobuster_dir_argv_exclude_length(self) -> None:
        argv = build_gobuster_dir_argv(
            "http://10.0.0.1/",
            "/tmp/common.txt",
            40,
            exclude_length=240,
        )
        self.assertEqual(argv[argv.index("--exclude-length") + 1], "240")

    def test_build_gobuster_dir_argv_host_header(self) -> None:
        argv = build_gobuster_dir_argv(
            "http://10.0.0.1/",
            "/tmp/common.txt",
            40,
            host_header="mafialive.thm",
        )
        self.assertEqual(argv[argv.index("-H") + 1], "Host:mafialive.thm")

    def test_build_gobuster_dir_argv_user_agent(self) -> None:
        argv = build_gobuster_dir_argv(
            "http://10.0.0.1/",
            "/tmp/common.txt",
            40,
            user_agent="Mozilla/5.0 (X11; Linux x86_64)",
        )
        self.assertEqual(argv[argv.index("-a") + 1], "Mozilla/5.0 (X11; Linux x86_64)")

    def test_build_gobuster_dir_argv_cookie(self) -> None:
        argv = build_gobuster_dir_argv(
            "http://10.0.0.1/",
            "/tmp/common.txt",
            40,
            cookie="PHPSESSID=abc123; role=admin",
        )
        cookie_headers = [
            argv[idx + 1]
            for idx, token in enumerate(argv[:-1])
            if token == "-H"
        ]
        self.assertIn("Cookie:PHPSESSID=abc123; role=admin", cookie_headers)

    def test_dirs_job_host_matches(self) -> None:
        plain = "gobuster dir -u http://10.0.0.1/ -w /tmp/common.txt"
        vhost = "gobuster dir -u http://10.0.0.1/ -H Host:mafialive.thm -w /tmp/common.txt"
        self.assertTrue(dirs_job_host_matches(plain, None))
        self.assertFalse(dirs_job_host_matches(vhost, None))
        self.assertTrue(dirs_job_host_matches(vhost, "mafialive.thm"))
        self.assertFalse(dirs_job_host_matches(plain, "mafialive.thm"))

    def test_build_web_url_webmin_uses_https(self) -> None:
        url = build_web_url("10.0.0.1", 10000, "MiniServ 1.890 Webmin httpd")
        self.assertEqual(url, "https://10.0.0.1:10000/")

    def test_build_web_url_port_10000_uses_https_even_without_service_hint(self) -> None:
        url = build_web_url("10.0.0.1", 10000, "http")
        self.assertEqual(url, "https://10.0.0.1:10000/")

    def test_coerce_web_url_upgrades_http_on_10000(self) -> None:
        self.assertEqual(
            coerce_web_url("http://10.0.0.1:10000/admin/"),
            "https://10.0.0.1:10000/admin/",
        )

    def test_resolve_dirs_target_port_10000_shorthand(self) -> None:
        self.assertEqual(
            resolve_dirs_target("10.0.0.1", ":10000/"),
            "https://10.0.0.1:10000/",
        )

    def test_vhost_hostname_not_dirs_path(self) -> None:
        self.assertTrue(looks_like_vhost_hostname("mafialive.thm"))
        self.assertFalse(looks_like_vhost_hostname("admin"))
        self.assertFalse(looks_like_vhost_hostname("/admin"))
        self.assertFalse(is_dirs_path_arg("mafialive.thm"))
        self.assertTrue(is_dirs_path_arg("admin"))

    @patch("scout_run.discover_web_targets", return_value=[])
    def test_resolve_dirs_targets_vhost_fallback(self, _mock_discover) -> None:
        self.assertEqual(
            resolve_dirs_targets("10.0.0.1", host_header="www.lookup.thm"),
            [(None, "http://10.0.0.1/")],
        )
        self.assertEqual(resolve_dirs_targets("10.0.0.1"), [])

    @patch("scout_run.subprocess.run")
    def test_probe_wildcard_exclude_length(self, mock_run) -> None:
        mock_run.return_value.returncode = 56
        mock_run.return_value.stdout = "200\n3727\n"
        self.assertEqual(
            probe_wildcard_exclude_length("https://10.0.0.1:10000/"),
            3727,
        )
        args = mock_run.call_args[0][0]
        self.assertIn("-k", args)

    @patch("scout_run.subprocess.run")
    def test_probe_wildcard_exclude_length_host_header(self, mock_run) -> None:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "200\n512\n"
        self.assertEqual(
            probe_wildcard_exclude_length(
                "http://10.0.0.1/",
                host_header="mafialive.thm",
            ),
            512,
        )
        args = mock_run.call_args[0][0]
        self.assertIn("-H", args)
        self.assertIn("Host: mafialive.thm", args)

    @patch("scout_run.subprocess.run")
    def test_probe_wildcard_exclude_length_ignores_404(self, mock_run) -> None:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "404\n1234\n"
        self.assertIsNone(probe_wildcard_exclude_length("http://10.0.0.1/"))

    @patch("scout_run.subprocess.run")
    def test_probe_wildcard_exclude_length_cookie(self, mock_run) -> None:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "200\n345\n"
        self.assertEqual(
            probe_wildcard_exclude_length(
                "http://10.0.0.1/",
                cookie="PHPSESSID=abc123; role=admin",
            ),
            345,
        )
        args = mock_run.call_args[0][0]
        self.assertIn("-H", args)
        self.assertIn("Cookie: PHPSESSID=abc123; role=admin", args)

    def test_parse_soft404_size_from_hits(self) -> None:
        import tempfile

        log = ".env                 (Status: 200) [Size: 3704]\n.git/  (Status: 200) [Size: 3704]\n"
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tmp:
            tmp.write(log)
            path = tmp.name
        try:
            self.assertEqual(parse_soft404_size_from_hits(path), 3704)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parse_wildcard_exclude_length(self) -> None:
        log = (
            "2026/06/08 04:13:06 the server returns a status code that matches the "
            "provided options for non existing urls. "
            "https://10.0.0.1:10000/uuid => 200 (Length: 3727). "
            "Please exclude the response length"
        )
        self.assertEqual(parse_wildcard_exclude_length_from_text(log), 3727)


def parse_wildcard_exclude_length_from_text(text: str) -> int | None:
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tmp:
        tmp.write(text)
        path = tmp.name
    try:
        return parse_wildcard_exclude_length(path)
    finally:
        Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
