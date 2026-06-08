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

from scout_run import build_gobuster_dir_argv
from scout_run import build_web_url
from scout_run import coerce_web_url
from scout_run import parse_soft404_size_from_hits
from scout_run import parse_wildcard_exclude_length
from scout_run import probe_wildcard_exclude_length
from scout_run import resolve_dirs_target


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
    def test_probe_wildcard_exclude_length_ignores_404(self, mock_run) -> None:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "404\n1234\n"
        self.assertIsNone(probe_wildcard_exclude_length("http://10.0.0.1/"))

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
