#!/usr/bin/env python3
"""Tests for scout file extension fuzz (ffuf)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from scout_ext_fuzz import build_ffuf_ext_argv
from scout_ext_fuzz import ext_fuzz_fuzz_path
from scout_ext_fuzz import extract_ffuf_ext_findings
from scout_ext_fuzz import has_ext_fuzz_marker
from scout_ext_fuzz import has_ext_wildcard_suffix
from scout_ext_fuzz import has_trailing_slash
from scout_ext_fuzz import is_ext_fuzz_request
from scout_ext_fuzz import parse_ext_fuzz_target
from scout_ext_fuzz import resolve_ext_fuzz_urls
from scout_ext_fuzz import split_ext_fuzz_stem


class ScoutExtFuzzTest(unittest.TestCase):
    def test_is_ext_fuzz_request_explicit_only(self) -> None:
        self.assertFalse(is_ext_fuzz_request("/scripts/script.txt"))
        self.assertFalse(is_ext_fuzz_request("http://10.0.0.1/scripts/script.txt"))
        self.assertTrue(is_ext_fuzz_request("/scripts/script.txt", dx=True))
        self.assertFalse(is_ext_fuzz_request("/scripts/script.FUZZ"))
        self.assertTrue(is_ext_fuzz_request("/scripts/script.FUZZ", dx=True))
        self.assertFalse(is_ext_fuzz_request("/scripts/script.FUZZ/"))
        self.assertFalse(is_ext_fuzz_request("/scripts/script.*"))
        self.assertTrue(is_ext_fuzz_request("/scripts/script.*", dx=True))
        self.assertFalse(is_ext_fuzz_request("/scripts/"))
        self.assertFalse(is_ext_fuzz_request("/admin"))

    def test_has_trailing_slash(self) -> None:
        self.assertTrue(has_trailing_slash("/scripts/script.FUZZ/"))
        self.assertFalse(has_trailing_slash("/scripts/script.FUZZ"))

    def test_has_ext_fuzz_marker_and_wildcard(self) -> None:
        self.assertTrue(has_ext_fuzz_marker("/scripts/script.FUZZ"))
        self.assertTrue(has_ext_wildcard_suffix("/scripts/script.*"))
        self.assertFalse(has_ext_wildcard_suffix("/scripts/script.txt"))

    def test_parse_ext_fuzz_target(self) -> None:
        self.assertEqual(
            parse_ext_fuzz_target("/scripts/script.txt", dx=True),
            ("/scripts/", "script"),
        )
        self.assertEqual(
            parse_ext_fuzz_target("/scripts/script.FUZZ", dx=True),
            ("/scripts/", "script"),
        )
        self.assertEqual(
            parse_ext_fuzz_target("/scripts/script.*", dx=True),
            ("/scripts/", "script"),
        )
        self.assertEqual(
            parse_ext_fuzz_target("/scripts/script", dx=True),
            ("/scripts/", "script"),
        )

    def test_split_ext_fuzz_stem(self) -> None:
        self.assertEqual(
            split_ext_fuzz_stem("/scripts/script.txt"),
            ("/scripts/", "script"),
        )

    def test_ext_fuzz_fuzz_path_bare_vs_dotted(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("old\ntxt\nbak\n")
            bare = f.name
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(".old\n.txt\n")
            dotted = f.name
        try:
            from scout_ext_fuzz import wordlist_extension_style

            self.assertEqual(wordlist_extension_style(bare), "bare")
            self.assertEqual(wordlist_extension_style(dotted), "dotted")
            self.assertEqual(
                ext_fuzz_fuzz_path("/scripts/", "script", bare),
                "scripts/script.FUZZ",
            )
            self.assertEqual(
                ext_fuzz_fuzz_path("/scripts/", "script", dotted),
                "scripts/scriptFUZZ",
            )
        finally:
            Path(bare).unlink(missing_ok=True)
            Path(dotted).unlink(missing_ok=True)

    def test_resolve_ext_fuzz_urls(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("old\ntxt\n")
            wl = f.name
        try:
            seed, ffuf, port = resolve_ext_fuzz_urls(
                "10.0.0.1",
                "/scripts/script.txt",
                dx=True,
                host_header="www.example.com",
                wordlist=wl,
            )
            self.assertEqual(seed, "http://10.0.0.1/scripts/script")
            self.assertEqual(ffuf, "http://10.0.0.1/scripts/script.FUZZ")
            self.assertEqual(port, 80)
        finally:
            Path(wl).unlink(missing_ok=True)

    def test_build_ffuf_ext_argv_vhost(self) -> None:
        argv = build_ffuf_ext_argv(
            "http://10.0.0.1/scripts/scriptFUZZ",
            "/tmp/ext.txt",
            40,
            json_path="/tmp/out.json",
            host_header="www.example.com",
        )
        self.assertEqual(argv[0], "ffuf")
        self.assertIn("-H", argv)
        self.assertIn("Host: www.example.com", argv)

    def test_extract_ffuf_ext_findings(self) -> None:
        payload = {
            "results": [
                {"url": "http://10.0.0.1/scripts/script.old", "status": 200},
                {"url": "http://10.0.0.1/scripts/script.txt", "status": 200},
                {"url": "http://10.0.0.1/scripts/script.nope", "status": 404},
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(payload, f)
            path = f.name
        try:
            hits = extract_ffuf_ext_findings(
                path,
                base_url="http://10.0.0.1/scripts/script",
            )
            paths = dict(hits)
            self.assertEqual(paths["/scripts/script.old"], 200)
            self.assertEqual(paths["/scripts/script.txt"], 200)
            self.assertNotIn("/scripts/script.nope", paths)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
