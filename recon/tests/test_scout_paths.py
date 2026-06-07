#!/usr/bin/env python3
"""Tests for per-origin PATHS report grouping."""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from scout_run import _parse_port_path_shorthand
from scout_run import _paths_report_groups
from scout_run import _print_paths_section
from scout_run import format_paths_tree
from scout_run import resolve_dirs_target
from url_util import dirs_origin_url
from url_util import normalize_dirs_scan_url

class ScoutPathsReportTest(unittest.TestCase):
    def test_parse_port_path_shorthand(self) -> None:
        self.assertEqual(_parse_port_path_shorthand(":65524/hidden/"), (65524, "/hidden/"))
        self.assertEqual(_parse_port_path_shorthand(":65524"), (65524, "/"))
        self.assertEqual(_parse_port_path_shorthand(":65524/"), (65524, "/"))
        self.assertIsNone(_parse_port_path_shorthand("/hidden/"))

    def test_resolve_dirs_target_port_shorthand(self) -> None:
        self.assertEqual(
            resolve_dirs_target("10.67.188.254", ":65524/hidden/"),
            "http://10.67.188.254:65524/hidden/",
        )
        self.assertEqual(
            resolve_dirs_target("10.67.188.254", ":443/hoge"),
            "https://10.67.188.254/hoge/",
        )
        self.assertEqual(
            resolve_dirs_target("10.67.188.254", ":80/fuga"),
            "http://10.67.188.254/fuga/",
        )

    def test_dirs_origin_url_groups_scan_bases(self) -> None:
        self.assertEqual(
            dirs_origin_url("http://10.0.0.1/hidden/"),
            "http://10.0.0.1/",
        )
        self.assertEqual(
            dirs_origin_url("http://10.0.0.1:65524/admin/"),
            "http://10.0.0.1:65524/",
        )

    def test_paths_report_groups_merges_same_origin(self) -> None:
        rows = [
            {"url": "http://10.0.0.1/"},
            {"url": "http://10.0.0.1/hidden/"},
            {"url": "http://10.0.0.1:65524/"},
        ]
        groups = _paths_report_groups(rows)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0][0], "http://10.0.0.1/")
        self.assertEqual(len(groups[0][1]), 2)
        self.assertEqual(groups[1][0], "http://10.0.0.1:65524/")

    def test_paths_report_groups_merges_trailing_slash_variants(self) -> None:
        rows = [
            {"url": "http://10.0.0.1/hidden/"},
            {"url": "http://10.0.0.1/hidden"},
        ]
        groups = _paths_report_groups(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][1]), 2)

    def test_format_paths_tree_files_without_trailing_slash(self) -> None:
        lines = format_paths_tree(
            [("/index.html", 200), ("/robots.txt", 200)],
            root_label="http://10.0.0.1:65524/",
        )
        self.assertIn("  index.html  200", "\n".join(lines))
        self.assertIn("  robots.txt  200", "\n".join(lines))
        self.assertNotIn("index.html/", "\n".join(lines))

    def test_print_paths_section_merges_port80_scan_bases(self) -> None:
        rows = [
            {
                "url": "http://10.0.0.1/",
                "log_path": "",
                "hits_summary": "/hidden/  301",
                "status": "done",
            },
            {
                "url": "http://10.0.0.1/hidden/",
                "log_path": "",
                "hits_summary": "/hidden/index.html  200\n/hidden/whatever/  301",
                "status": "done",
            },
            {
                "url": "http://10.0.0.1:65524/",
                "log_path": "",
                "hits_summary": "/index.html  200\n/robots.txt  200",
                "status": "done",
            },
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_paths_section("10.0.0.1", rows)
        out = buf.getvalue()
        self.assertEqual(out.count("http://10.0.0.1/"), 1)
        self.assertEqual(out.count("http://10.0.0.1:65524/"), 1)
        self.assertIn("  hidden/  301", out)
        self.assertIn("    index.html  200", out)
        self.assertIn("    whatever/  301", out)
        self.assertIn("  index.html  200", out)
        self.assertIn("  robots.txt  200", out)


if __name__ == "__main__":
    unittest.main()
