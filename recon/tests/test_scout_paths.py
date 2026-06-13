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

import os

from scout_run import _parse_port_path_shorthand
from scout_run import _paths_report_groups
from scout_run import _paths_report_groups_case
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
            {"url": "http://10.0.0.1/", "command": "gobuster dir -u http://10.0.0.1/ -w /tmp/w.txt"},
            {"url": "http://10.0.0.1/hidden/", "command": "gobuster dir -u http://10.0.0.1/hidden/ -w /tmp/w.txt"},
            {"url": "http://10.0.0.1:65524/", "command": "gobuster dir -u http://10.0.0.1:65524/ -w /tmp/w.txt"},
        ]
        groups = _paths_report_groups(rows)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0][0], "http://10.0.0.1/")
        self.assertEqual(len(groups[0][1]), 2)
        self.assertEqual(groups[1][0], "http://10.0.0.1:65524/")

    def test_paths_report_groups_splits_ip_and_vhost(self) -> None:
        rows = [
            {
                "url": "http://10.0.0.1/",
                "command": "gobuster dir -u http://10.0.0.1/ -w /tmp/w.txt",
                "hits_summary": "/admin/  301",
                "status": "done",
            },
            {
                "url": "http://10.0.0.1/",
                "command": "gobuster dir -u http://10.0.0.1/ -H Host:www.example.com -w /tmp/w.txt",
                "hits_summary": "/login/  200",
                "status": "done",
            },
        ]
        groups = _paths_report_groups(rows)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0][0], "http://10.0.0.1/")
        self.assertEqual(groups[1][0], "http://www.example.com/")

    def test_print_paths_section_shows_ip_and_vhost_separately(self) -> None:
        rows = [
            {
                "url": "http://10.0.0.1/",
                "command": "gobuster dir -u http://10.0.0.1/ -w /tmp/w.txt",
                "log_path": "",
                "hits_summary": "/admin/  301",
                "status": "done",
            },
            {
                "url": "http://10.0.0.1/",
                "command": "gobuster dir -u http://10.0.0.1/ -H Host:www.example.com -w /tmp/w.txt",
                "log_path": "",
                "hits_summary": "/login/  200",
                "status": "done",
            },
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_paths_section("10.0.0.1", rows)
        out = buf.getvalue()
        self.assertIn("http://10.0.0.1/\n  admin/  301", out)
        self.assertIn("http://www.example.com/\n  login/  200", out)

    def test_paths_report_groups_case_splits_vhost(self) -> None:
        rows = [
            {
                "url": "http://10.0.0.1/",
                "command": "gobuster dir -u http://10.0.0.1/ -w /tmp/w.txt",
                "log_path": "",
                "hits_summary": "/admin/  301",
                "status": "done",
            },
            {
                "url": "http://10.0.0.1/",
                "command": "gobuster dir -u http://10.0.0.1/ -H Host:www.example.com -w /tmp/w.txt",
                "log_path": "",
                "hits_summary": "/login/  200",
                "status": "done",
            },
        ]
        groups = _paths_report_groups_case(rows, current_ip="10.0.0.99")
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0][0], "http://10.0.0.99/")
        self.assertEqual(groups[1][0], "http://www.example.com/")

    def test_paths_display_label_https_nonstandard_port(self) -> None:
        from scout_run import _paths_display_label

        self.assertEqual(
            _paths_display_label("https://10.0.0.1:10000/", "www.example.com"),
            "https://www.example.com:10000/",
        )
        self.assertEqual(
            _paths_display_label("https://10.0.0.1/", "www.example.com"),
            "https://www.example.com/",
        )

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

    def test_paths_report_groups_case_merges_lineage_by_service(self) -> None:
        rows = [
            {
                "url": "https://10.0.0.1:10000/",
                "log_path": "",
                "hits_summary": "/admin/  200",
                "status": "done",
            },
            {
                "url": "http://10.0.0.2:10000/",
                "log_path": "",
                "hits_summary": "/login/  301",
                "status": "done",
            },
        ]
        groups = _paths_report_groups_case(rows, current_ip="10.0.0.99")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "https://10.0.0.99:10000/")
        self.assertEqual(len(groups[0][1]), 2)

    def test_print_paths_section_case_uses_current_ip_label(self) -> None:
        rows = [
            {
                "url": "https://10.0.0.1:10000/",
                "log_path": "",
                "hits_summary": "/panel/  200",
                "status": "done",
            },
        ]
        old_case = os.environ.get("CASE")
        old_home = os.environ.get("CASE_HOME")
        os.environ["CASE"] = "room"
        os.environ["CASE_HOME"] = "/tmp/room"
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _print_paths_section("10.0.0.99", rows)
            out = buf.getvalue()
            self.assertIn("https://10.0.0.99:10000/", out)
            self.assertIn("  panel/  200", out)
            self.assertNotIn("10.0.0.1", out)
        finally:
            if old_case is None:
                os.environ.pop("CASE", None)
            else:
                os.environ["CASE"] = old_case
            if old_home is None:
                os.environ.pop("CASE_HOME", None)
            else:
                os.environ["CASE_HOME"] = old_home

    def test_print_paths_section_skips_empty_failed_origins(self) -> None:
        rows = [
            {"url": "http://10.0.0.1:10000/", "log_path": "", "hits_summary": "", "status": "failed"},
            {"url": "https://10.0.0.2:10000/", "log_path": "", "hits_summary": "", "status": "failed"},
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_paths_section("10.0.0.2", rows)
        out = buf.getvalue()
        self.assertEqual(out, "--- PATHS ---\n(none)\n")

    def test_print_paths_section_merges_findings_across_jobs(self) -> None:
        rows = [
            {
                "url": "https://10.0.0.1:10000/",
                "log_path": "",
                "hits_summary": "",
                "status": "failed",
            },
            {
                "url": "https://10.0.0.1:10000/",
                "log_path": "",
                "hits_summary": "/admin/  200",
                "status": "done",
            },
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_paths_section("10.0.0.1", rows)
        out = buf.getvalue()
        self.assertIn("https://10.0.0.1:10000/", out)
        self.assertIn("  admin/  200", out)
        self.assertNotIn("\n\n\n", out)

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
