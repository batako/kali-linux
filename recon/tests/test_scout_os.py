#!/usr/bin/env python3
"""Tests for scout OS detection."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <os>
      <osmatch name="Linux 4.15 - 5.6" accuracy="95" line="1">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="95"/>
      </osmatch>
      <osmatch name="Linux 5.0" accuracy="80" line="2">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="80"/>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""


class ScoutOsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        os.environ["RECON_DB_PATH"] = str(self.db_path)

        import db
        import scout_os

        importlib.reload(db)
        importlib.reload(scout_os)

        self.db = db
        self.scout_os = scout_os
        db.init_db()

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("RECON_DB_PATH", None)
        else:
            os.environ["RECON_DB_PATH"] = self._old_db
        self._tmpdir.cleanup()

    def test_parse_nmap_os_xml(self) -> None:
        parsed = self.scout_os.parse_nmap_os_xml(SAMPLE_XML)
        self.assertEqual(parsed["best"], "Linux 4.15 - 5.6")
        self.assertEqual(len(parsed["matches"]), 2)
        self.assertEqual(parsed["matches"][0]["family"], "Linux")

    def test_format_os_report_lines(self) -> None:
        self.scout_os.store_os_detect(
            "10.0.0.1",
            self.scout_os.parse_nmap_os_xml(SAMPLE_XML),
        )
        lines = self.scout_os.format_os_report_lines("10.0.0.1")
        self.assertTrue(any("best: Linux 4.15 - 5.6" in line for line in lines))
        self.assertTrue(any("alt1:" in line for line in lines))

    def test_format_os_report_lines_missing(self) -> None:
        lines = self.scout_os.format_os_report_lines("10.0.0.9")
        self.assertEqual(lines, ["(none — run scout to detect)"])

    @mock.patch("scout_os.fetch_merged_open_ports")
    def test_run_os_detect_skips_without_open_ports(self, mock_ports) -> None:
        mock_ports.return_value = []
        rc = self.scout_os.run_os_detect_phase("10.0.0.1")
        self.assertEqual(rc, 0)
        self.assertIsNone(self.scout_os.load_os_detect("10.0.0.1"))

    @mock.patch("scout_os.run_command_or_cache")
    @mock.patch("scout_os.fetch_merged_open_ports")
    def test_run_os_detect_stores_artifact(self, mock_ports, mock_run) -> None:
        mock_ports.return_value = [(22, "tcp", "open", "ssh", "OpenSSH")]
        mock_run.return_value = (42, False)

        conn = self.db.connect()
        conn.execute(
            """
            INSERT INTO executions (id, task_id, ip, task_type, command, cwd, status, exit_code, stdout, stderr)
            VALUES (42, NULL, '10.0.0.1', 'scout-os', 'nmap', '/', 'done', 0, ?, '')
            """,
            (SAMPLE_XML,),
        )
        conn.commit()
        conn.close()

        rc = self.scout_os.run_os_detect_phase("10.0.0.1")
        self.assertEqual(rc, 0)
        data = self.scout_os.load_os_detect("10.0.0.1")
        self.assertIsNotNone(data)
        assert data is not None
        self.assertEqual(data["best"], "Linux 4.15 - 5.6")


if __name__ == "__main__":
    unittest.main()
