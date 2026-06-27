#!/usr/bin/env python3
"""Tests for scout default scan output artifacts."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class ScoutScanOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        os.environ["RECON_DB_PATH"] = str(self.db_path)

        import db
        import scout_run

        importlib.reload(db)
        importlib.reload(scout_run)

        self.db = db
        self.scout_run = scout_run
        db.init_db()
        self.ip = "10.0.0.1"

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("RECON_DB_PATH", None)
        else:
            os.environ["RECON_DB_PATH"] = self._old_db
        self._tmpdir.cleanup()

    @patch("scout_exploit.run_exploit_phase", return_value=0)
    @patch("task_run.run_task_plan_phase", return_value=0)
    @patch("scout_run._run_probe_phase", return_value=0)
    @patch("scout_os.run_os_detect_phase", return_value=0)
    @patch("scout_enum.run_port_enum_phase", return_value=0)
    @patch("scout_udp.run_udp_phase", return_value=0)
    @patch("scout_run.run_scan", return_value=0)
    def test_default_scout_does_not_save_basic_scan_artifacts(
        self,
        mock_scan,
        _mock_udp,
        _mock_enum,
        _mock_os,
        _mock_probe,
        _mock_plan,
        _mock_exploit,
    ) -> None:
        rc = self.scout_run.run_scout(self.ip)
        self.assertEqual(rc, 0)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_BASIC,
            force=False,
            dry_run=False,
            quiet_ports=False,
            jobs=1,
            quick=False,
            output_base=None,
        )

    @patch("scout_exploit.run_exploit_phase", return_value=0)
    @patch("task_run.run_task_plan_phase", return_value=0)
    @patch("scout_run._run_probe_phase", return_value=0)
    @patch("scout_os.run_os_detect_phase", return_value=0)
    @patch("scout_enum.run_port_enum_phase", return_value=0)
    @patch("scout_udp.run_udp_phase", return_value=0)
    @patch("scout_run.run_scan", return_value=0)
    def test_save_scan_writes_basic_scan_to_logs_ports(
        self,
        mock_scan,
        _mock_udp,
        _mock_enum,
        _mock_os,
        _mock_probe,
        _mock_plan,
        _mock_exploit,
    ) -> None:
        rc = self.scout_run.run_scout(self.ip, save_scan=True)
        self.assertEqual(rc, 0)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_BASIC,
            force=False,
            dry_run=False,
            quiet_ports=False,
            jobs=1,
            quick=False,
            output_base="logs/ports",
        )


if __name__ == "__main__":
    unittest.main()
