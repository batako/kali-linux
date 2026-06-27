#!/usr/bin/env python3
"""Tests for scout -fp (full port scan) chaining exploit search."""

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


class ScoutFullPortsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        os.environ["RECON_DB_PATH"] = str(self.db_path)

        import db

        importlib.reload(db)
        import scout_run

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
    @patch("scout_run.run_scan", return_value=0)
    def test_full_ports_does_not_save_artifacts_by_default(
        self, mock_scan, mock_exploit
    ) -> None:
        rc = self.scout_run.run_scout(self.ip, full_ports=True, dry_run=True)
        self.assertEqual(rc, 0)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_FULL,
            force=False,
            dry_run=True,
            quiet_ports=False,
            jobs=1,
            quick=False,
            output_base=None,
        )
        mock_exploit.assert_called_once_with(self.ip, dry_run=True, force=False)

    @patch("scout_exploit.run_exploit_phase", return_value=0)
    @patch("scout_run.run_scan", return_value=0)
    def test_save_scan_writes_full_ports_artifacts(
        self, mock_scan, mock_exploit
    ) -> None:
        rc = self.scout_run.run_scout(
            self.ip,
            full_ports=True,
            dry_run=True,
            save_scan=True,
        )
        self.assertEqual(rc, 0)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_FULL,
            force=False,
            dry_run=True,
            quiet_ports=False,
            jobs=1,
            quick=False,
            output_base="logs/full-ports",
        )
        mock_exploit.assert_called_once_with(self.ip, dry_run=True, force=False)

    @patch("scout_run.run_scan", return_value=0)
    def test_quick_full_ports_uses_separate_output_base_when_saved(
        self, mock_scan
    ) -> None:
        rc = self.scout_run.run_scout(self.ip, full_ports=True, quick_scan=True)
        self.assertEqual(rc, 0)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_FULL,
            force=False,
            dry_run=False,
            quiet_ports=False,
            jobs=1,
            quick=True,
            output_base=None,
        )

    @patch("scout_run.run_scan", return_value=0)
    def test_quick_full_ports_uses_separate_output_base_when_save_scan(
        self, mock_scan
    ) -> None:
        rc = self.scout_run.run_scout(
            self.ip,
            full_ports=True,
            quick_scan=True,
            save_scan=True,
        )
        self.assertEqual(rc, 0)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_FULL,
            force=False,
            dry_run=False,
            quiet_ports=False,
            jobs=1,
            quick=True,
            output_base="logs/full-ports-quick",
        )

    @patch("scout_exploit.run_exploit_phase")
    @patch("scout_run.run_scan", return_value=1)
    def test_full_ports_skips_exploit_on_scan_failure(self, mock_scan, mock_exploit) -> None:
        rc = self.scout_run.run_scout(self.ip, full_ports=True)
        self.assertEqual(rc, 1)
        mock_scan.assert_called_once_with(
            self.ip,
            profile=self.scout_run.PROFILE_FULL,
            force=False,
            dry_run=False,
            quiet_ports=False,
            jobs=1,
            quick=False,
            output_base=None,
        )
        mock_exploit.assert_not_called()

    @patch("scout_exploit.run_exploit_phase")
    @patch("scout_run.run_scan")
    @patch("scout_run.is_profile_coverage_complete", return_value=True)
    def test_full_ports_skip_scan_skips_exploit(
        self, mock_complete, mock_scan, mock_exploit
    ) -> None:
        rc = self.scout_run.run_scout(self.ip, full_ports=True)
        self.assertEqual(rc, 0)
        mock_scan.assert_not_called()
        mock_exploit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
