#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

import scan_run


class ScanRunTests(unittest.TestCase):
    def test_nmap_cmd_uses_resilience_flags_without_stdout_pipe(self) -> None:
        cmd, info = scan_run.plan_scan("10.0.0.1", scan_run.PROFILE_BASIC, force=True)
        self.assertIsNotNone(cmd)
        assert cmd is not None
        self.assertIn("-Pn", cmd)
        self.assertIn("-n", cmd)
        self.assertIn("--host-timeout", cmd)
        self.assertNotIn("-oX", cmd)
        self.assertEqual(info.get("mode"), "force")

    def test_nmap_cmd_quick_uses_ss_without_scripts(self) -> None:
        cmd, _ = scan_run.plan_scan(
            "10.0.0.1", scan_run.PROFILE_BASIC, force=True, quick=True
        )
        self.assertIsNotNone(cmd)
        assert cmd is not None
        self.assertIn("-sS", cmd)
        self.assertNotIn("-sC", cmd)
        self.assertNotIn("-sV", cmd)
        self.assertIn("--min-rate", cmd)

    def test_quick_scan_does_not_satisfy_basic_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            old_db = os.environ.get("RECON_DB_PATH")
            os.environ["RECON_DB_PATH"] = str(db_path)
            try:
                import importlib

                import db

                importlib.reload(db)
                db.init_db()
                ip = "10.0.0.1"
                for port in (22, 80, 443):
                    db.mark_port_scanned(ip, port, "tcp", "open", scan_run.PROFILE_QUICK)
                self.assertFalse(
                    scan_run.is_profile_coverage_complete(ip, scan_run.PROFILE_BASIC)
                )
                self.assertFalse(
                    scan_run.is_profile_coverage_complete(
                        ip, scan_run.PROFILE_BASIC, quick=True
                    )
                )
            finally:
                if old_db is None:
                    os.environ.pop("RECON_DB_PATH", None)
                else:
                    os.environ["RECON_DB_PATH"] = old_db

    @patch("scan_run.subprocess.call", return_value=0)
    def test_run_nmap_chunk_writes_xml_to_temp_file(self, mock_call) -> None:
        xml = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http"/>
</port>
</ports>
</host>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            old_db = os.environ.get("RECON_DB_PATH")
            os.environ["RECON_DB_PATH"] = str(db_path)
            try:
                import importlib

                import db

                importlib.reload(db)
                db.init_db()

                def _fake_call(full_cmd: str, shell: bool = False) -> int:
                    marker = "-oX "
                    idx = full_cmd.rfind(marker)
                    self.assertGreater(idx, 0)
                    xml_path = full_cmd[idx + len(marker) :].strip().strip("'\"")
                    Path(xml_path).write_text(xml, encoding="utf-8")
                    return 0

                mock_call.side_effect = _fake_call
                cmd, info = scan_run.plan_scan("10.0.0.1", scan_run.PROFILE_BASIC, force=True)
                self.assertIsNotNone(cmd)
                rc = scan_run._run_nmap_chunk("10.0.0.1", scan_run.PROFILE_BASIC, cmd or "", info)
                self.assertEqual(rc, 0)
                self.assertEqual(mock_call.call_count, 1)
                called_cmd = mock_call.call_args[0][0]
                self.assertIn("-oX", called_cmd)
                self.assertNotIn("-oX -", called_cmd)
            finally:
                if old_db is None:
                    os.environ.pop("RECON_DB_PATH", None)
                else:
                    os.environ["RECON_DB_PATH"] = old_db


if __name__ == "__main__":
    unittest.main()
