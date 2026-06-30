#!/usr/bin/env python3
"""Tests for scout UDP top-ports scan."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="domain" product="dnsmasq" version="2.80"/>
      </port>
      <port protocol="udp" portid="161">
        <state state="open|filtered"/>
        <service name="snmp"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ScoutUdpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        os.environ["RECON_DB_PATH"] = str(self.db_path)

        import db
        import scout_udp

        importlib.reload(db)
        importlib.reload(scout_udp)

        self.db = db
        self.scout_udp = scout_udp
        db.init_db()
        self.ip = "10.0.0.1"

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("RECON_DB_PATH", None)
        else:
            os.environ["RECON_DB_PATH"] = self._old_db
        self._tmpdir.cleanup()

    def test_parse_nmap_udp_xml(self) -> None:
        parsed = self.scout_udp.parse_nmap_udp_xml(SAMPLE_XML)
        self.assertEqual(len(parsed["ports"]), 2)
        self.assertEqual(parsed["ports"][0]["port"], 53)
        self.assertEqual(parsed["ports"][1]["state"], "open|filtered")

    def test_format_udp_report_lines(self) -> None:
        parsed = self.scout_udp.parse_nmap_udp_xml(SAMPLE_XML)
        self.scout_udp.store_udp_scan(self.ip, parsed)
        lines = self.scout_udp.format_udp_report_lines(self.ip)
        self.assertTrue(any("53/udp  state=open  service=domain" in line for line in lines))
        self.assertTrue(any("161/udp  state=open|filtered  service=snmp" in line for line in lines))

    def test_udp_open_filtered_is_integrated_into_port_snapshot(self) -> None:
        parsed = self.scout_udp.parse_nmap_udp_xml(SAMPLE_XML)
        self.scout_udp.store_udp_scan(self.ip, parsed)
        self.db.upsert_port(self.ip, 22, "tcp", "open", "ssh", "OpenSSH")

        lines = self.db.format_scan_snapshot_lines(self.ip, "[*] basic 3/1000  full 3/65535")
        joined = "\n".join(lines)
        self.assertIn("22\ttcp\topen\tssh\tOpenSSH", joined)
        self.assertIn("53\tudp\topen\tdomain\tdnsmasq 2.80", joined)
        self.assertIn("161\tudp\topen|filtered\tsnmp\t", joined)
        self.assertIn("--- UNKNOWN ---", joined)
        self.assertIn("open|filtered is tentative", joined)

    @mock.patch("scout_udp.subprocess.run")
    def test_run_udp_phase_stores_udp_ports(self, mock_run) -> None:
        def _fake_run(cmd: str, shell: bool, capture_output: bool, text: bool, timeout: int, check: bool):
            marker = "-oX "
            idx = cmd.rfind(marker)
            self.assertGreater(idx, 0)
            xml_path = cmd[idx + len(marker) :].strip().split()[0].strip("'\"")
            Path(xml_path).write_text(SAMPLE_XML, encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        mock_run.side_effect = _fake_run

        rc = self.scout_udp.run_udp_phase(self.ip)
        self.assertEqual(rc, 0)

        rows = self.scout_udp.load_udp_scan(self.ip)
        self.assertEqual(len(rows), 2)

        conn = self.db.connect()
        row = conn.execute(
            "SELECT state, service FROM ports WHERE ip = ? AND port = 53 AND proto = 'udp'",
            (self.ip,),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["state"], "open")
        self.assertEqual(row["service"], "domain")


if __name__ == "__main__":
    unittest.main()
