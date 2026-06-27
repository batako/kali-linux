#!/usr/bin/env python3
"""Tests for scout open-port enumeration."""

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
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/>
        <script id="ssh-hostkey" output="256 SHA256:abc test (RSA)"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41" extrainfo="Ubuntu"/>
        <script id="http-title" output="Site Title"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ScoutEnumTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        os.environ["RECON_DB_PATH"] = str(self.db_path)

        import db
        import scout_enum

        importlib.reload(db)
        importlib.reload(scout_enum)

        self.db = db
        self.scout_enum = scout_enum
        db.init_db()
        self.ip = "10.0.0.1"

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("RECON_DB_PATH", None)
        else:
            os.environ["RECON_DB_PATH"] = self._old_db
        self._tmpdir.cleanup()

    def _seed_open_ports(self) -> None:
        self.db.upsert_port(self.ip, 22, "tcp", "open", "ssh", "")
        self.db.upsert_port(self.ip, 80, "tcp", "open", "http", "")

    def test_parse_nmap_enum_xml(self) -> None:
        parsed = self.scout_enum.parse_nmap_enum_xml(SAMPLE_XML)
        self.assertEqual(len(parsed["ports"]), 2)
        self.assertEqual(parsed["ports"][0]["port"], 22)
        self.assertEqual(parsed["ports"][1]["service"], "http")
        self.assertEqual(parsed["ports"][1]["scripts"][0]["id"], "http-title")

    def test_format_port_enum_report_lines(self) -> None:
        parsed = self.scout_enum.parse_nmap_enum_xml(SAMPLE_XML)
        self.scout_enum.store_port_enum(self.ip, parsed)
        lines = self.scout_enum.format_port_enum_report_lines(self.ip)
        self.assertTrue(any("22/tcp  service=ssh" in line for line in lines))
        self.assertTrue(any("ssh-hostkey:" in line for line in lines))
        self.assertTrue(any("http-title:" in line for line in lines))

    @mock.patch("scout_enum.subprocess.run")
    def test_run_port_enum_phase_stores_artifacts(self, mock_run) -> None:
        self._seed_open_ports()

        def _fake_run(cmd: str, shell: bool, capture_output: bool, text: bool, timeout: int, check: bool):
            marker = "-oX "
            idx = cmd.rfind(marker)
            self.assertGreater(idx, 0)
            xml_path = cmd[idx + len(marker) :].strip().split()[0].strip("'\"")
            Path(xml_path).write_text(SAMPLE_XML, encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        mock_run.side_effect = _fake_run

        rc = self.scout_enum.run_port_enum_phase(self.ip)
        self.assertEqual(rc, 0)

        rows = self.scout_enum.load_port_enum(self.ip)
        self.assertEqual(len(rows), 2)

        conn = self.db.connect()
        port = conn.execute(
            "SELECT service, version FROM ports WHERE ip = ? AND port = 80 AND proto = 'tcp'",
            (self.ip,),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(port)
        assert port is not None
        self.assertEqual(port["service"], "http")
        self.assertIn("Apache httpd 2.4.41", port["version"])


if __name__ == "__main__":
    unittest.main()
