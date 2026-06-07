#!/usr/bin/env python3
"""Tests for case-scoped scout (IP reboot within same room)."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class ScoutCaseScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "lianyu"

        import db

        importlib.reload(db)
        self.db = db
        self.case = "lianyu"
        self.old_ip = "10.0.0.1"
        self.new_ip = "10.0.0.2"

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("RECON_DB_PATH", None)
        else:
            os.environ["RECON_DB_PATH"] = self._old_db
        if self._old_case is None:
            os.environ.pop("CASE", None)
        else:
            os.environ["CASE"] = self._old_case
        self._tmpdir.cleanup()

    def test_dirs_job_skip_across_case_ips_same_path(self) -> None:
        from case_scope import register_case_ip
        from url_util import canonicalize_url

        register_case_ip(self.case, self.old_ip)
        register_case_ip(self.case, self.new_ip)

        old_url = canonicalize_url(f"http://{self.old_ip}/island/")
        new_url = canonicalize_url(f"http://{self.new_ip}/island/")
        wl = "/wordlists/common.txt"

        self.db.insert_scout_job(
            self.old_ip,
            "dirs",
            old_url,
            wordlist=wl,
            status="done",
        )

        done = self.db.find_done_scout_job(self.new_ip, "dirs", new_url, wl)
        self.assertIsNotNone(done)
        self.assertEqual(done["ip"], self.old_ip)

    def test_merged_open_ports_from_case(self) -> None:
        from case_scope import register_case_ip

        register_case_ip(self.case, self.old_ip)
        register_case_ip(self.case, self.new_ip)

        conn = self.db.connect()
        conn.execute(
            """
            INSERT INTO ports (ip, port, proto, state, service, version, first_seen, last_seen)
            VALUES (?, 80, 'tcp', 'open', 'http', '', datetime('now'), datetime('now'))
            """,
            (self.old_ip,),
        )
        conn.commit()
        conn.close()

        rows = self.db.fetch_merged_open_ports(self.new_ip)
        self.assertEqual(len(rows), 1)
        self.assertEqual(int(rows[0][0]), 80)


if __name__ == "__main__":
    unittest.main()
