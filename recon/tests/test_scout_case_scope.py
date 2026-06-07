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
        self.case_home = Path(self._tmpdir.name) / "cases" / "lianyu"
        self.case_home.mkdir(parents=True)
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        self._old_case_home = os.environ.get("CASE_HOME")
        self._old_ip = os.environ.get("IP")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "lianyu"
        os.environ["CASE_HOME"] = str(self.case_home)

        import db

        importlib.reload(db)
        import case_scope

        importlib.reload(case_scope)
        self.db = db
        self.case_scope = case_scope
        self.case = "lianyu"
        self.old_ip = "10.0.0.1"
        self.new_ip = "10.0.0.2"

    def tearDown(self) -> None:
        for key, old in (
            ("RECON_DB_PATH", self._old_db),
            ("CASE", self._old_case),
            ("CASE_HOME", self._old_case_home),
            ("IP", self._old_ip),
        ):
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        self._tmpdir.cleanup()

    def _inherit_from_old(self) -> None:
        self.case_scope.write_load_from(self.old_ip)
        os.environ["IP"] = self.new_ip

    def test_dirs_job_skip_across_case_ips_same_path(self) -> None:
        from url_util import canonicalize_url

        self.case_scope.register_case_ip(self.case, self.old_ip)
        self.case_scope.register_case_ip(self.case, self.new_ip)
        self._inherit_from_old()

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

    def test_dirs_job_no_skip_without_load_from(self) -> None:
        from url_util import canonicalize_url

        self.case_scope.register_case_ip(self.case, self.old_ip)
        self.case_scope.register_case_ip(self.case, self.new_ip)
        self.case_scope.clear_load_from()
        os.environ["IP"] = self.new_ip

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
        self.assertIsNone(done)

    def test_merged_open_ports_from_load_from(self) -> None:
        self.case_scope.register_case_ip(self.case, self.old_ip)
        self.case_scope.register_case_ip(self.case, self.new_ip)
        self._inherit_from_old()

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
