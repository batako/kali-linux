#!/usr/bin/env python3
"""Tests for case-scoped el/cl (IP changes within a room)."""

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


class CaseScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "lianyu"

        import db

        importlib.reload(db)
        import case_scope

        importlib.reload(case_scope)
        self.db = db
        self.case_scope = case_scope
        self.case = "lianyu"

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

    def test_register_and_list_case_ips(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        ips = self.case_scope.list_case_ips(self.case)
        self.assertEqual(set(ips), {"10.0.0.1", "10.0.0.2"})

    def test_el_lists_all_case_ips(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")

        self.db.add_execution(None, "10.0.0.1", "probe", "curl old")
        self.db.finish_execution(1, "done", exit_code=0)
        self.db.add_execution(None, "10.0.0.2", "probe", "curl new")
        self.db.finish_execution(2, "done", exit_code=0)

        rows = self.db.list_executions_for_case(self.case)
        self.assertEqual(len(rows), 2)
        seen_ips = {r["ip"] for r in rows}
        self.assertEqual(seen_ips, {"10.0.0.1", "10.0.0.2"})

    def test_cl_lists_all_case_creds(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        self.db.creds_upsert("10.0.0.1", "alice", "pass1")
        self.db.creds_upsert("10.0.0.2", "bob", "pass2")

        rows = self.db.list_ssh_creds_for_case(self.case)
        self.assertEqual(len(rows), 2)
        by_user = {r["username"]: r for r in rows}
        self.assertEqual(by_user["alice"]["ip"], "10.0.0.1")
        self.assertEqual(by_user["bob"]["ip"], "10.0.0.2")

    def test_exec_cache_falls_back_to_case_ip(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        cmd = "curl -s http://10.0.0.1/island/"
        self.db.add_execution(None, "10.0.0.1", "probe", cmd)
        self.db.finish_execution(1, "done", exit_code=0, stdout="old body")

        row = self.db.find_done_execution("10.0.0.2", cmd)
        self.assertIsNotNone(row)
        self.assertEqual(row["ip"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
