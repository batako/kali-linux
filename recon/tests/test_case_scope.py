#!/usr/bin/env python3
"""Tests for case-scoped el/cl and load_from lineage."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class CaseScopeTests(unittest.TestCase):
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

    def test_register_and_list_case_ips(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        ips = self.case_scope.list_case_ips(self.case)
        self.assertEqual(set(ips), {"10.0.0.1", "10.0.0.2"})

    def test_el_lists_recon_scope_only(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        self.case_scope.register_case_ip(self.case, "10.0.0.99")

        self.db.add_execution(None, "10.0.0.1", "probe", "curl old")
        self.db.finish_execution(1, "done", exit_code=0)
        self.db.add_execution(None, "10.0.0.2", "probe", "curl new")
        self.db.finish_execution(2, "done", exit_code=0)
        self.db.add_execution(None, "10.0.0.99", "probe", "curl pivot")
        self.db.finish_execution(3, "done", exit_code=0)

        self.case_scope.write_load_from("10.0.0.1")
        os.environ["IP"] = "10.0.0.2"

        rows = self.db.list_executions_for_case(self.case)
        self.assertEqual(len(rows), 2)
        seen_ips = {r["ip"] for r in rows}
        self.assertEqual(seen_ips, {"10.0.0.1", "10.0.0.2"})
        self.assertNotIn("10.0.0.99", seen_ips)

    def test_el_all_case_lists_every_ip(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        self.db.add_execution(None, "10.0.0.1", "probe", "a")
        self.db.finish_execution(1, "done", exit_code=0)
        self.db.add_execution(None, "10.0.0.2", "probe", "b")
        self.db.finish_execution(2, "done", exit_code=0)

        self.case_scope.clear_load_from()
        os.environ["IP"] = "10.0.0.2"

        rows = self.db.list_executions_for_case(self.case, all_case=True)
        self.assertEqual({r["ip"] for r in rows}, {"10.0.0.1", "10.0.0.2"})

    def test_cl_lists_recon_scope_creds(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        self.case_scope.register_case_ip(self.case, "10.0.0.99")
        self.db.creds_upsert("10.0.0.1", "alice", "pass1")
        self.db.creds_upsert("10.0.0.2", "bob", "pass2")
        self.db.creds_upsert("10.0.0.99", "eve", "pass3")

        self.case_scope.write_load_from("10.0.0.1")
        os.environ["IP"] = "10.0.0.2"

        rows = self.db.list_ssh_creds_for_case(self.case)
        self.assertEqual(len(rows), 2)
        by_user = {r["username"]: r for r in rows}
        self.assertEqual(by_user["alice"]["ip"], "10.0.0.1")
        self.assertEqual(by_user["bob"]["ip"], "10.0.0.2")
        self.assertNotIn("eve", by_user)

    def test_exec_cache_falls_back_to_load_from(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        cmd = "curl -s http://10.0.0.1/island/"
        self.db.add_execution(None, "10.0.0.1", "probe", cmd)
        self.db.finish_execution(1, "done", exit_code=0, stdout="old body")

        self.case_scope.write_load_from("10.0.0.1")
        os.environ["IP"] = "10.0.0.2"

        row = self.db.find_done_execution("10.0.0.2", cmd)
        self.assertIsNotNone(row)
        self.assertEqual(row["ip"], "10.0.0.1")

    def test_pivot_does_not_inherit_without_load_from(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.case_scope.register_case_ip(self.case, "10.0.0.2")
        cmd = "curl -s http://10.0.0.1/island/"
        self.db.add_execution(None, "10.0.0.1", "probe", cmd)
        self.db.finish_execution(1, "done", exit_code=0, stdout="old body")

        self.case_scope.clear_load_from()
        os.environ["IP"] = "10.0.0.2"

        row = self.db.find_done_execution("10.0.0.2", cmd)
        self.assertIsNone(row)

    def test_load_from_read_write(self) -> None:
        self.assertIsNone(self.case_scope.read_load_from())
        self.case_scope.write_load_from("10.0.0.1")
        self.assertEqual(self.case_scope.read_load_from(), "10.0.0.1")
        self.case_scope.clear_load_from()
        self.assertIsNone(self.case_scope.read_load_from())

    def test_recon_scope_ips(self) -> None:
        self.case_scope.write_load_from("10.0.0.1")
        os.environ["IP"] = "10.0.0.2"
        self.assertEqual(self.case_scope.recon_scope_ips(), ["10.0.0.1", "10.0.0.2"])

        self.case_scope.clear_load_from()
        self.assertEqual(self.case_scope.recon_scope_ips(), ["10.0.0.2"])

    def test_read_choice_shows_prompt_with_stream(self) -> None:
        import io

        out = io.StringIO()
        inp = io.StringIO("2\n")
        with unittest.mock.patch("sys.stdout", out):
            line = self.case_scope._read_choice("load> ", stream=inp)
        self.assertEqual(line, "2")
        self.assertEqual(out.getvalue(), "load> ")

    def test_pick_discovers_ips_without_case_ips_registry(self) -> None:
        """Migration: recon rows exist but case_ips was never populated."""
        self.db.add_execution(None, "10.0.0.1", "probe", "curl old")
        self.db.finish_execution(1, "done", exit_code=0)
        conn = self.db.connect()
        conn.execute(
            "UPDATE executions SET case_name = ? WHERE id = 1",
            (self.case,),
        )
        conn.commit()
        conn.close()

        rows = self.case_scope.list_case_ip_candidates(
            self.case,
            current_ip="10.0.0.2",
            also_ips=["10.0.0.1"],
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "10.0.0.1")

    def test_discover_ips_from_case_log_filenames(self) -> None:
        logs = self.case_home / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "gobuster_10.0.0.55_raft-small-words.log").write_text("", encoding="utf-8")
        self.db.add_execution(None, "10.0.0.55", "probe", "curl x")
        self.db.finish_execution(1, "done", exit_code=0)

        ips = self.case_scope.discover_case_ips(self.case)
        self.assertIn("10.0.0.55", ips)


if __name__ == "__main__":
    unittest.main()
