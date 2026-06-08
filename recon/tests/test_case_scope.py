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
        self.case_scope.write_lineage(["10.0.0.1"])
        os.environ["IP"] = "10.0.0.2"
        self.assertEqual(self.case_scope.recon_scope_ips(), ["10.0.0.1", "10.0.0.2"])

        self.case_scope.clear_lineage()
        self.assertEqual(self.case_scope.recon_scope_ips(), ["10.0.0.2"])

    def test_recon_scope_ips_migrates_load_from(self) -> None:
        self.case_scope.write_load_from("10.0.0.1")
        os.environ["IP"] = "10.0.0.2"
        self.assertEqual(self.case_scope.recon_scope_ips(), ["10.0.0.1", "10.0.0.2"])

    def test_lineage_three_ip_reboot_scope(self) -> None:
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.99"):
            self.case_scope.register_case_ip(self.case, ip)
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            eid = self.db.add_execution(None, ip, "probe", f"curl {ip}")
            self.db.finish_execution(eid, "done", exit_code=0)
        self.db.add_execution(None, "10.0.0.99", "probe", "curl pivot")
        self.db.finish_execution(4, "done", exit_code=0)

        self.case_scope.update_lineage_on_target_set(
            new_ip="10.0.0.2",
            previous_ip="10.0.0.1",
            mode="auto",
            load_from="10.0.0.1",
        )
        self.case_scope.update_lineage_on_target_set(
            new_ip="10.0.0.3",
            previous_ip="10.0.0.2",
            mode="auto",
            load_from="10.0.0.2",
        )
        os.environ["IP"] = "10.0.0.3"
        self.assertEqual(
            self.case_scope.recon_scope_ips(),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )

        rows = self.db.list_executions_for_case(self.case)
        self.assertEqual({r["ip"] for r in rows}, {"10.0.0.1", "10.0.0.2", "10.0.0.3"})
        self.assertNotIn("10.0.0.99", {r["ip"] for r in rows})

    def test_lineage_new_clears_on_pivot(self) -> None:
        self.case_scope.write_lineage(["10.0.0.1", "10.0.0.2"])
        self.case_scope.update_lineage_on_target_set(
            new_ip="10.0.0.99",
            previous_ip="10.0.0.3",
            mode="new",
            load_from=None,
        )
        self.assertEqual(self.case_scope.read_lineage(), [])

    def test_bootstrap_lineage_from_case_logs(self) -> None:
        """Pre-lineage case: log filenames + load_from rebuild reboot chain."""
        self.case_scope.write_load_from("10.0.0.2")
        logs = self.case_home / "logs"
        logs.mkdir()
        for ip in ("10.0.0.1", "10.0.0.2"):
            (logs / f"gobuster_{ip}_10000_common.log").touch()
            eid = self.db.add_execution(None, ip, "probe", f"curl {ip}")
            self.db.finish_execution(eid, "done", exit_code=0)
        os.environ["IP"] = "10.0.0.3"
        self.assertTrue(self.case_scope.bootstrap_lineage_if_needed())
        self.assertEqual(
            set(self.case_scope.read_lineage()),
            {"10.0.0.1", "10.0.0.2"},
        )
        self.assertEqual(
            set(self.case_scope.recon_scope_ips()),
            {"10.0.0.1", "10.0.0.2", "10.0.0.3"},
        )

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

    def test_resolve_load_from_auto_inherits_previous(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.db.add_execution(None, "10.0.0.1", "probe", "curl old")
        self.db.finish_execution(1, "done", exit_code=0)

        load_from = self.case_scope.resolve_load_from(
            new_ip="10.0.0.2",
            previous_ip="10.0.0.1",
            mode="auto",
        )
        self.assertEqual(load_from, "10.0.0.1")

    def test_resolve_load_from_new_clears_inherit(self) -> None:
        self.case_scope.register_case_ip(self.case, "10.0.0.1")
        self.db.add_execution(None, "10.0.0.1", "probe", "curl old")
        self.db.finish_execution(1, "done", exit_code=0)

        load_from = self.case_scope.resolve_load_from(
            new_ip="10.0.0.2",
            previous_ip="10.0.0.1",
            mode="new",
        )
        self.assertIsNone(load_from)

    def test_discover_ips_from_case_log_filenames(self) -> None:
        logs = self.case_home / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "gobuster_10.0.0.55_raft-small-words.log").write_text("", encoding="utf-8")
        self.db.add_execution(None, "10.0.0.55", "probe", "curl x")
        self.db.finish_execution(1, "done", exit_code=0)

        ips = self.case_scope.discover_case_ips(self.case)
        self.assertIn("10.0.0.55", ips)

    def test_reset_case_wipes_files_and_db(self) -> None:
        ip = "10.0.0.1"
        (self.case_home / "target").write_text(ip + "\n", encoding="utf-8")
        self.case_scope.write_lineage([ip])
        self.case_scope.write_load_from(ip)
        logs = self.case_home / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "probe.log").write_text("x", encoding="utf-8")
        (self.case_home / "memo.md").write_text("note", encoding="utf-8")

        self.case_scope.register_case_ip(self.case, ip)
        eid = self.db.add_execution(None, ip, "probe", f"curl {ip}")
        self.db.finish_execution(eid, "done", exit_code=0)
        conn = self.db.connect()
        conn.execute(
            """
            INSERT INTO ports (ip, port, proto, state, service, version, first_seen, last_seen)
            VALUES (?, 22, 'tcp', 'open', 'ssh', '', datetime('now'), datetime('now'))
            """,
            (ip,),
        )
        conn.commit()
        conn.close()
        self.db.creds_upsert(ip, "alice", "pass1")
        self.db.add_artifact(ip, "hint", "", "go!", case_name=self.case)

        result = self.case_scope.reset_case(self.case)

        self.assertFalse((self.case_home / "target").exists())
        self.assertFalse((self.case_home / "lineage").exists())
        self.assertFalse((self.case_home / "load_from").exists())
        self.assertFalse((self.case_home / "memo.md").exists())
        self.assertTrue((self.case_home / "logs").is_dir())
        self.assertTrue((self.case_home / "exports").is_dir())
        self.assertEqual(list(logs.iterdir()), [])

        self.assertGreater(result["db"]["executions"], 0)
        self.assertGreater(result["db"]["ports"], 0)
        self.assertEqual(self.case_scope.list_case_ips(self.case), [])
        self.assertEqual(self.db.list_executions_for_case(self.case), [])


if __name__ == "__main__":
    unittest.main()
