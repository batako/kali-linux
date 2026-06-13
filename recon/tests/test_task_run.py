#!/usr/bin/env python3
"""Tests for auth task catalog and task plan/strike."""

from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class TaskAuthTests(unittest.TestCase):
    def test_match_ftp_postgres_mysql(self) -> None:
        import task_auth

        ftp = task_auth.match_auth_plans("10.0.0.1", 2121, "ftp", "vsftpd")
        self.assertEqual(len(ftp), 1)
        self.assertEqual(ftp[0].task_type, "auth-ftp-anon")
        self.assertIn("-s 2121", ftp[0].command)

        pg = task_auth.match_auth_plans("10.0.0.1", 5432, "postgresql", "9.5")
        self.assertEqual(len(pg), 1)
        self.assertEqual(pg[0].task_type, "auth-pg-quick")
        self.assertIn("postgres-betterdefaultpasslist", pg[0].command)

        my = task_auth.match_auth_plans("10.0.0.1", 3306, "mysql", "5.7")
        self.assertEqual(len(my), 1)
        self.assertEqual(my[0].task_type, "auth-my-quick")
        self.assertIn("-l root -e ns", my[0].command)

    def test_ssh_on_nonstandard_port(self) -> None:
        import task_auth

        # SSH auth not in phase 1 catalog — no plan for ssh service
        plans = task_auth.match_auth_plans("10.0.0.1", 8080, "ssh", "OpenSSH")
        self.assertEqual(plans, [])

    def test_no_sftp_ftp(self) -> None:
        import task_auth

        plans = task_auth.match_auth_plans("10.0.0.1", 22, "sftp", "")
        self.assertEqual(plans, [])


class TaskDbTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "tasks.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "testroom"

        import db

        importlib.reload(db)
        self.db = db
        self.db.init_db()

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

    def test_upsert_skips_done(self) -> None:
        action, tid = self.db.upsert_task(
            ip="10.0.0.1",
            port=21,
            service="ftp",
            task_type="auth-ftp-anon",
            command="hydra ...",
        )
        self.assertEqual(action, "created")
        self.db.finish_task(tid, status="done", outcome="hit", result_summary="anon")

        action2, tid2 = self.db.upsert_task(
            ip="10.0.0.1",
            port=21,
            service="ftp",
            task_type="auth-ftp-anon",
            command="hydra ...",
        )
        self.assertEqual(action2, "skipped")
        self.assertEqual(tid2, tid)

    def test_dedupe_key_includes_port(self) -> None:
        key_a = self.db.build_task_dedupe_key("room", "10.0.0.1", 21, "auth-ftp-anon")
        key_b = self.db.build_task_dedupe_key("room", "10.0.0.1", 8080, "auth-ftp-anon")
        self.assertNotEqual(key_a, key_b)


class TaskRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "tasks.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "testroom"

        import db
        import task_run

        importlib.reload(db)
        importlib.reload(task_run)
        self.db = db
        self.task_run = task_run
        self.db.init_db()

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

    @mock.patch("task_auth.fetch_merged_open_ports")
    def test_task_plan_dry_run(self, mock_ports) -> None:
        mock_ports.return_value = [
            (21, "tcp", "open", "ftp", "vsftpd"),
            (5432, "tcp", "open", "postgresql", "9.5"),
        ]
        rc = self.task_run.run_task_plan_phase("10.0.0.1", dry_run=True)
        self.assertEqual(rc, 0)
        rows = self.db.list_tasks(ip="10.0.0.1")
        self.assertEqual(len(rows), 0)

    @mock.patch("task_auth.fetch_merged_open_ports")
    def test_task_plan_enqueue(self, mock_ports) -> None:
        mock_ports.return_value = [(21, "tcp", "open", "ftp", "vsftpd")]
        rc = self.task_run.run_task_plan_phase("10.0.0.1", dry_run=False)
        self.assertEqual(rc, 0)
        rows = self.db.list_tasks(ip="10.0.0.1", status="pending")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_type"], "auth-ftp-anon")
        self.assertIn("-s 21", rows[0]["command"])

    def test_detect_outcome_hit(self) -> None:
        row = {
            "status": "done",
            "exit_code": 0,
            "stdout": "[21][ftp] host: 10.0.0.1   login: anonymous   password: anonymous@",
            "stderr": "",
        }
        outcome, summary = self.task_run._detect_outcome(row)
        self.assertEqual(outcome, "hit")
        self.assertIn("anonymous", summary)

    def test_detect_outcome_miss_hydra_exit_zero(self) -> None:
        """Hydra exits 0 even when no passwords found (ev 551 case)."""
        row = {
            "status": "done",
            "exit_code": 0,
            "stdout": """\
[ATTEMPT] target 10.49.146.5 - login "anonymous" - pass "anonymous@" - 1 of 1 [child 0] (0/0)
1 of 1 target completed, 0 valid password found
Hydra finished
""",
            "stderr": "",
        }
        outcome, summary = self.task_run._detect_outcome(row)
        self.assertEqual(outcome, "miss")
        self.assertEqual(summary, "0 valid passwords")

    def test_detect_outcome_hit_valid_count(self) -> None:
        row = {
            "status": "done",
            "exit_code": 0,
            "stdout": "1 of 1 target completed, 1 valid password found\n",
            "stderr": "",
        }
        outcome, summary = self.task_run._detect_outcome(row)
        self.assertEqual(outcome, "hit")
        self.assertIn("1 valid", summary)


if __name__ == "__main__":
    unittest.main()
