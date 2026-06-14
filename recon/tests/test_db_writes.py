#!/usr/bin/env python3
"""SQLite write serialization and retry tests."""

from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class DbWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "writes.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "writetest"

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

    def test_finish_task_concurrent(self) -> None:
        task_ids = []
        for port in (21, 22, 80):
            _, tid = self.db.upsert_task(
                ip="10.0.0.1",
                port=port,
                service="svc",
                task_type=f"auth-{port}",
                command=f"hydra ... {port}",
            )
            task_ids.append(tid)

        errors: list[Exception] = []

        def _finish(tid: int) -> None:
            try:
                self.db.finish_task(
                    tid,
                    status="done",
                    outcome="miss",
                    result_summary="ok",
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_finish, args=(tid,)) for tid in task_ids]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])

    def test_db_write_retries_on_busy(self) -> None:
        calls = {"n": 0}

        def _flaky(conn) -> int:
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            conn.execute("SELECT 1")
            return 42

        with mock.patch.object(self.db, "db_file_lock", wraps=self.db.db_file_lock):
            with mock.patch("db.time.sleep"):
                result = self.db.db_write(_flaky)

        self.assertEqual(result, 42)
        self.assertEqual(calls["n"], 2)


if __name__ == "__main__":
    unittest.main()
