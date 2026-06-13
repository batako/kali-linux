#!/usr/bin/env python3
"""DB migration tests."""

from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class DbMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "legacy.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        os.environ["RECON_DB_PATH"] = str(self.db_path)

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                task_type TEXT,
                description TEXT,
                status TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO tasks (ip, task_type, description, status) VALUES (?, ?, ?, ?)",
            ("10.0.0.1", "dir-brute", "web directory brute force", "pending"),
        )
        conn.commit()
        conn.close()

        import db

        importlib.reload(db)
        self.db = db

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("RECON_DB_PATH", None)
        else:
            os.environ["RECON_DB_PATH"] = self._old_db
        self._tmpdir.cleanup()

    def test_init_db_replaces_legacy_tasks_schema(self) -> None:
        self.db.init_db()
        conn = self.db.connect()
        cols = {r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()}
        conn.close()
        self.assertIn("dedupe_key", cols)
        self.assertIn("outcome", cols)
        self.assertIn("execution_id", cols)


if __name__ == "__main__":
    unittest.main()
