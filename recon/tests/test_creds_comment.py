#!/usr/bin/env python3
"""Tests for creds comment storage and listing."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

import db as db_mod


class CredsCommentTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_db = db_mod.DB_PATH
        db_mod.DB_PATH = str(Path(self._tmpdir.name) / "recon.db")
        db_mod.init_db()

    def tearDown(self) -> None:
        db_mod.DB_PATH = self._old_db
        self._tmpdir.cleanup()

    def test_upsert_and_list_comment(self) -> None:
        status = db_mod.creds_upsert(
            "10.0.0.1", "barry", "secret", comment="HTTP Basic (hydra)"
        )
        self.assertEqual(status, "saved")

        rows = db_mod.list_ssh_creds("10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["comment"], "HTTP Basic (hydra)")

    def test_comment_update_without_password_change(self) -> None:
        db_mod.creds_upsert("10.0.0.1", "barry", "secret", comment="SSH (hydra)")
        status = db_mod.creds_upsert(
            "10.0.0.1", "barry", "secret", comment="HTTP Basic (hydra)"
        )
        self.assertEqual(status, "updated")
        rows = db_mod.list_ssh_creds("10.0.0.1")
        self.assertEqual(rows[0]["comment"], "HTTP Basic (hydra)")

    def test_manual_add_without_comment_preserves_existing(self) -> None:
        db_mod.creds_upsert("10.0.0.1", "barry", "secret", comment="FTP (hydra)")
        status = db_mod.creds_upsert("10.0.0.1", "barry", "newpass")
        self.assertEqual(status, "updated")
        rows = db_mod.list_ssh_creds("10.0.0.1")
        self.assertEqual(rows[0]["password"], "newpass")
        self.assertEqual(rows[0]["comment"], "FTP (hydra)")

    def test_delete_removes_comment(self) -> None:
        db_mod.creds_upsert("10.0.0.1", "barry", "secret", comment="SSH (hydra)")
        db_mod.creds_delete("10.0.0.1", "barry")
        self.assertEqual(db_mod.list_ssh_creds("10.0.0.1"), [])

    def test_upsert_allows_blank_password(self) -> None:
        status = db_mod.creds_upsert("10.0.0.1", "anonymous", "")
        self.assertEqual(status, "saved")
        rows = db_mod.list_ssh_creds("10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "anonymous")
        self.assertEqual(rows[0]["password"], "")


if __name__ == "__main__":
    unittest.main()
