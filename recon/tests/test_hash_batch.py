#!/usr/bin/env python3
"""Tests for hash-list batch prepare / john show parsing."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from hash_batch import parse_john_crack_stdout
from hash_batch import parse_john_show
from hash_batch import prepare_batch
from hash_import import HashRecord
from hash_ops import import_hash_records
from hash_store import STATE_CRACKED
from hash_store import STATE_FAILED


class HashBatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "poster"

        import db

        importlib.reload(db)
        import hash_batch

        importlib.reload(hash_batch)
        self.db = db
        self.hash_batch = hash_batch
        self.ip = "10.0.0.1"

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

    def _add_postgres(self, user: str, hex_part: str) -> None:
        rec = HashRecord(
            user,
            "postgres_md5",
            f"md5{hex_part}",
            "raw",
            "test",
        )
        import_hash_records(self.ip, [rec])

    def test_prepare_batch_converts_pending(self) -> None:
        self._add_postgres("postgres", "32e12f215ba27cb750c9e093ce4b5127")
        lines, users, fmt = prepare_batch(self.ip)
        self.assertEqual(fmt, "dynamic_1034")
        self.assertEqual(users, ["postgres"])
        self.assertEqual(len(lines), 1)
        self.assertIn("$dynamic_1034$", lines[0])

    def test_prepare_batch_skips_cracked(self) -> None:
        self._add_postgres("postgres", "32e12f215ba27cb750c9e093ce4b5127")
        entry = self.db.list_hash_entries(self.ip)[0]
        entry.state = STATE_CRACKED
        self.db.hash_save_entry(self.ip, entry)
        lines, users, fmt = prepare_batch(self.ip)
        self.assertEqual(lines, [])
        self.assertEqual(users, [])

    def test_prepare_batch_force_includes_failed(self) -> None:
        self._add_postgres("postgres", "32e12f215ba27cb750c9e093ce4b5127")
        entry = self.db.list_hash_entries(self.ip)[0]
        entry.state = STATE_FAILED
        self.db.hash_save_entry(self.ip, entry)
        lines, _, _ = prepare_batch(self.ip)
        self.assertEqual(lines, [])
        lines2, _, _ = prepare_batch(self.ip, force=True)
        self.assertEqual(len(lines2), 1)

    def test_parse_john_show_dynamic(self) -> None:
        text = "postgres:$dynamic_1034$32e12f215ba27cb750c9e093ce4b5127:password\n"
        cracked = parse_john_show(text)
        self.assertEqual(cracked["postgres"], "password")

    def test_parse_john_crack_stdout(self) -> None:
        text = (
            "password         (postgres)\n"
            "batman           (poster)\n"
        )
        cracked = parse_john_crack_stdout(text)
        self.assertEqual(cracked["postgres"], "password")
        self.assertEqual(cracked["poster"], "batman")

    def test_apply_batch_results_fallback_crack_stdout(self) -> None:
        self._add_postgres("postgres", "32e12f215ba27cb750c9e093ce4b5127")
        crack_out = "password         (postgres)\n"
        with patch("hash_batch.creds_upsert", return_value="saved") as mock_upsert:
            results = self.hash_batch.apply_batch_results(
                self.ip, ["postgres"], "", crack_text=crack_out
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["password"], "password")
        mock_upsert.assert_called_once()

    @patch("hash_batch.creds_upsert", return_value="saved")
    def test_apply_batch_results(self, mock_upsert) -> None:
        self._add_postgres("postgres", "32e12f215ba27cb750c9e093ce4b5127")
        show = "postgres:$dynamic_1034$32e12f215ba27cb750c9e093ce4b5127:secret\n"
        results = self.hash_batch.apply_batch_results(
            self.ip, ["postgres"], show
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["password"], "secret")
        entry = self.db.list_hash_entries(self.ip)[0]
        self.assertEqual(entry.state, STATE_CRACKED)
        mock_upsert.assert_called_once()


if __name__ == "__main__":
    unittest.main()
