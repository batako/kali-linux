#!/usr/bin/env python3
"""Tests for hash-list state and john conversion."""

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

from hash_import import HashRecord
from hash_store import STATE_CRACKED
from hash_store import STATE_FAILED
from hash_store import STATE_IMPORTED
from hash_store import STATE_JOHN_READY
from hash_store import STATE_UNSUPPORTED
from hash_store import ensure_john_line
from hash_store import entry_from_import
from hash_store import merge_on_import
from hash_store import new_entry
from hash_store import should_crack


class HashStoreTest(unittest.TestCase):
    def test_merge_unchanged_same_stored(self) -> None:
        rec = HashRecord(
            "postgres",
            "postgres_md5",
            "md532e12f215ba27cb750c9e093ce4b5127",
            "raw",
            "msf_hashdump/table",
        )
        incoming = entry_from_import(rec)
        existing = entry_from_import(rec)
        existing.state = STATE_JOHN_READY
        existing.john = "postgres:$dynamic_1034$32e12f215ba27cb750c9e093ce4b5127"
        merged, status = merge_on_import(existing, incoming)
        self.assertEqual(status, "unchanged")
        self.assertEqual(merged.state, STATE_JOHN_READY)

    def test_merge_updated_clears_john(self) -> None:
        rec = HashRecord(
            "postgres",
            "postgres_md5",
            "md532e12f215ba27cb750c9e093ce4b5127",
            "raw",
            "msf_hashdump/table",
        )
        incoming = entry_from_import(rec)
        existing = entry_from_import(rec)
        existing.state = STATE_CRACKED
        existing.john = "x"
        incoming.stored = "md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        merged, status = merge_on_import(existing, incoming)
        self.assertEqual(status, "updated")
        self.assertEqual(merged.state, STATE_IMPORTED)
        self.assertIsNone(merged.john)

    def test_ensure_john_line_caches(self) -> None:
        entry = new_entry(
            username="postgres",
            format="postgres_md5",
            stored="md532e12f215ba27cb750c9e093ce4b5127",
        )
        out = ensure_john_line(entry)
        self.assertEqual(out.state, STATE_JOHN_READY)
        self.assertEqual(
            out.john, "postgres:$dynamic_1034$32e12f215ba27cb750c9e093ce4b5127"
        )

    def test_scram_is_unsupported(self) -> None:
        entry = new_entry(
            username="postgres",
            format="scram_sha256",
            stored="SCRAM-SHA-256$4096:abc",
        )
        self.assertEqual(entry.state, STATE_UNSUPPORTED)
        self.assertFalse(should_crack(entry))

    def test_should_crack_failed_only_with_force(self) -> None:
        entry = new_entry(
            username="u",
            format="postgres_md5",
            stored="md532e12f215ba27cb750c9e093ce4b5127",
            state=STATE_FAILED,
        )
        self.assertFalse(should_crack(entry))
        self.assertTrue(should_crack(entry, force=True))


class HashDbTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "poster"

        import db

        importlib.reload(db)
        self.db = db

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

    def test_upsert_list_delete(self) -> None:
        from hash_ops import import_hash_records

        rec = HashRecord(
            "postgres",
            "postgres_md5",
            "md532e12f215ba27cb750c9e093ce4b5127",
            "raw",
            "msf_hashdump/table",
        )
        results = import_hash_records("10.0.0.1", [rec])
        self.assertEqual(results[0]["status"], "saved")

        entries = self.db.list_hash_entries("10.0.0.1")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].state, STATE_IMPORTED)

        results2 = import_hash_records("10.0.0.1", [rec])
        self.assertEqual(results2[0]["status"], "unchanged")

        n = self.db.hash_delete("10.0.0.1", "postgres")
        self.assertEqual(n, 1)
        self.assertEqual(self.db.list_hash_entries("10.0.0.1"), [])


if __name__ == "__main__":
    unittest.main()
