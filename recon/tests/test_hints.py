#!/usr/bin/env python3
"""Tests for hint / memo storage."""

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


class HintTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self._old_db = os.environ.get("RECON_DB_PATH")
        self._old_case = os.environ.get("CASE")
        os.environ["RECON_DB_PATH"] = str(self.db_path)
        os.environ["CASE"] = "lianyu"

        import db

        importlib.reload(db)
        import hints

        importlib.reload(hints)
        self.hints = hints
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

    def test_scope_from_case_env(self) -> None:
        self.assertEqual(self.hints.hint_scope(), "lianyu")

    def test_add_list_and_report(self) -> None:
        status, hid = self.hints.add_hint(self.case, "go!go!go!")
        self.assertEqual(status, "saved")
        self.assertGreater(hid, 0)

        status2, _ = self.hints.add_hint(
            self.case,
            "vigilante",
            tag="codeword",
        )
        self.assertEqual(status2, "saved")

        lines = self.hints.format_hint_list_lines(self.case)
        self.assertEqual(len(lines), 2)
        self.assertIn("go!go!go!", lines[0])
        self.assertIn("[codeword] vigilante", lines[1])

        report = self.hints.format_hint_report_lines(self.case)
        self.assertEqual(len(report), 2)
        self.assertFalse(report[0].startswith("  "))

    def test_duplicate_is_unchanged(self) -> None:
        self.hints.add_hint(self.case, "same")
        status, hid = self.hints.add_hint(self.case, "same")
        self.assertEqual(status, "unchanged")
        self.assertEqual(len(self.hints.list_hints(self.case)), 1)
        self.assertGreater(hid, 0)

    def test_delete_hint(self) -> None:
        _status, hid = self.hints.add_hint(self.case, "tmp")
        self.assertTrue(self.hints.delete_hint(hid))
        self.assertEqual(self.hints.list_hints(self.case), [])
        self.assertFalse(self.hints.delete_hint(hid))


if __name__ == "__main__":
    unittest.main()
