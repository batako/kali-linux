#!/usr/bin/env python3
"""Tests for recon/wordlists — run inside kali where SecLists is installed."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from wordlists.wordlists import WordlistCatalog  # noqa: E402


class WordlistCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = WordlistCatalog.load()

    def test_entry_count(self) -> None:
        self.assertGreaterEqual(len(self.catalog.entries), 6000)

    def test_resolve_short_id(self) -> None:
        path = self.catalog.resolve("common")
        self.assertTrue(path.endswith("/Discovery/Web-Content/common.txt"))

    def test_resolve_dirbuster_small(self) -> None:
        path = self.catalog.resolve("dirbuster-small")
        self.assertIn("DirBuster-2007_directory-list-2.3-small.txt", path)

    def test_list_dirs_ext_selector(self) -> None:
        entries = self.catalog.list_selector("dirs-ext")
        ids = {e.id for e in entries}
        self.assertIn("common", ids)
        self.assertIn("dirbuster-small", ids)

    def test_validate_full_coverage(self) -> None:
        issues = self.catalog.validate()
        errors = [i for i in issues if i.level == "error"]
        self.assertEqual(
            errors,
            [],
            msg="\n".join(i.message for i in errors[:10]),
        )

    def test_unique_paths_and_ids(self) -> None:
        ids = [e.id for e in self.catalog.entries]
        paths = [e.path for e in self.catalog.entries]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(paths), len(set(paths)))


if __name__ == "__main__":
    unittest.main()
