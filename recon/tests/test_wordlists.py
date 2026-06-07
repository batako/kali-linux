#!/usr/bin/env python3
"""Tests for recon/wordlists — run inside kali where SecLists is installed."""

from __future__ import annotations

import sys
import unittest
from io import StringIO
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

    def test_scout_resolve_id(self) -> None:
        from wordlists.scout import resolve_scout_wordlist

        path = resolve_scout_wordlist("dirbuster-small", extensions="ticket")
        self.assertIn("DirBuster-2007_directory-list-2.3-small.txt", path)

    def test_scout_default_dirs_ext(self) -> None:
        from wordlists.scout import default_wordlist_id

        self.assertEqual(default_wordlist_id(extensions="bak"), "common")

    def test_scout_default_dirs(self) -> None:
        from wordlists.scout import default_wordlist_id

        self.assertEqual(default_wordlist_id(extensions=None), "common")

    def test_scout_unknown_id_raises(self) -> None:
        from wordlists.scout import resolve_scout_wordlist

        with self.assertRaises(ValueError):
            resolve_scout_wordlist("no-such-wordlist-id", extensions=None)

    def test_scout_no_flag_uses_default(self) -> None:
        from wordlists.scout import resolve_scout_wordlist

        path = resolve_scout_wordlist(None, extensions="ticket", from_flag=False)
        self.assertIn("common.txt", path)

    def test_scout_from_flag_empty_triggers_pick(self) -> None:
        from wordlists.scout import _pick_mode

        self.assertEqual(_pick_mode("pick"), "context")
        self.assertEqual(_pick_mode("browse"), "browse")
        self.assertIsNone(_pick_mode(""))

    def test_pick_from_selector_by_number(self) -> None:
        from wordlists.pick import pick_from_selector

        picked = pick_from_selector(
            self.catalog,
            "dirs-ext",
            input_fn=lambda _prompt: "2",
            output=StringIO(),
        )
        self.assertEqual(picked, "dirbuster-small")

    def test_pick_from_selector_by_id(self) -> None:
        from wordlists.pick import pick_from_selector

        picked = pick_from_selector(
            self.catalog,
            "dirs",
            input_fn=lambda _prompt: "common",
            output=StringIO(),
        )
        self.assertEqual(picked, "common")

    def test_pick_from_selector_cancel(self) -> None:
        from wordlists.pick import pick_from_selector

        picked = pick_from_selector(
            self.catalog,
            "dirs",
            input_fn=lambda _prompt: "q",
            output=StringIO(),
        )
        self.assertIsNone(picked)

    def test_dirs_multi_default_dirs_selector(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists()
        self.assertEqual(len(paths), 3)
        names = {Path(p).name for p in paths}
        self.assertIn("common.txt", names)
        self.assertIn("raft-small-directories.txt", names)
        self.assertIn("quickhits.txt", names)

    def test_dirs_multi_preset_standard(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(preset="standard", preset_from_flag=True)
        self.assertEqual(len(paths), 3)

    def test_dirs_multi_preset_ctf_alias(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(preset="ctf", preset_from_flag=True)
        self.assertEqual(len(paths), 3)

    def test_dirs_multi_preset_light(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(preset="light", preset_from_flag=True)
        self.assertEqual(len(paths), 2)

    def test_dirs_multi_preset_fast_alias(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(preset="fast", preset_from_flag=True)
        self.assertEqual(len(paths), 2)

    def test_dirs_multi_preset_wide(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(preset="wide", preset_from_flag=True)
        self.assertEqual(len(paths), 4)

    def test_dirs_multi_preset_deep(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(preset="deep", preset_from_flag=True)
        self.assertEqual(len(paths), 6)
        names = {Path(p).name for p in paths}
        self.assertIn("DirBuster-2007_directory-list-2.3-small.txt", names)
        self.assertIn("raft-small-words.txt", names)

    def test_dirs_multi_ext_default_standard(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(extensions="php")
        self.assertEqual(len(paths), 2)
        names = {Path(p).name for p in paths}
        self.assertIn("common.txt", names)
        self.assertIn("DirBuster-2007_directory-list-2.3-small.txt", names)

    def test_dirs_multi_ext_preset_light(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(
            preset="light",
            extensions="php",
            preset_from_flag=True,
        )
        self.assertEqual(len(paths), 1)

    def test_dirs_multi_ext_preset_fast_alias(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(
            preset="fast",
            extensions="php",
            preset_from_flag=True,
        )
        self.assertEqual(len(paths), 1)

    def test_dirs_multi_ext_preset_deep(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(
            preset="deep",
            extensions="ticket",
            preset_from_flag=True,
        )
        self.assertEqual(len(paths), 4)

    def test_dirs_multi_ext_unknown_preset(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        with self.assertRaises(ValueError):
            resolve_dirs_multi_wordlists(
                preset="nope",
                extensions="ticket",
                preset_from_flag=True,
            )

    def test_dirs_multi_custom_ids(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        paths = resolve_dirs_multi_wordlists(
            wordlist_ids=["common", "quickhits"],
        )
        self.assertEqual(len(paths), 2)

    def test_dirs_multi_unknown_preset(self) -> None:
        from wordlists.scout import resolve_dirs_multi_wordlists

        with self.assertRaises(ValueError):
            resolve_dirs_multi_wordlists(preset="nope", preset_from_flag=True)

    def test_next_tier_adds(self) -> None:
        done = {
            self.catalog.resolve("common"),
            self.catalog.resolve("quickhits"),
            self.catalog.resolve("raft-small-directories"),
        }
        tier, _label, pending = self.catalog.next_tier_adds(
            extensions=False,
            done_wordlist_paths=done,
        )
        self.assertEqual(tier, "wide")
        self.assertEqual(pending, ("discovery-web-content-raft-small-files",))

    def test_next_tier_all_done(self) -> None:
        ids = self.catalog.cumulative_preset_ids("deep", extensions=False)
        done = {self.catalog.resolve(i) for i in ids}
        tier, _label, pending = self.catalog.next_tier_adds(
            extensions=False,
            done_wordlist_paths=done,
        )
        self.assertEqual(tier, "")
        self.assertEqual(pending, ())

    def test_unique_paths_and_ids(self) -> None:
        ids = [e.id for e in self.catalog.entries]
        paths = [e.path for e in self.catalog.entries]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(paths), len(set(paths)))


if __name__ == "__main__":
    unittest.main()
