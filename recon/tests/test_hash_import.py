#!/usr/bin/env python3
"""Tests for MSF / manual hashdump parsing."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from hash_import import parse_hashdump_text
from hash_import import parse_msf_hashdump


MSF_SAMPLE = """
[+] 10.0.0.1:5432 - PostgreSQL - Hash table dump
Username                                Hash
--------                                ----
postgres                                md532e12f215ba27cb750c9e093ce4b5127
darkstart                               md58842b99375db43e9fdf238753623a27d
"""


class HashImportTest(unittest.TestCase):
    def test_msf_table_format(self) -> None:
        rows = parse_msf_hashdump(MSF_SAMPLE)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].username, "postgres")
        self.assertEqual(rows[0].stored, "md532e12f215ba27cb750c9e093ce4b5127")
        self.assertEqual(rows[0].format, "postgres_md5")
        self.assertEqual(rows[0].parser, "msf_hashdump/table")

    def test_colon_format(self) -> None:
        rows = parse_hashdump_text("postgres:md532e12f215ba27cb750c9e093ce4b5127")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].parser, "msf_hashdump/colon")

    def test_manual_fields(self) -> None:
        rows = parse_hashdump_text("darkstart md58842b99375db43e9fdf238753623a27d")
        self.assertEqual(rows[0].username, "darkstart")
        self.assertEqual(rows[0].parser, "msf_hashdump/table")

    def test_dedupes_same_user_hash(self) -> None:
        text = (
            "postgres md532e12f215ba27cb750c9e093ce4b5127\n"
            "postgres md532e12f215ba27cb750c9e093ce4b5127\n"
        )
        self.assertEqual(len(parse_hashdump_text(text)), 1)

    def test_skips_header_lines(self) -> None:
        text = "Username\tHash\n--------\t----\n"
        self.assertEqual(parse_hashdump_text(text), [])


if __name__ == "__main__":
    unittest.main()
