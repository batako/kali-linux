#!/usr/bin/env python3
"""Tests for PostgreSQL stored MD5 → john line conversion."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from hash_crack import is_postgres_stored_md5
from hash_crack import postgres_stored_to_john_line


class HashCrackPostgresTest(unittest.TestCase):
    def test_postgres_password_example(self) -> None:
        line = postgres_stored_to_john_line(
            "postgres", "md532e12f215ba27cb750c9e093ce4b5127"
        )
        self.assertEqual(
            line, "postgres:$dynamic_1034$32e12f215ba27cb750c9e093ce4b5127"
        )

    def test_is_postgres_stored_md5(self) -> None:
        self.assertTrue(is_postgres_stored_md5("md532e12f215ba27cb750c9e093ce4b5127"))
        self.assertFalse(is_postgres_stored_md5("32e12f215ba27cb750c9e093ce4b5127"))


if __name__ == "__main__":
    unittest.main()
