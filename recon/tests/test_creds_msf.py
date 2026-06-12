#!/usr/bin/env python3
"""Tests for Metasploit login output → creds import."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from creds import import_msf_login
from msf_run import list_msfr_creds
from msf_run import pick_msfr_user
from msf_run import resolve_msfr_user


class CredsMsfImportTest(unittest.TestCase):
    @patch("creds.creds_upsert", return_value="saved")
    def test_import_postgres_login_quoted(self, mock_upsert) -> None:
        text = "[+] 10.0.0.1:5432 - Success: 'postgres:password@template1'\n"
        rows = import_msf_login("pg-login", text, ip="10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "postgres")
        self.assertEqual(rows[0]["password"], "password")
        mock_upsert.assert_called_once_with(
            ip="10.0.0.1",
            username="postgres",
            password="password",
            execution_id=None,
            comment="PostgreSQL (msfr)",
        )

    @patch("creds.creds_upsert", return_value="saved")
    def test_import_postgres_login_msf64(self, mock_upsert) -> None:
        text = (
            "[+] 10.48.139.75:5432 - 10.48.139.75:5432 - "
            "Login Successful: postgres:password@template1\n"
        )
        rows = import_msf_login("pg-login", text, ip="10.48.139.75")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "postgres")
        self.assertEqual(rows[0]["password"], "password")

    @patch("creds.creds_upsert", return_value="saved")
    def test_import_mysql_login(self, mock_upsert) -> None:
        text = "[+] 10.0.0.1:3306 - Success: 'root:secret'\n"
        rows = import_msf_login("my-login", text, ip="10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "root")
        self.assertEqual(rows[0]["password"], "secret")
        mock_upsert.assert_called_once_with(
            ip="10.0.0.1",
            username="root",
            password="secret",
            execution_id=None,
            comment="MySQL (msfr)",
        )

    @patch("creds.creds_upsert", return_value="saved")
    def test_import_ssh_login(self, mock_upsert) -> None:
        text = "[+] 10.0.0.1:22 - Success: 'root' 'toor' 'SSH-2.0-OpenSSH'\n"
        rows = import_msf_login("ssh-login", text, ip="10.0.0.1")
        self.assertEqual(rows[0]["username"], "root")
        self.assertEqual(rows[0]["password"], "toor")

    @patch("db.list_hash_entries", return_value=[])
    @patch("db.list_ssh_creds")
    def test_list_msfr_creds_includes_manual(self, mock_list, _mock_hash) -> None:
        mock_list.return_value = [
            {"username": "postgres", "password": "p", "comment": "PostgreSQL (msfr)"},
            {"username": "alison", "password": "x", "comment": ""},
        ]
        rows = list_msfr_creds("10.0.0.1", "postgres")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["username"], "postgres")
        self.assertEqual(rows[1]["username"], "alison")

    @patch("db.list_hash_entries", return_value=[])
    @patch("db.list_ssh_creds")
    def test_list_msfr_creds_excludes_ssh_comment(self, mock_list, _mock_hash) -> None:
        mock_list.return_value = [
            {"username": "postgres", "password": "p", "comment": "PostgreSQL (msfr)"},
            {"username": "dark", "password": "x", "comment": "SSH"},
        ]
        rows = list_msfr_creds("10.0.0.1", "postgres")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "postgres")

    @patch("db.list_hash_entries", return_value=[])
    @patch("db.list_ssh_creds")
    def test_list_msfr_creds_includes_hash_crack(self, mock_list, _mock_hash) -> None:
        mock_list.return_value = [
            {"username": "postgres", "password": "p", "comment": "PostgreSQL (msfr)"},
            {
                "username": "darkstart",
                "password": "qwerty",
                "comment": "hash-crack postgres",
            },
        ]
        rows = list_msfr_creds("10.0.0.1", "postgres")
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["username"] for r in rows}, {"postgres", "darkstart"})

    @patch("db.list_ssh_creds")
    def test_resolve_msfr_user_explicit(self, mock_list) -> None:
        mock_list.return_value = [
            {"username": "darkstart", "password": "qwerty", "comment": "hash-crack postgres"},
        ]
        self.assertEqual(
            resolve_msfr_user("10.0.0.1", "postgres", user="darkstart"),
            "darkstart",
        )

    @patch("db.get_msfr_last_user", return_value=None)
    @patch("db.list_ssh_creds")
    def test_pick_msfr_user_single(self, mock_list, _mock_last) -> None:
        mock_list.return_value = [
            {"username": "postgres", "password": "p", "comment": "PostgreSQL (msfr)"},
        ]
        self.assertEqual(pick_msfr_user("10.0.0.1", "postgres"), "postgres")


if __name__ == "__main__":
    unittest.main()
