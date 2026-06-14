#!/usr/bin/env python3
"""Tests for hydra output → creds import."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from creds import import_hydra


class CredsHydraImportTest(unittest.TestCase):
    @patch("creds.creds_upsert", return_value="saved")
    def test_import_http_get_basic(self, mock_upsert) -> None:
        text = (
            "[80][http-get] host: 10.0.0.1   login: barry   password: s3cret\n"
            "1 of 1 target successfully completed, 1 valid password found\n"
        )
        rows = import_hydra(text, ip="10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "barry")
        self.assertEqual(rows[0]["password"], "s3cret")
        mock_upsert.assert_called_once_with(
            ip="10.0.0.1",
            username="barry",
            password="s3cret",
            execution_id=None,
            comment="HTTP Basic (hydra)",
        )

    @patch("creds.creds_upsert", return_value="saved")
    def test_import_http_post_form(self, mock_upsert) -> None:
        text = "[80][http-post-form] host: 10.0.0.1   login: admin   password: pass\n"
        rows = import_hydra(text, ip="10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "admin")

    @patch("creds.creds_upsert", return_value="saved")
    def test_import_ftp_without_password(self, mock_upsert) -> None:
        text = (
            "[\x1b[1;32m21\x1b[0m][\x1b[1;32mftp\x1b[0m] host: "
            "\x1b[1;32m10.0.0.1\x1b[0m   login: \x1b[1;32manonymous\x1b[0m\n"
            "1 of 1 target successfully completed, 1 valid password found\n"
        )
        rows = import_hydra(text, ip="10.0.0.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "anonymous")
        self.assertEqual(rows[0]["password"], "")
        mock_upsert.assert_called_once_with(
            ip="10.0.0.1",
            username="anonymous",
            password="",
            execution_id=None,
            comment="FTP (hydra)",
        )


if __name__ == "__main__":
    unittest.main()
