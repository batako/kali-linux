#!/usr/bin/env python3
"""Tests for msfr helpers."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

import msf_run


class TestMsfRun(unittest.TestCase):
    def test_module_family(self) -> None:
        self.assertEqual(
            msf_run.module_family("auxiliary/scanner/postgres/postgres_login"),
            "postgres",
        )
        self.assertEqual(
            msf_run.module_family("auxiliary/scanner/mysql/mysql_login"),
            "mysql",
        )
        self.assertEqual(
            msf_run.module_family("exploit/multi/http/tomcat_mgr_upload"),
            "http",
        )
        self.assertEqual(
            msf_run.module_family("auxiliary/scanner/ssh/ssh_login"),
            "ssh",
        )
        self.assertEqual(msf_run.module_family("exploit/linux/local/foo"), "generic")

    def test_cred_option_names(self) -> None:
        self.assertEqual(
            msf_run.cred_option_names("exploit/multi/http/tomcat_mgr_upload"),
            ("HttpUsername", "HttpPassword"),
        )
        self.assertEqual(
            msf_run.cred_option_names("auxiliary/scanner/postgres/postgres_sql"),
            ("USERNAME", "PASSWORD"),
        )

    @mock.patch("msf_run.fetch_merged_open_ports")
    def test_resolve_port_from_scout(self, mock_ports) -> None:
        mock_ports.return_value = [
            (22, "tcp", "open", "ssh", "OpenSSH"),
            (80, "tcp", "open", "http", "Apache"),
            (3306, "tcp", "open", "mysql", "5.7"),
            (5432, "tcp", "open", "postgresql", "9.5"),
        ]
        self.assertEqual(msf_run.resolve_port_from_scout("10.0.0.1", "postgres"), 5432)
        self.assertEqual(msf_run.resolve_port_from_scout("10.0.0.1", "mysql"), 3306)
        self.assertEqual(msf_run.resolve_port_from_scout("10.0.0.1", "http"), 80)
        self.assertIsNone(msf_run.resolve_port_from_scout("10.0.0.1", "ftp"))

    @mock.patch("msf_run.resolve_port_from_scout", return_value=8080)
    def test_resolve_rport_prefers_explicit(self, _mock_scout) -> None:
        self.assertEqual(
            msf_run.resolve_rport(
                "10.0.0.1",
                "exploit/multi/http/tomcat_mgr_upload",
                explicit=1234,
            ),
            1234,
        )

    @mock.patch.dict("os.environ", {"HTTP_PORT": "8443"}, clear=False)
    @mock.patch("msf_run.resolve_port_from_scout", return_value=None)
    def test_resolve_rport_env_family(self, _mock_scout) -> None:
        self.assertEqual(
            msf_run.resolve_rport("10.0.0.1", "exploit/multi/http/tomcat_mgr_upload"),
            8443,
        )

    def test_default_ssl(self) -> None:
        self.assertTrue(msf_run.default_ssl(443, "exploit/multi/http/foo"))
        self.assertFalse(msf_run.default_ssl(80, "exploit/multi/http/foo"))

    def test_login_scan_resource_sets_default(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("root:toor\n")
            path = tmp.name
        try:
            with mock.patch.dict(
                os.environ, {"MSFR_SSH_USERPASS": path}, clear=False
            ):
                result = msf_run.login_scan_resource_sets("ssh-login")
            sets = dict(result.sets)
            self.assertEqual(len(result.temp_files), 1)
            self.assertIn("USERPASS_FILE", sets)
            with open(sets["USERPASS_FILE"], encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "root toor\n")
        finally:
            os.remove(path)
            for temp in result.temp_files:
                if os.path.isfile(temp):
                    os.remove(temp)

    def test_login_scan_resource_sets_single_user(self) -> None:
        result = msf_run.login_scan_resource_sets("ssh-login", user="root")
        sets = dict(result.sets)
        self.assertEqual(sets["USERNAME"], "root")
        self.assertNotIn("PASS_FILE", sets)
        self.assertNotIn("USER_FILE", sets)
        self.assertNotIn("USERPASS_FILE", sets)

    def test_login_scan_resource_sets_user_pass(self) -> None:
        sets = dict(
            msf_run.login_scan_resource_sets(
                "ftp-login", user="anonymous", password="anonymous@"
            ).sets
        )
        self.assertEqual(sets["FTPUSER"], "anonymous")
        self.assertEqual(sets["FTPPASS"], "anonymous@")

    def test_login_scan_pg_login_empty(self) -> None:
        result = msf_run.login_scan_resource_sets("pg-login")
        self.assertEqual(result.sets, [])
        self.assertEqual(result.temp_files, [])

    def test_prepare_msf_userpass_file_converts_colon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.txt")
            with open(src, "w", encoding="utf-8") as handle:
                handle.write("root:toor\nadmin:admin\n")
            msf_path, is_temp = msf_run.prepare_msf_userpass_file(src)
            self.assertTrue(is_temp)
            try:
                with open(msf_path, encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), "root toor\nadmin admin\n")
            finally:
                os.remove(msf_path)

    def test_login_scan_result_iter_compat(self) -> None:
        result = msf_run.LoginScanResult(sets=[("USERNAME", "root")])
        self.assertEqual(dict(result), {"USERNAME": "root"})
        path = msf_run.default_quick_userpass_file("ssh")
        self.assertIn("ssh-betterdefaultpasslist.txt", path)

    def test_default_quick_userpass_file_ftp(self) -> None:
        path = msf_run.default_quick_userpass_file("ftp")
        self.assertIn("ftp-betterdefaultpasslist.txt", path)


if __name__ == "__main__":
    unittest.main()
