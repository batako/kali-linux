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
            (5432, "tcp", "open", "postgresql", "9.5"),
        ]
        self.assertEqual(msf_run.resolve_port_from_scout("10.0.0.1", "postgres"), 5432)
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

    @mock.patch("msf_run.os.path.isfile", return_value=True)
    @mock.patch.dict(
        "os.environ",
        {
            "MSFR_USERLIST": "/wl/users.txt",
            "RECON_PASSLIST": "/wl/pass.txt",
        },
        clear=False,
    )
    def test_login_scan_resource_sets_default(self, _mock_isfile) -> None:
        sets = dict(msf_run.login_scan_resource_sets("ssh-login"))
        self.assertEqual(sets["USER_FILE"], "/wl/users.txt")
        self.assertEqual(sets["PASS_FILE"], "/wl/pass.txt")

    @mock.patch("msf_run.os.path.isfile", return_value=True)
    @mock.patch.dict("os.environ", {"RECON_PASSLIST": "/wl/pass.txt"}, clear=False)
    def test_login_scan_resource_sets_single_user(self, _mock_isfile) -> None:
        sets = dict(msf_run.login_scan_resource_sets("ssh-login", user="root"))
        self.assertEqual(sets["USERNAME"], "root")
        self.assertEqual(sets["PASS_FILE"], "/wl/pass.txt")
        self.assertNotIn("USER_FILE", sets)

    def test_login_scan_resource_sets_user_pass(self) -> None:
        sets = dict(
            msf_run.login_scan_resource_sets(
                "ftp-login", user="anonymous", password="anonymous@"
            )
        )
        self.assertEqual(sets["FTPUSER"], "anonymous")
        self.assertEqual(sets["FTPPASS"], "anonymous@")

    def test_login_scan_pg_login_empty(self) -> None:
        self.assertEqual(msf_run.login_scan_resource_sets("pg-login"), [])
