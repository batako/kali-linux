#!/usr/bin/env python3
"""Tests for lhost detection."""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from unittest import mock

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))


class LhostTests(unittest.TestCase):
    def setUp(self) -> None:
        import lhost

        importlib.reload(lhost)
        self.lhost = lhost

    @mock.patch("lhost.subprocess.run")
    def test_ipv4_on_iface(self, mock_run) -> None:
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout="3: tun0    inet 10.10.14.5/16 brd 10.10.255.255 scope global tun0\n",
        )
        self.assertEqual(self.lhost.ipv4_on_iface("tun0"), "10.10.14.5")

    @mock.patch("lhost.ipv4_on_iface")
    def test_collect_tun0_only(self, mock_ip) -> None:
        mock_ip.return_value = "10.10.14.5"
        info = self.lhost.collect_lhost_info()
        self.assertEqual(info, {"tun0": "10.10.14.5"})
        mock_ip.assert_called_once_with("tun0")

    @mock.patch("lhost.ipv4_on_iface")
    def test_collect_tun0_down(self, mock_ip) -> None:
        mock_ip.return_value = None
        self.assertEqual(self.lhost.collect_lhost_info(), {"tun0": None})


if __name__ == "__main__":
    unittest.main()
