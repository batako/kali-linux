#!/usr/bin/env python3
"""Tests for scout vhost scheme planning."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from scout_run import assess_http_vhost_value
from scout_run import plan_vhost_schemes
from scout_run import probe_vhost_wildcard_length
from scout_run import probe_vhost_wildcard_profile
from scout_run import probe_vhost_http_redirect_wildcard
from scout_run import VhostProbeResponse


class ScoutVhostSchemeTest(unittest.TestCase):
    @patch("scout_run.fetch_merged_open_ports")
    def test_auto_both_when_80_and_443(self, mock_ports) -> None:
        mock_ports.return_value = [
            (80, "tcp", "open", "http"),
            (443, "tcp", "open", "https"),
        ]
        self.assertEqual(plan_vhost_schemes("10.0.0.1"), ["https", "http"])

    @patch("scout_run.fetch_merged_open_ports")
    def test_auto_https_only_when_443_open(self, mock_ports) -> None:
        mock_ports.return_value = [(443, "tcp", "open", "https")]
        self.assertEqual(plan_vhost_schemes("10.0.0.1"), ["https"])

    @patch("scout_run.fetch_merged_open_ports")
    def test_auto_http_only_when_80_open(self, mock_ports) -> None:
        mock_ports.return_value = [(80, "tcp", "open", "http")]
        self.assertEqual(plan_vhost_schemes("10.0.0.1"), ["http"])

    @patch("scout_run.fetch_merged_open_ports")
    def test_auto_both_when_no_ports(self, mock_ports) -> None:
        mock_ports.return_value = []
        self.assertEqual(plan_vhost_schemes("10.0.0.1"), ["https", "http"])

    def test_override_flags(self) -> None:
        self.assertEqual(plan_vhost_schemes("10.0.0.1", override="http"), ["http"])
        self.assertEqual(plan_vhost_schemes("10.0.0.1", override="https"), ["https"])
        self.assertEqual(plan_vhost_schemes("10.0.0.1", override="both"), ["https", "http"])


def _mock_probe_response(
    status: int,
    size: int,
    redirect: str = "",
    body_hash: str = "abc",
    server: str = "nginx",
    cookie: str = "",
) -> VhostProbeResponse:
    return VhostProbeResponse(status, size, redirect, body_hash, server, cookie)


class ScoutVhostWildcardProbeTest(unittest.TestCase):
    @patch("scout_run._probe_vhost_host")
    def test_probe_returns_size_on_catch_all(self, mock_probe) -> None:
        mock_probe.return_value = _mock_probe_response(200, 4605)
        profile = probe_vhost_wildcard_profile("futurevera.thm", scheme="https")
        self.assertEqual(profile.suspicion, "strong")
        self.assertEqual(profile.filter_mode, "fs")
        self.assertEqual(profile.exclude_sizes, [4605])
        self.assertEqual(
            probe_vhost_wildcard_length("futurevera.thm", scheme="https"),
            4605,
        )

    @patch("scout_run._probe_vhost_host")
    def test_probe_ignores_404(self, mock_probe) -> None:
        mock_probe.return_value = _mock_probe_response(404, 123)
        self.assertEqual(probe_vhost_wildcard_profile("example.com", scheme="http").suspicion, "none")
        self.assertIsNone(probe_vhost_wildcard_length("example.com", scheme="http"))

    @patch("scout_run._probe_vhost_host")
    def test_probe_http_redirect_size_zero(self, mock_probe) -> None:
        mock_probe.return_value = _mock_probe_response(302, 0, "https://example.com/")
        profile = probe_vhost_wildcard_profile("example.com", scheme="http")
        self.assertEqual(profile.suspicion, "strong")
        self.assertEqual(profile.exclude_sizes, [0])
        self.assertEqual(probe_vhost_wildcard_length("example.com", scheme="http"), 0)

    @patch("scout_run._probe_vhost_host")
    def test_probe_https_empty_body_not_wildcard(self, mock_probe) -> None:
        mock_probe.return_value = _mock_probe_response(404, 0)
        self.assertEqual(probe_vhost_wildcard_profile("example.com", scheme="https").suspicion, "none")
        self.assertIsNone(probe_vhost_wildcard_length("example.com", scheme="https"))

    @patch("scout_run._probe_vhost_host")
    def test_weak_suspicion_uses_ac(self, mock_probe) -> None:
        mock_probe.side_effect = [
            _mock_probe_response(200, 4605, body_hash="aaa"),
            _mock_probe_response(200, 4605, body_hash="bbb"),
            _mock_probe_response(200, 4605, body_hash="ccc"),
        ]
        profile = probe_vhost_wildcard_profile("example.com", scheme="https")
        self.assertEqual(profile.suspicion, "weak")
        self.assertEqual(profile.filter_mode, "ac")
        self.assertEqual(profile.exclude_sizes, [4605])

    @patch("scout_run._probe_vhost_host")
    def test_http_redirect_advisory_not_skip_by_default(self, mock_probe) -> None:
        mock_probe.return_value = _mock_probe_response(302, 0, "https://futurevera.thm/")
        assessment = assess_http_vhost_value("futurevera.thm")
        self.assertEqual(assessment["advisory"], "strong_redirect_suspicion")
        self.assertTrue(assessment["run_ffuf"])
        self.assertTrue(probe_vhost_http_redirect_wildcard("futurevera.thm"))

    @patch("scout_run._probe_vhost_host")
    def test_http_redirect_advisory_not_https(self, mock_probe) -> None:
        mock_probe.return_value = _mock_probe_response(302, 0, "http://other.example/")
        assessment = assess_http_vhost_value("futurevera.thm")
        self.assertIsNone(assessment["advisory"])
        self.assertFalse(probe_vhost_http_redirect_wildcard("futurevera.thm"))


if __name__ == "__main__":
    unittest.main()
