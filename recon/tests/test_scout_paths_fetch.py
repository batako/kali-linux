#!/usr/bin/env python3
"""Tests for scout -rtf paths mirror helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from scout_paths_fetch import _extract_links
from scout_paths_fetch import is_image_url
from scout_paths_fetch import is_internal_url
from scout_paths_fetch import local_rel_path
from scout_paths_fetch import origin_for_url
from scout_paths_fetch import site_path_from_url
from url_util import canonicalize_url


class ScoutPathsFetchTest(unittest.TestCase):
    def test_origin_for_url_longest_prefix(self) -> None:
        origins = [
            "http://10.0.0.1/",
            "http://10.0.0.1/hidden/",
        ]
        self.assertEqual(
            origin_for_url("http://10.0.0.1/hidden/index.html", origins),
            "http://10.0.0.1/hidden/",
        )
        self.assertEqual(
            origin_for_url("http://10.0.0.1/admin/", origins),
            "http://10.0.0.1/",
        )

    def test_site_path_from_scan_base(self) -> None:
        origin = "http://10.0.0.1/hidden/"
        url = "http://10.0.0.1/hidden/index.html"
        self.assertEqual(site_path_from_url(url, origin), "/index.html")

    def test_internal_host(self) -> None:
        hosts = {"10.0.0.1"}
        self.assertTrue(
            is_internal_url("http://10.0.0.1:65524/x", target_ip="10.0.0.1", internal_hosts=hosts)
        )
        self.assertFalse(
            is_internal_url(
                "http://cdn.example.com/a.png",
                target_ip="10.0.0.1",
                internal_hosts=hosts,
            )
        )

    def test_is_image_url(self) -> None:
        self.assertTrue(is_image_url("http://cdn.example.com/a.png"))
        self.assertFalse(is_image_url("http://cdn.example.com/page"))

    def test_local_rel_path(self) -> None:
        self.assertEqual(
            local_rel_path("http://10.0.0.1/hidden/index.html", external=False),
            "hidden/index.html",
        )
        self.assertEqual(
            local_rel_path("http://10.0.0.1/", external=False),
            "index.html",
        )

    def test_extract_links_internal_and_external_img(self) -> None:
        html = """
        <html><body>
        <a href="/other/page.html">x</a>
        <a href="https://evil.example/secret">ext</a>
        <img src="/img/local.png">
        <img src="https://cdn.example/logo.jpg">
        </body></html>
        """
        hrefs, imgs = _extract_links("http://10.0.0.1/hidden/index.html", html)
        self.assertIn("http://10.0.0.1/other/page.html", map(canonicalize_url, hrefs))
        self.assertIn(
            "https://cdn.example/logo.jpg",
            map(canonicalize_url, imgs),
        )

    def test_dedupe_canonical_url(self) -> None:
        a = canonicalize_url("http://10.0.0.1:80/hidden/index.html")
        b = canonicalize_url("http://10.0.0.1/hidden/index.html")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
