#!/usr/bin/env python3
"""Tests for ffuf POST cred import."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RECON = Path(__file__).resolve().parents[1]
if str(RECON) not in sys.path:
    sys.path.insert(0, str(RECON))

from creds import import_ffuf_post_json


class CredsFfufTest(unittest.TestCase):
    def test_import_ffuf_post_json(self) -> None:
        payload = {
            "results": [
                {"input": {"FUZZ": "secret123"}, "status": 302},
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(payload, f)
            path = f.name
        try:
            rows = import_ffuf_post_json(path, ip="10.0.0.1", username="admin")
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "admin")
        self.assertEqual(rows[0]["password"], "secret123")


if __name__ == "__main__":
    unittest.main()
