"""Minimal language helpers for custom CLI help output."""

from __future__ import annotations

import os


def toolkit_lang() -> str:
    raw = (os.environ.get("TOOLKIT_LANG") or "en").strip().lower()
    if raw == "ja" or raw.startswith("ja_") or raw.startswith("ja-"):
        return "ja"
    return "en"


def is_ja() -> bool:
    return toolkit_lang() == "ja"


def pick(en: str, ja: str) -> str:
    return ja if is_ja() else en
