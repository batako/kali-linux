"""Scout / gobuster dir wordlist resolution via catalog."""

from __future__ import annotations

import os
from typing import Optional

from wordlists.wordlists import WordlistCatalog

SELECTOR_DIRS = "dirs"
SELECTOR_DIRS_EXT = "dirs-ext"

_catalog: Optional[WordlistCatalog] = None


def get_catalog() -> WordlistCatalog:
    global _catalog
    if _catalog is None:
        _catalog = WordlistCatalog.load()
    return _catalog


def scout_selector(*, extensions: Optional[str]) -> str:
    return SELECTOR_DIRS_EXT if extensions else SELECTOR_DIRS


def default_wordlist_id(*, extensions: Optional[str]) -> str:
    selector = scout_selector(extensions=extensions)
    spec = get_catalog().selectors.get(selector)
    if spec is None:
        raise ValueError(f"catalog missing selector: {selector}")
    if spec.default:
        return spec.default
    if spec.entry_ids:
        return spec.entry_ids[0]
    raise ValueError(f"selector {selector!r} has no default or entries")


def default_wordlist_spec(*, extensions: Optional[str]) -> str:
    """Env override (id or path) or catalog default id."""
    if extensions:
        return os.environ.get("GB_DIRS_EXT_WORDLIST") or default_wordlist_id(
            extensions=extensions
        )
    return os.environ.get("GB_WORDLIST") or default_wordlist_id(extensions=None)


def resolve_scout_wordlist(
    value: Optional[str] = None,
    *,
    extensions: Optional[str] = None,
) -> str:
    """Resolve catalog id, relative path, or absolute path for gobuster -w."""
    spec = (value or "").strip() or default_wordlist_spec(extensions=extensions)
    selector = scout_selector(extensions=extensions)
    return get_catalog().resolve(spec, category=selector)
