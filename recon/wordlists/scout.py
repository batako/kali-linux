"""Scout / gobuster dir wordlist resolution via catalog."""

from __future__ import annotations

import sys
from typing import Optional

from wordlists.wordlists import WordlistCatalog

SELECTOR_DIRS = "dirs"
SELECTOR_DIRS_EXT = "dirs-ext"
DEFAULT_DIRS_MULTI_PRESET = "ctf"

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
    """Catalog default id for scout -d when -w is omitted."""
    return default_wordlist_id(extensions=extensions)


def _pick_mode(value: str) -> Optional[str]:
    v = (value or "").strip()
    if v == "pick":
        return "context"
    if v == "browse":
        return "browse"
    return None


def _interactive_pick(
    *,
    extensions: Optional[str],
    mode: str,
) -> str:
    from wordlists.pick import pick_browse_category
    from wordlists.pick import pick_from_selector

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("wordlist pick requires a TTY (use -w <catalog-id>)")

    catalog = get_catalog()
    if mode == "browse":
        picked = pick_browse_category(catalog)
    else:
        picked = pick_from_selector(catalog, scout_selector(extensions=extensions))
    if not picked:
        raise ValueError("cancelled")
    return picked


def resolve_scout_wordlist(
    value: Optional[str] = None,
    *,
    extensions: Optional[str] = None,
    from_flag: bool = False,
) -> str:
    """Resolve catalog id, relative path, or absolute path for gobuster -w.

    - No -w (from_flag=False): catalog/env default.
    - -w with id/path: resolve that entry.
    - -w alone or -w browse: interactive picker.
    """
    spec = (value or "").strip()
    pick_mode = _pick_mode(spec) if spec else None

    if from_flag and (not spec or pick_mode):
        mode = pick_mode or "context"
        spec = _interactive_pick(extensions=extensions, mode=mode)
    elif pick_mode:
        spec = _interactive_pick(extensions=extensions, mode=pick_mode)
    elif not spec:
        spec = default_wordlist_spec(extensions=extensions)

    selector = scout_selector(extensions=extensions)
    return get_catalog().resolve(spec, category=selector)


def resolve_dirs_multi_wordlists(
    *,
    preset: str = DEFAULT_DIRS_MULTI_PRESET,
    wordlist_ids: Optional[list[str]] = None,
    extensions: Optional[str] = None,
    preset_from_flag: bool = False,
) -> list[str]:
    """Resolve parallel dir wordlists for scout -ds.

    - Explicit -w ids: those entries only.
    - -x set, no -p: all dirs-ext selector entries (same pool as ``-d -x -w`` picker).
    - -x set + -p: dirs_ext_multi_presets subset (fast/deep/ctf).
    - -p set (no -x): dirs_multi_presets subset (fast/deep/ctf).
    - Default (no -x, no -p): all dirs selector entries (same pool as ``-d -w`` picker).
    """
    catalog = get_catalog()
    if wordlist_ids:
        ids = wordlist_ids
    elif extensions:
        if preset_from_flag:
            entries = catalog.list_dirs_ext_multi_preset(preset)
        else:
            entries = catalog.list_selector(SELECTOR_DIRS_EXT)
        ids = [e.id for e in entries]
    elif preset_from_flag:
        entries = catalog.list_dirs_multi_preset(preset)
        ids = [e.id for e in entries]
    else:
        entries = catalog.list_selector(SELECTOR_DIRS)
        ids = [e.id for e in entries]
    return [catalog.resolve(wid) for wid in ids]
