"""Scout / gobuster dir wordlist resolution via catalog."""

from __future__ import annotations

import sys
from typing import Callable
from typing import Optional

from wordlists.wordlists import WordlistCatalog

SELECTOR_DIRS = "dirs"
SELECTOR_DIRS_EXT = "dirs-ext"
DEFAULT_DIRS_MULTI_PRESET = "standard"
DEFAULT_DIRS_MULTI_TIER = "standard"

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


def _done_wordlist_paths(ip: str, url: str) -> set[str]:
    from db import list_scout_jobs
    from url_util import canonicalize_url

    canon = canonicalize_url((url or "").strip())
    done: set[str] = set()
    for status in ("running", "done"):
        for row in list_scout_jobs(ip, kind="dirs", status=status, limit=500):
            row_url = canonicalize_url((row["url"] or "").strip())
            if row_url != canon:
                continue
            wl = (row["wordlist"] or "").strip()
            if wl:
                done.add(wl)
    return done


def resolve_dirs_multi_wordlist_ids(
    *,
    preset: str = DEFAULT_DIRS_MULTI_PRESET,
    wordlist_ids: Optional[list[str]] = None,
    extensions: Optional[str] = None,
    preset_from_flag: bool = False,
    preset_is_next: bool = False,
    ip: Optional[str] = None,
    url: Optional[str] = None,
    warn: Optional[Callable[[str], None]] = None,
) -> tuple[list[str], str]:
    """Resolve catalog ids for scout -ds.

    Returns (ids, label) where label describes the tier/source for logging.
    """
    catalog = get_catalog()
    ext = bool(extensions)

    if wordlist_ids:
        return list(wordlist_ids), "custom"

    raw_preset = (preset or DEFAULT_DIRS_MULTI_PRESET).strip().lower()

    if preset_is_next or raw_preset == "next":
        if not ip or not url:
            raise ValueError("-p next requires a target URL (pass path or ip with web target)")
        done = _done_wordlist_paths(ip, url)
        tier, label, pending = catalog.next_tier_adds(
            extensions=ext,
            done_wordlist_paths=done,
        )
        if not pending:
            return [], "done"
        return list(pending), f"next/{tier}"

    if preset_from_flag:
        hint = catalog.preset_deprecated_hint(raw_preset, extensions=ext)
        if hint and warn:
            warn(f"[!] {hint} — use -p {catalog.normalize_preset_id(raw_preset, extensions=ext)}")
        tier = catalog.normalize_preset_id(raw_preset, extensions=ext)
        ids = list(catalog.cumulative_preset_ids(tier, extensions=ext))
        return ids, tier

    # Default -ds: standard tier cumulative
    tier = DEFAULT_DIRS_MULTI_TIER
    ids = list(catalog.cumulative_preset_ids(tier, extensions=ext))
    return ids, tier


def resolve_dirs_multi_wordlists(
    *,
    preset: str = DEFAULT_DIRS_MULTI_PRESET,
    wordlist_ids: Optional[list[str]] = None,
    extensions: Optional[str] = None,
    preset_from_flag: bool = False,
    preset_is_next: bool = False,
    ip: Optional[str] = None,
    url: Optional[str] = None,
    warn: Optional[Callable[[str], None]] = None,
) -> list[str]:
    """Resolve parallel dir wordlist paths for scout -ds."""
    ids, _label = resolve_dirs_multi_wordlist_ids(
        preset=preset,
        wordlist_ids=wordlist_ids,
        extensions=extensions,
        preset_from_flag=preset_from_flag,
        preset_is_next=preset_is_next,
        ip=ip,
        url=url,
        warn=warn,
    )
    catalog = get_catalog()
    return [catalog.resolve(wid) for wid in ids]
