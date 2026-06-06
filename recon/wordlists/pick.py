"""Interactive wordlist picker (no fzf)."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Optional
from typing import TextIO

from wordlists.wordlists import CatalogEntry
from wordlists.wordlists import WordlistCatalog
from wordlists.wordlists import format_lines


InputFn = Callable[[str], str]


def _entry_meta(entry: CatalogEntry) -> str:
    parts = [format_lines(entry.lines).rjust(6)]
    if entry.speed:
        parts.append(entry.speed)
    if entry.use:
        parts.append(entry.use)
    return "  ".join(parts)


def _read_choice(prompt: str, input_fn: InputFn) -> str:
    try:
        return input_fn(prompt).strip()
    except EOFError:
        return "q"


def pick_from_selector(
    catalog: WordlistCatalog,
    selector_id: str,
    *,
    input_fn: InputFn = input,
    output: TextIO = sys.stdout,
) -> Optional[str]:
    spec = catalog.selectors.get(selector_id)
    if spec is None:
        raise ValueError(f"unknown selector: {selector_id}")

    entries = catalog.list_selector(selector_id)
    _print_selector_menu(spec.description, selector_id, entries, spec.recommended, output=output)

    choice = _read_choice("Pick [1-{}], id, or q: ".format(len(entries)), input_fn)
    if choice.lower() in ("q", "quit", ""):
        return None
    return _resolve_menu_choice(choice, entries)


def pick_browse_category(
    catalog: WordlistCatalog,
    *,
    input_fn: InputFn = input,
    output: TextIO = sys.stdout,
    page_size: int = 25,
) -> Optional[str]:
    counts: dict[str, int] = {}
    for entry in catalog.entries:
        counts[entry.category_id] = counts.get(entry.category_id, 0) + 1
    cat_ids = sorted(counts)

    output.write("\nCatalog categories (pick a group, then a wordlist id):\n\n")
    for n, cat_id in enumerate(cat_ids, 1):
        output.write(f"  {n:>3}  {cat_id:<40} {counts[cat_id]:>5} files\n")
    output.write("\n")

    choice = _read_choice("Category [1-{}], id, or q: ".format(len(cat_ids)), input_fn)
    if choice.lower() in ("q", "quit", ""):
        return None

    cat_id = _resolve_category_choice(choice, cat_ids)
    if cat_id is None:
        output.write("[-] unknown category\n", file=sys.stderr if output is sys.stdout else output)
        return None

    entries = sorted(
        (e for e in catalog.entries if e.category_id == cat_id),
        key=lambda e: e.path.lower(),
    )
    return _pick_from_entry_list(
        catalog,
        entries,
        title=f"category: {cat_id} ({len(entries)} entries)",
        input_fn=input_fn,
        output=output,
        page_size=page_size,
    )


def _print_selector_menu(
    description: str,
    selector_id: str,
    entries: list[CatalogEntry],
    recommended: Optional[str],
    *,
    output: TextIO,
) -> None:
    output.write(f"\nWordlists for {selector_id}\n")
    output.write(f"{description}\n\n")
    for n, entry in enumerate(entries, 1):
        star = "* " if entry.id == recommended else "  "
        output.write(f"{star}{n:>2}  {entry.id:<22} {_entry_meta(entry)}\n")
    if recommended:
        output.write("\n* recommended\n")
    output.write("\n")


def _pick_from_entry_list(
    catalog: WordlistCatalog,
    entries: list[CatalogEntry],
    *,
    title: str,
    input_fn: InputFn,
    output: TextIO,
    page_size: int,
) -> Optional[str]:
    if not entries:
        return None

    output.write(f"\n{title}\n\n")
    shown = entries[:page_size]
    for n, entry in enumerate(shown, 1):
        output.write(f"  {n:>3}  {entry.id:<30} {entry.path}\n")
    if len(entries) > page_size:
        output.write(
            f"\n  ... and {len(entries) - page_size} more — type catalog id directly\n"
        )
    output.write("\n")

    choice = _read_choice(
        "Pick [1-{}], id, or q: ".format(len(shown)),
        input_fn,
    )
    if choice.lower() in ("q", "quit", ""):
        return None

    picked = _resolve_menu_choice(choice, shown)
    if picked:
        return picked

    if catalog.get(choice):
        return choice
    return None


def _resolve_menu_choice(choice: str, entries: list[CatalogEntry]) -> Optional[str]:
    if not choice:
        return None
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(entries):
            return entries[idx - 1].id
        return None
    for entry in entries:
        if entry.id == choice:
            return entry.id
    return None


def _resolve_category_choice(choice: str, cat_ids: list[str]) -> Optional[str]:
    if not choice:
        return None
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(cat_ids):
            return cat_ids[idx - 1]
        return None
    if choice in cat_ids:
        return choice
    return None
