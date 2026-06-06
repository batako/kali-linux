"""CLI helpers for recon.py wordlist subcommand."""

from __future__ import annotations

import sys
from pathlib import Path

from wordlists.wordlists import WordlistCatalog
from wordlists.wordlists import format_lines


def cmd_validate(args: list[str]) -> int:
    strict_lines = "--strict-lines" in args
    catalog = WordlistCatalog.load()
    issues = catalog.validate(strict_lines=strict_lines)
    errors = [i for i in issues if i.level == "error"]
    warns = [i for i in issues if i.level == "warn"]

    for issue in issues:
        prefix = "ERROR" if issue.level == "error" else "WARN"
        print(f"[{prefix}] {issue.message}", file=sys.stderr if issue.level == "error" else sys.stdout)

    print(
        f"catalog: {catalog.catalog_path.name} "
        f"entries={len(catalog.entries)} selectors={len(catalog.selectors)}"
    )
    if errors:
        print(f"validate: FAIL ({len(errors)} error(s), {len(warns)} warn(s))")
        return 1
    print(f"validate: OK ({len(warns)} warn(s))")
    return 0


def cmd_list(args: list[str]) -> int:
    selector = None
    category = None
    show_all = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--for", "--selector"):
            selector = args[i + 1]
            i += 2
        elif a in ("--category", "-c"):
            category = args[i + 1]
            i += 2
        elif a == "--all-categories":
            show_all = True
            i += 1
        else:
            print(f"unknown list option: {a}", file=sys.stderr)
            return 1

    catalog = WordlistCatalog.load()

    if show_all:
        counts: dict[str, int] = {}
        for entry in catalog.entries:
            counts[entry.category_id] = counts.get(entry.category_id, 0) + 1
        for cat_id in sorted(counts):
            print(f"{cat_id}\t{counts[cat_id]}")
        return 0

    if selector:
        spec = catalog.selectors.get(selector)
        if spec is None:
            print(f"unknown selector: {selector}", file=sys.stderr)
            return 1
        print(f"# selector: {selector} — {spec.description}")
        entries = catalog.list_selector(selector)
        for n, entry in enumerate(entries, 1):
            star = "* " if entry.id == spec.recommended else "  "
            meta = _entry_line(entry)
            print(f"{star}{n:>2}  {entry.id:<22} {meta}")
        return 0

    if category:
        matches = [e for e in catalog.entries if e.category_id == category]
        if not matches:
            print(f"unknown or empty category: {category}", file=sys.stderr)
            return 1
        print(f"# category: {category} ({len(matches)} entries)")
        for entry in sorted(matches, key=lambda e: e.path.lower()):
            print(f"  {entry.id}\t{entry.path}\t{_entry_line(entry)}")
        return 0

    print("usage: recon.py wordlist list --for <selector>", file=sys.stderr)
    print("       recon.py wordlist list --category <id>", file=sys.stderr)
    print("       recon.py wordlist list --all-categories", file=sys.stderr)
    print(f"selectors: {', '.join(sorted(catalog.selectors))}", file=sys.stderr)
    return 1


def cmd_resolve(args: list[str]) -> int:
    if not args:
        print("usage: recon.py wordlist resolve <id|path> [--category dirs-ext]", file=sys.stderr)
        return 1
    value = args[0]
    category = None
    if len(args) >= 3 and args[1] == "--category":
        category = args[2]
    catalog = WordlistCatalog.load()
    try:
        path = catalog.resolve(value, category=category)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(path)
    return 0


def cmd_stats(_args: list[str]) -> int:
    catalog = WordlistCatalog.load()
    cat_counts: dict[str, int] = {}
    for entry in catalog.entries:
        cat_counts[entry.category_id] = cat_counts.get(entry.category_id, 0) + 1
    print(f"root: {catalog.root}")
    print(f"entries: {len(catalog.entries)}")
    print(f"categories: {len(cat_counts)}")
    print(f"selectors: {', '.join(sorted(catalog.selectors))}")
    return 0


def _entry_line(entry) -> str:
    parts = [format_lines(entry.lines).rjust(6)]
    if entry.speed:
        parts.append(entry.speed)
    if entry.use:
        parts.append(entry.use)
    return "  ".join(parts)


def run_wordlist_cli(argv: list[str]) -> int:
    if not argv:
        print(
            "usage: recon.py wordlist <validate|list|resolve|stats> ...",
            file=sys.stderr,
        )
        return 1
    sub = argv[0]
    rest = argv[1:]
    if sub == "validate":
        return cmd_validate(rest)
    if sub == "list":
        return cmd_list(rest)
    if sub == "resolve":
        return cmd_resolve(rest)
    if sub == "stats":
        return cmd_stats(rest)
    print(f"unknown wordlist command: {sub}", file=sys.stderr)
    return 1
