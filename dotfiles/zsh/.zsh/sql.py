#!/usr/bin/env python3
"""Thin sqlmap wrapper for common CTF enumeration flows."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


SYSTEM_DATABASES = {"information_schema", "performance_schema", "mysql", "sys"}
INTERESTING_TABLE_KEYWORDS = (
    "users",
    "user",
    "admin",
    "admins",
    "accounts",
    "account",
    "credentials",
    "creds",
    "login",
    "logins",
    "members",
    "employees",
    "staff",
)
TOP_LEVEL_HELP = """usage:
  sql <command> (-r REQ | -u URL) [options]

commands:
  test      check SQL injection
  dbs       list databases
  tables    list tables       requires -D DB
  columns   list columns      requires -D DB -T TABLE
  dump      dump table        requires -D DB -T TABLE
  auto      test -> dbs -> tables -> interesting dump

options:
  -h, --help      show this help
  -r REQ          request file
  -u URL          target URL
  -D DB           database
  -T TABLE        table
  -C COLUMNS      columns
  --risk N        pass to sqlmap
  --level N       pass to sqlmap
  --proxy URL     pass to sqlmap
  --cookie TEXT   pass to sqlmap
  --extra TEXT    extra sqlmap args
  --output-dir DIR  sqlmap output directory

examples:
  sql test -r search.req
  sql dbs -r search.req
  sql tables -r search.req -D recruit_db
  sql dump -r search.req -D recruit_db -T users
  sql auto -r search.req
"""


class SqlCliError(Exception):
    pass


def resolve_case_home() -> Path | None:
    raw = (os.environ.get("CASE_HOME") or "").strip()
    if raw:
        path = Path(raw)
        if path.is_dir():
            return path

    cwd = Path.cwd().resolve()
    parts = cwd.parts
    try:
        idx = parts.index("cases")
    except ValueError:
        return None
    if idx + 1 >= len(parts):
        return None
    return Path(*parts[: idx + 2])


def default_output_dir() -> Path | None:
    case_home = resolve_case_home()
    if case_home is None:
        return None
    return case_home / "exports" / "sqlmap"


def build_parser() -> argparse.ArgumentParser:
    epilog = """examples:
  sql test -r search.req
  sql dbs -r search.req
  sql tables -r search.req -D recruit_db
  sql columns -r search.req -D recruit_db -T users
  sql dump -r search.req -D recruit_db -T users
  sql auto -r search.req

common options:
  pass -r <request-file> or -u <url> after each subcommand
  pass --risk / --level / --proxy / --cookie / --extra through to sqlmap

required selectors:
  tables   : -D <database>
  columns  : -D <database> -T <table>
  dump     : -D <database> -T <table>
"""
    parser = argparse.ArgumentParser(
        prog="sql",
        description="Short sqlmap wrapper for common test/dbs/tables/columns/dump flows.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand", required=True, title="subcommands")

    definitions = {
        "test": "Check whether the target appears injectable.",
        "dbs": "List available databases.",
        "tables": "List tables in the selected database. Requires -D <database>.",
        "columns": "List columns in the selected table. Requires -D <database> and -T <table>.",
        "dump": "Dump rows from the selected table. Requires -D <database> and -T <table>.",
        "auto": "Run test/dbs/tables flow and dump only interesting tables.",
    }

    for name, help_text in definitions.items():
        subparser = sub.add_parser(
            name,
            help=help_text,
            description=help_text,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        add_common_arguments(subparser)
        if name in {"tables", "columns", "dump"}:
            subparser.add_argument("-D", dest="database", help="Database name (required)")
        if name in {"columns", "dump"}:
            subparser.add_argument("-T", dest="table", help="Table name (required)")
        if name == "dump":
            subparser.add_argument("-C", dest="columns", help="Column names")
    return parser


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-r", dest="request_file", help="Request file for sqlmap -r (use -r or -u)")
    parser.add_argument("-u", dest="url", help="Direct URL for sqlmap -u (use -u or -r)")
    parser.add_argument("--risk", dest="risk", help="Pass through sqlmap --risk")
    parser.add_argument("--level", dest="level", help="Pass through sqlmap --level")
    parser.add_argument("--proxy", dest="proxy", help="Pass through sqlmap --proxy")
    parser.add_argument("--cookie", dest="cookie", help="Pass through sqlmap --cookie")
    parser.add_argument("--extra", dest="extra", default="", help="Extra sqlmap arguments")
    parser.add_argument("--output-dir", dest="output_dir", help="sqlmap output directory")


def validate_args(args: argparse.Namespace) -> None:
    if not args.request_file and not args.url:
        raise SqlCliError("use -r <file> or -u <url>")
    if args.request_file and args.url:
        raise SqlCliError("use either -r or -u, not both")
    if args.request_file and not Path(args.request_file).is_file():
        raise SqlCliError(f"request file not found: {args.request_file}")
    if args.subcommand in {"tables", "columns", "dump"} and not args.database:
        raise SqlCliError(f"{args.subcommand} requires -D <database>")
    if args.subcommand in {"columns", "dump"} and not args.table:
        raise SqlCliError(f"{args.subcommand} requires -T <table>")
    if shutil.which("sqlmap") is None:
        raise SqlCliError("sqlmap not found in PATH")


def resolve_output_dir(args: argparse.Namespace) -> Path | None:
    if args.output_dir:
        return Path(args.output_dir)
    return default_output_dir()


def sqlmap_base_args(args: argparse.Namespace) -> list[str]:
    command = ["sqlmap", "--batch"]
    if args.request_file:
        command.extend(["-r", args.request_file])
    else:
        command.extend(["-u", args.url])
    database = getattr(args, "database", None)
    if database:
        command.extend(["-D", database])
    if getattr(args, "table", None):
        command.extend(["-T", args.table])
    if getattr(args, "columns", None):
        command.extend(["-C", args.columns])
    if args.risk:
        command.extend(["--risk", args.risk])
    if args.level:
        command.extend(["--level", args.level])
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    if args.cookie:
        command.extend(["--cookie", args.cookie])
    output_dir = resolve_output_dir(args)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        command.extend(["--output-dir", str(output_dir)])
    if args.extra:
        command.extend(shlex.split(args.extra))
    return command


def render_command(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def run_sqlmap(command: list[str]) -> tuple[int, list[str]]:
    print(f"[*] Running: {render_command(command)}")
    collected: list[str] = []
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="")
        collected.append(line.rstrip("\n"))
    return proc.wait(), collected


def looks_injectable(lines: list[str]) -> bool:
    text = "\n".join(lines).lower()
    if "does not seem to be injectable" in text:
        return False
    return "is vulnerable" in text or "sql injection" in text or "parameter" in text and "injectable" in text


def extract_databases(lines: list[str]) -> list[str]:
    databases: list[str] = []
    capture = False
    for raw in lines:
        line = raw.strip()
        lower = line.lower()
        if "available databases" in lower:
            capture = True
            continue
        if capture:
            match = re.match(r"^\[\*\]\s+(.+)$", line)
            if match:
                name = match.group(1).strip()
                if name:
                    databases.append(name)
                    continue
            if line.startswith("[") and not line.startswith("[*]"):
                capture = False
    return _dedupe(databases)


def extract_tables(lines: list[str]) -> list[str]:
    tables: list[str] = []
    for raw in lines:
        line = raw.strip()
        match = re.match(r"^\|\s*([A-Za-z0-9_.$-]+)\s*\|$", line)
        if match:
            value = match.group(1).strip()
            if value and value.lower() != "table":
                tables.append(value)
    return _dedupe(tables)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def print_output_summary(args: argparse.Namespace) -> None:
    out_dir = resolve_output_dir(args)
    if out_dir is not None:
        print(f"[+] Output dir: {out_dir}")


def do_test(args: argparse.Namespace) -> int:
    rc, _lines = run_sqlmap(sqlmap_base_args(args))
    print_output_summary(args)
    return rc


def do_dbs(args: argparse.Namespace) -> int:
    command = sqlmap_base_args(args) + ["--dbs"]
    rc, lines = run_sqlmap(command)
    databases = extract_databases(lines)
    if databases:
        print(f"[+] Databases: {', '.join(databases)}")
    print_output_summary(args)
    return rc


def do_tables(args: argparse.Namespace) -> int:
    command = sqlmap_base_args(args) + ["--tables"]
    rc, lines = run_sqlmap(command)
    tables = extract_tables(lines)
    if tables:
        print(f"[+] Tables in {args.database}: {', '.join(tables)}")
    print_output_summary(args)
    return rc


def do_columns(args: argparse.Namespace) -> int:
    command = sqlmap_base_args(args) + ["--columns"]
    rc, _lines = run_sqlmap(command)
    print_output_summary(args)
    return rc


def do_dump(args: argparse.Namespace) -> int:
    command = sqlmap_base_args(args) + ["--dump"]
    rc, _lines = run_sqlmap(command)
    print_output_summary(args)
    return rc


def maybe_current_php_filename(args: argparse.Namespace) -> str:
    if not args.url:
        return ""
    parsed = urlparse(args.url)
    return Path(parsed.path).name


def do_auto(args: argparse.Namespace) -> int:
    rc, lines = run_sqlmap(sqlmap_base_args(args))
    if rc != 0:
        print_output_summary(args)
        return rc
    if not looks_injectable(lines):
        print("[-] SQLi not confirmed")
        print_output_summary(args)
        return 1

    print("[+] SQLi appears confirmed")
    dbs_rc, db_lines = run_sqlmap(sqlmap_base_args(args) + ["--dbs"])
    if dbs_rc != 0:
        print_output_summary(args)
        return dbs_rc

    databases = [name for name in extract_databases(db_lines) if name.lower() not in SYSTEM_DATABASES]
    if not databases:
        print("[-] No non-system database found")
        print_output_summary(args)
        return 0

    print(f"[+] Candidate DBs: {', '.join(databases)}")
    interesting_hits: list[tuple[str, str]] = []

    for database in databases:
        table_args = argparse.Namespace(**vars(args))
        table_args.database = database
        tables_rc, table_lines = run_sqlmap(sqlmap_base_args(table_args) + ["--tables"])
        if tables_rc != 0:
            continue
        tables = extract_tables(table_lines)
        if tables:
            print(f"[+] Tables in {database}: {', '.join(tables)}")
        for table in tables:
            lower = table.lower()
            if any(keyword in lower for keyword in INTERESTING_TABLE_KEYWORDS):
                interesting_hits.append((database, table))

    if not interesting_hits:
        print("[-] No interesting table found")
        print("[*] Showing table list only")
        print_output_summary(args)
        return 0

    for database, table in interesting_hits:
        print(f"[+] Interesting table found: {database}.{table}")
        print("[*] Dumping...")
        dump_args = argparse.Namespace(**vars(args))
        dump_args.database = database
        dump_args.table = table
        dump_rc, _dump_lines = run_sqlmap(sqlmap_base_args(dump_args) + ["--dump"])
        if dump_rc != 0:
            print(f"[-] Dump failed: {database}.{table}")
    print_output_summary(args)
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv in (["-h"], ["--help"]):
        print(TOP_LEVEL_HELP, end="")
        return 0

    parser = build_parser()
    args = parser.parse_args(raw_argv)
    try:
        validate_args(args)
    except SqlCliError as exc:
        print(f"[-] sql: {exc}", file=sys.stderr)
        return 2

    handlers = {
        "test": do_test,
        "dbs": do_dbs,
        "tables": do_tables,
        "columns": do_columns,
        "dump": do_dump,
        "auto": do_auto,
    }
    try:
        return handlers[args.subcommand](args)
    except KeyboardInterrupt:
        print("\n[-] sql: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
