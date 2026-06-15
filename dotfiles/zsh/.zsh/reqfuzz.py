#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import re
import shlex
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

import http_client as requests
from http_client import RequestException


USAGE = """usage:
  reqfuzz [options] <url> <param> <start> <end>

options:
  -X GET|POST          request method (default: GET)
  -d <data>            POST body template (use {value}; default: <param>={value})
  -H <header>          extra header (repeatable)
  -k                   ignore TLS verification
  -s                   show only differing responses
  -o <file>            write results to file
  --deep               include words/lines/hash/note and save response bodies
  -n                   dry-run (print commands only)
  -h                   show this help

examples:
  reqfuzz http://$IP/th1s_1s_h1dd3n/ secret 0 99
  reqfuzz -k http://$IP/app/ secret 0 99
  reqfuzz -X POST -d 'secret={value}&submit=1' http://$IP/app/ secret 0 99

alias:
  param-fuzz -> reqfuzz
"""

CONNECT_TIMEOUT = float(os.environ.get("REQFUZZ_CONNECT_TIMEOUT", "10"))
MAX_TIME = float(os.environ.get("REQFUZZ_MAX_TIME", "20"))
DEBUG = os.environ.get("REQFUZZ_DEBUG", "0") == "1"


@dataclass(slots=True)
class Config:
    method: str = "GET"
    post_template: str = ""
    dry_run: bool = False
    only_diff: bool = False
    insecure: bool = False
    output_file: str = ""
    deep: bool = False
    headers: list[str] | None = None
    base_url: str = ""
    param: str = ""
    start: int = 0
    end: int = 0
    tmpdir: Path | None = None


@dataclass(slots=True)
class ResponseRecord:
    value: int
    status: str
    bytes: int
    time_total: float
    body_path: Path | None = None
    body_bytes: bytes | None = None
    error: str | None = None

    @property
    def key(self) -> tuple[str, int]:
        return (self.status, self.bytes)


_thread_local = threading.local()
_debug_lock = threading.Lock()


def emit(line: str, sink: list[str], output_path: Path | None) -> None:
    sink.append(line)
    print(line)
    if output_path is not None:
        with output_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def debug_print(*lines: str) -> None:
    if not DEBUG:
        return
    with _debug_lock:
        for line in lines:
            print(line, file=sys.stderr)


def build_url(base_url: str, param: str, value: int) -> str:
    # TODO: Existing query parameters are not replaced.
    # Future versions should support parameter overwrite.
    parsed = urlsplit(base_url)
    query = parsed.query
    addition = f"{param}={value}"
    if query:
        query = f"{query}&{addition}"
    else:
        query = addition
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def render_curl(config: Config, url: str, body: str, out_target: str) -> str:
    def fmt_number(value: float) -> str:
        return str(int(value)) if value.is_integer() else str(value)

    parts = [
        "curl",
        "-sS",
        "--connect-timeout",
        fmt_number(CONNECT_TIMEOUT),
        "--max-time",
        fmt_number(MAX_TIME),
    ]
    if config.insecure:
        parts.append("-k")
    for header in config.headers or []:
        parts.extend(["-H", header])
    parts.extend(["-o", out_target, "-w", "%{http_code}\\t%{size_download}\\t%{time_total}"])
    if config.method == "POST":
        parts.extend(["-X", "POST", "-d", body, config.base_url])
    else:
        parts.append(url)
    return " ".join(shlex.quote(part) for part in parts)


def get_session(config: Config) -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        _thread_local.session = session
    session.verify = not config.insecure
    session.headers.clear()
    for header in config.headers or []:
        if ":" in header:
            name, value = header.split(":", 1)
            session.headers[name.strip()] = value.strip()
        else:
            debug_print(f"[debug] invalid header ignored: {header}")
    if config.method == "POST" and "Content-Type" not in session.headers:
        session.headers["Content-Type"] = "application/x-www-form-urlencoded"
    return session


def body_summary(body_path: Path, needle: str) -> tuple[int, int, int, str, str]:
    raw_bytes = body_path.read_bytes()
    raw_text = raw_bytes.decode(errors="replace")
    normalized = raw_text.replace(needle, "<FUZZ>") if needle else raw_text
    bytes_count = len(raw_bytes)
    words = len(raw_text.split())
    lines = raw_text.count("\n")
    hash_value = hashlib.sha1(normalized.encode()).hexdigest()[:8]
    note = ""
    title_match = re.search(r"<title[^>]*>([^<]*)</title>", raw_text, re.I | re.S)
    if title_match:
        note = title_match.group(1).strip()
    if not note:
        stripped = re.sub(r"<script[^>]*>.*?</script>", "", raw_text, flags=re.I | re.S)
        stripped = re.sub(r"<style[^>]*>.*?</style>", "", stripped, flags=re.I | re.S)
        stripped = re.sub(r"<[^>]+>", " ", stripped)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        note = stripped[:64]
    if not note:
        note = "(empty)"
    return bytes_count, words, lines, hash_value, note


def parse_args(argv: list[str]) -> Config:
    config = Config(headers=[])
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == "-X":
            idx += 1
            if idx >= len(argv):
                raise ValueError("-X requires GET or POST")
            config.method = argv[idx].upper()
        elif arg == "-d":
            idx += 1
            if idx >= len(argv):
                raise ValueError("-d requires a body template")
            config.post_template = argv[idx]
        elif arg == "-H":
            idx += 1
            if idx >= len(argv):
                raise ValueError("-H requires a header")
            config.headers.append(argv[idx])
        elif arg == "-k":
            config.insecure = True
        elif arg == "-s":
            config.only_diff = True
        elif arg == "-o":
            idx += 1
            if idx >= len(argv):
                raise ValueError("-o requires a file path")
            config.output_file = argv[idx]
        elif arg == "--deep":
            config.deep = True
        elif arg == "-n":
            config.dry_run = True
        elif arg in ("-h", "--help"):
            print(USAGE, end="")
            raise SystemExit(0)
        elif arg.startswith("-"):
            raise ValueError(f"unknown option: {arg}")
        else:
            break
        idx += 1

    rest = argv[idx:]
    if len(rest) < 4:
        raise ValueError("missing arguments")

    config.base_url = rest[0]
    config.param = rest[1]
    try:
        config.start = int(rest[2])
        config.end = int(rest[3])
    except ValueError as exc:
        raise ValueError("start/end must be integers") from exc
    if config.start > config.end:
        raise ValueError("start must be <= end")

    if config.method not in ("GET", "POST"):
        raise ValueError("-X must be GET or POST")

    if config.method == "POST" and not config.post_template:
        config.post_template = f"{config.param}={{value}}"
    return config


def dry_run(config: Config) -> None:
    baseline_url = build_url(config.base_url, config.param, config.start)
    print(f"[*] dry-run: baseline {config.method} {baseline_url}")
    for value in range(config.start, config.end + 1):
        if config.method == "GET":
            print(f"[*] GET  {build_url(config.base_url, config.param, value)}")
        else:
            body = config.post_template.replace("{value}", str(value))
            print(f"[*] POST {config.base_url}  body={body}")


def request_once(config: Config, value: int) -> ResponseRecord:
    session = get_session(config)
    url = build_url(config.base_url, config.param, value)
    body = config.post_template.replace("{value}", str(value))
    kwargs = {
        "method": config.method,
        "timeout": (CONNECT_TIMEOUT, MAX_TIME),
        "stream": True,
        "allow_redirects": False,
    }
    if config.method == "GET":
        kwargs["url"] = url
        kwargs["data"] = None
    else:
        kwargs["url"] = config.base_url
        kwargs["data"] = body

    if config.deep and config.tmpdir is not None:
        out_target = str(config.tmpdir / f"body.{value}")
    else:
        out_target = "/dev/null"
    debug_print(
        f"[debug] value={value}",
        f"[debug] method={config.method}",
        f"[debug] url={url if config.method == 'GET' else config.base_url}",
        f"[debug] curl={render_curl(config, url, body, out_target)}",
    )

    started = time.perf_counter()
    body_path: Path | None = None
    status = "000"
    bytes_count = 0
    error: str | None = None
    response = None
    try:
        response = session.request(**kwargs)
        status = str(response.status_code)
        if config.deep and config.tmpdir is not None:
            body_path = config.tmpdir / f"body.{value}"
            with body_path.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        fh.write(chunk)
        else:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    bytes_count += len(chunk)
        response.close()
    except (RequestException, OSError) as exc:
        error = str(exc)
        status = "000"
        bytes_count = 0
    finally:
        if response is not None:
            response.close()
    time_total = time.perf_counter() - started
    if config.deep and body_path is not None:
        bytes_count = body_path.stat().st_size
    debug_print(f"[debug] time_total={time_total:.6f}")
    if error:
        debug_print(f"[debug] error={error}")
    return ResponseRecord(value=value, status=status, bytes=bytes_count, time_total=time_total, body_path=body_path, error=error)


def format_row(config: Config, record: ResponseRecord, summary: tuple[int, int, int, str, str] | None = None) -> str:
    if config.deep:
        if summary is None:
            if record.body_path is None:
                summary = (0, 0, 0, "ERR", "(no response)")
            else:
                summary = body_summary(record.body_path, str(record.value))
        bytes_count, words, lines, hash_value, note = summary
        return f"{record.value:<8} {record.status:<6} {bytes_count:<7} {words:<7} {lines:<7} {hash_value:<8} {note}"
    return f"{record.value:<8} {record.status:<6} {record.bytes:<7}"


def most_common_key(records: Iterable[ResponseRecord]) -> tuple[str, int]:
    counter = Counter(record.key for record in records)
    if not counter:
        return ("", 0)
    first_index: dict[tuple[str, int], int] = {}
    for index, record in enumerate(records):
        first_index.setdefault(record.key, index)
    best_key = None
    best_count = -1
    best_seen = 10**9
    for key, count in counter.items():
        seen = first_index[key]
        if count > best_count or (count == best_count and seen < best_seen):
            best_key = key
            best_count = count
            best_seen = seen
    assert best_key is not None
    return best_key


def run(config: Config) -> int:
    output_path = Path(config.output_file) if config.output_file else None
    if output_path is not None:
        output_path.write_text("", encoding="utf-8")

    if config.dry_run:
        dry_run(config)
        return 0

    values = list(range(config.start, config.end + 1))
    max_workers = min(8, len(values)) or 1
    # TODO:
    # http_client.Session currently does not reuse TCP connections.
    # If higher performance is needed, replace http_client with requests.Session
    # or implement connection pooling / Keep-Alive.
    tmpdir: Path | None = None
    if config.deep:
        tmpdir = Path(tempfile.mkdtemp(prefix="reqfuzz.", dir=os.environ.get("TMPDIR", "/tmp")))
        config.tmpdir = tmpdir

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            records = list(executor.map(lambda value: request_once(config, value), values))

        lines: list[str] = []
        if config.deep:
            header = "VALUE    STATUS BYTES   WORDS   LINES   HASH     NOTE"
        else:
            header = "VALUE    STATUS BYTES"
        lines.append(header)

        if config.only_diff:
            skip_key = most_common_key(records)
            for record in records:
                if record.key == skip_key:
                    continue
                if config.deep and record.body_path is not None:
                    summary = body_summary(record.body_path, str(record.value))
                elif config.deep:
                    summary = (0, 0, 0, "ERR", "(no response)")
                else:
                    summary = None
                lines.append(format_row(config, record, summary))
        else:
            for record in records:
                summary = None
                if config.deep and record.body_path is not None:
                    summary = body_summary(record.body_path, str(record.value))
                elif config.deep:
                    summary = (0, 0, 0, "ERR", "(no response)")
                lines.append(format_row(config, record, summary))

        for line in lines:
            print(line)
        if output_path is not None:
            output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0
    finally:
        if tmpdir is not None:
            for path in tmpdir.glob("body.*"):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            try:
                tmpdir.rmdir()
            except OSError:
                pass


def main(argv: list[str]) -> int:
    try:
        config = parse_args(argv)
    except ValueError as exc:
        print(f"[-] reqfuzz: {exc}", file=sys.stderr)
        print(USAGE, end="")
        return 1
    return run(config)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
