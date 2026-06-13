"""Fetch PATHS tree (-rt) into a local mirror + sitemap with link crawl."""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
from collections import deque
from dataclasses import asdict
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import urljoin
from urllib.parse import urlparse
from urllib.request import Request
from urllib.request import urlopen

from case_scope import looks_like_ipv4
from scout_run import _fetch_paths_report_state
from scout_run import _looks_like_file
from scout_run import _merge_job_findings
from scout_run import _paths_group_origin
from scout_run import _paths_report_groups
from scout_run import _paths_tree_insert
from scout_run import _paths_tree_lines
from scout_run import _url_host_slug
from url_util import canonicalize_url
from url_util import dirs_origin_url

_IMAGE_EXTS = frozenset(
    {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif"}
)
_SKIP_LINK_PREFIXES = ("mailto:", "javascript:", "tel:", "data:")
_FETCH_TIMEOUT = int(os.environ.get("SCOUT_FETCH_TIMEOUT", "30"))
_MAX_REDIRECTS = int(os.environ.get("SCOUT_FETCH_MAX_REDIRECTS", "5"))
_MAX_CRAWL = int(os.environ.get("SCOUT_FETCH_MAX_URLS", "500"))

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


@dataclass
class MirrorEntry:
    url: str
    path: str
    origin: str
    status: Optional[int] = None
    redirect_to: Optional[str] = None
    local: Optional[str] = None
    source: str = "paths"
    external: bool = False
    fetched: bool = False
    error: Optional[str] = None


@dataclass
class _FetchResult:
    body: bytes
    final_url: str
    status: int
    content_type: str


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.imgs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = dict(attrs)
        if tag == "a" and attr.get("href"):
            self.hrefs.append(attr["href"].strip())
        elif tag == "img" and attr.get("src"):
            self.imgs.append(attr["src"].strip())


def _case_exports_dir() -> str:
    case_home = os.environ.get("CASE_HOME")
    if case_home:
        root = Path(case_home) / "exports"
        root.mkdir(parents=True, exist_ok=True)
        return str(root)
    if os.environ.get("CASE_LOOSE") == "1":
        base = Path(os.environ.get("CASE_ROOT", "/workspace/cases")) / "_unscoped" / "exports"
        base.mkdir(parents=True, exist_ok=True)
        return str(base)
    raise RuntimeError("case not set — cs <name> first (or export CASE_LOOSE=1)")


def _origin_mirror_root(exports: Path, origin: str) -> Path:
    slug = _url_host_slug(origin.rstrip("/") or origin)
    root = exports / "web_mirror" / slug
    root.mkdir(parents=True, exist_ok=True)
    return root


def _external_mirror_root(exports: Path, url: str) -> Path:
    parsed = urlparse(url)
    host = (parsed.hostname or "unknown").replace(":", "_")
    root = exports / "web_mirror" / "_external" / host
    root.mkdir(parents=True, exist_ok=True)
    return root


def is_image_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    base = path.rsplit("/", 1)[-1]
    if "." not in base:
        return False
    ext = "." + base.rsplit(".", 1)[-1]
    return ext in _IMAGE_EXTS


def is_internal_url(url: str, *, target_ip: str, internal_hosts: set[str]) -> bool:
    host = urlparse(url).hostname
    if not host:
        return True
    if host == target_ip:
        return True
    return host in internal_hosts


def origin_for_url(url: str, origins: list[str]) -> Optional[str]:
    canon = canonicalize_url(url)
    best: Optional[str] = None
    best_len = -1
    for origin in origins:
        o = canonicalize_url(origin)
        if canon == o or canon.startswith(o):
            if len(o) > best_len:
                best = origin
                best_len = len(o)
    return best


def site_path_from_url(url: str, origin: str) -> str:
    parsed = urlparse(canonicalize_url(url))
    origin_parsed = urlparse(canonicalize_url(origin))
    path = parsed.path or "/"
    base = origin_parsed.path or "/"
    if base != "/" and path.startswith(base):
        path = path[len(base.rstrip("/")) :] or "/"
    if _looks_like_file(path):
        return path.rstrip("/") or "/"
    if not path.endswith("/"):
        path = f"{path}/"
    return path


def local_rel_path(url: str, *, external: bool) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path.endswith("/"):
        path = f"{path}index.html"
    path = path.lstrip("/")
    if external:
        if parsed.query:
            safe_q = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.query)[:40]
            stem = Path(path)
            path = str(stem.parent / f"{stem.stem}_{safe_q}{stem.suffix}")
    return path or "index.html"


def _skip_href(href: str) -> bool:
    h = (href or "").strip()
    if not h or h.startswith("#"):
        return True
    low = h.lower()
    return any(low.startswith(p) for p in _SKIP_LINK_PREFIXES)


def _http_fetch(url: str, *, method: str = "GET") -> _FetchResult:
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        req = Request(
            current,
            method=method,
            headers={"User-Agent": "scout-rtf/1.0"},
        )
        try:
            with urlopen(req, timeout=_FETCH_TIMEOUT, context=_SSL_CTX) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                headers = resp.headers
                if status in (301, 302, 303, 307, 308) and method == "GET":
                    loc = headers.get("Location")
                    if loc:
                        current = urljoin(current, loc)
                        continue
                body = resp.read() if method == "GET" else b""
                ctype = (headers.get_content_type() or "").split(";")[0].strip()
                return _FetchResult(
                    body=body,
                    final_url=canonicalize_url(current),
                    status=int(status),
                    content_type=ctype,
                )
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                loc = exc.headers.get("Location")
                if loc:
                    current = urljoin(current, loc)
                    continue
            raise
    raise URLError(f"too many redirects: {url}")


def resolve_redirect(url: str, origins: list[str]) -> tuple[str, Optional[str]]:
    """HEAD/GET to learn redirect target for a 301 dir path."""
    try:
        try:
            result = _http_fetch(url, method="HEAD")
        except (HTTPError, URLError):
            result = _http_fetch(url, method="GET")
        origin = origin_for_url(result.final_url, origins) or url
        target_path = site_path_from_url(result.final_url, origin)
        if canonicalize_url(result.final_url) != canonicalize_url(url):
            return result.final_url, target_path
        return result.final_url, None
    except (HTTPError, URLError):
        return url, None


def _collect_path_seeds(ip: str) -> tuple[list[str], list[tuple[str, list]], set[str]]:
    rows, running = _fetch_paths_report_state(ip)
    if running:
        print("[!] dirs jobs still running — seeds may be incomplete", file=sys.stderr)
    groups = _paths_report_groups(rows)
    origins = [_paths_group_origin(origin_rows) for _, origin_rows in groups]
    internal_hosts = {urlparse(o).hostname for o in origins if urlparse(o).hostname}
    internal_hosts.add(ip)
    return origins, groups, internal_hosts


def _build_seed_entries(
    groups: list[tuple[str, list]],
) -> dict[str, MirrorEntry]:
    """PATHS findings → canonical URL map (200 files + 301 dirs with redirect)."""
    entries: dict[str, MirrorEntry] = {}

    def add_entry(
        url: str,
        *,
        origin: str,
        path: str,
        status: Optional[int],
        source: str,
        redirect_to: Optional[str] = None,
        external: bool = False,
    ) -> None:
        canon = canonicalize_url(url)
        prev = entries.get(canon)
        entry = MirrorEntry(
            url=canon,
            path=path,
            origin=origin,
            status=status,
            redirect_to=redirect_to,
            source=source,
            external=external,
        )
        if prev is None or (entry.status == 200 and prev.status != 200):
            entries[canon] = entry

    for label, origin_rows in groups:
        base_origin = _paths_group_origin(origin_rows)
        findings = _merge_job_findings(origin_rows)
        for path, status in findings:
            if status not in (200, 301):
                continue
            full = urljoin(base_origin, path.lstrip("/"))
            full = canonicalize_url(full)
            if status == 200:
                if not _looks_like_file(path):
                    continue
                add_entry(
                    full,
                    origin=label,
                    path=path if path.startswith("/") else f"/{path}",
                    status=200,
                    source="paths",
                )
            elif status == 301:
                dir_path = path if path.startswith("/") else f"/{path}"
                if _looks_like_file(dir_path):
                    continue
                redirect_url, redirect_path = resolve_redirect(
                    full, origins
                )
                add_entry(
                    full,
                    origin=label,
                    path=dir_path,
                    status=301,
                    source="paths",
                    redirect_to=redirect_path,
                )
                if redirect_url and redirect_path and _looks_like_file(redirect_path):
                    add_entry(
                        redirect_url,
                        origin=label,
                        path=redirect_path,
                        status=200,
                        source="redirect",
                    )

    return entries


def _extract_links(base_url: str, html: str) -> tuple[list[str], list[str]]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        return [], []
    hrefs = [urljoin(base_url, h) for h in parser.hrefs if not _skip_href(h)]
    imgs = [urljoin(base_url, s) for s in parser.imgs if s.strip()]
    return hrefs, imgs


def _enqueue_crawl_links(
    entries: dict[str, MirrorEntry],
    *,
    base_url: str,
    html: str,
    target_ip: str,
    internal_hosts: set[str],
    origins: list[str],
) -> list[str]:
    hrefs, imgs = _extract_links(base_url, html)
    new_urls: list[str] = []

    for href in hrefs:
        canon = canonicalize_url(href)
        if canon in entries:
            continue
        parsed = urlparse(canon)
        if parsed.scheme not in ("http", "https"):
            continue
        if not is_internal_url(canon, target_ip=target_ip, internal_hosts=internal_hosts):
            continue
        origin = origin_for_url(canon, origins)
        if not origin:
            continue
        path = site_path_from_url(canon, origin)
        entries[canon] = MirrorEntry(
            url=canon,
            path=path,
            origin=origin,
            source="crawl",
        )
        new_urls.append(canon)

    for src in imgs:
        canon = canonicalize_url(src)
        if canon in entries:
            continue
        parsed = urlparse(canon)
        if parsed.scheme not in ("http", "https"):
            continue
        if is_internal_url(canon, target_ip=target_ip, internal_hosts=internal_hosts):
            origin = origin_for_url(canon, origins)
            if not origin:
                continue
            path = site_path_from_url(canon, origin)
            entries[canon] = MirrorEntry(
                url=canon,
                path=path,
                origin=origin,
                source="crawl",
            )
            new_urls.append(canon)
        elif is_image_url(canon):
            entries[canon] = MirrorEntry(
                url=canon,
                path=urlparse(canon).path or "/",
                origin="_external",
                source="crawl",
                external=True,
            )
            new_urls.append(canon)

    return new_urls


def _write_bytes(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def _fetch_all(
    entries: dict[str, MirrorEntry],
    *,
    exports: Path,
    target_ip: str,
    internal_hosts: set[str],
    origins: list[str],
    dry_run: bool,
) -> None:
    queue: deque[str] = deque()
    queued: set[str] = set()
    downloaded: set[str] = set()

    def schedule(url: str) -> None:
        canon = canonicalize_url(url)
        entry = entries.get(canon)
        if entry is None or entry.status == 301:
            return
        if canon in queued or canon in downloaded:
            return
        queued.add(canon)
        queue.append(canon)

    for url, entry in entries.items():
        if entry.status != 301:
            schedule(url)

    fetched_count = 0

    while queue and fetched_count < _MAX_CRAWL:
        canon = queue.popleft()
        queued.discard(canon)
        if canon in downloaded:
            continue
        downloaded.add(canon)

        entry = entries.get(canon)
        if entry is None or entry.status == 301:
            continue

        if dry_run:
            print(f"    GET {canon}")
            entry.fetched = True
            fetched_count += 1
            continue

        try:
            result = _http_fetch(canon)
        except (HTTPError, URLError) as exc:
            entry.error = str(exc)
            print(f"[-] fetch failed: {canon} ({exc})", file=sys.stderr)
            continue

        entry.status = result.status
        entry.fetched = True
        fetched_count += 1

        if entry.external:
            root = _external_mirror_root(exports, canon)
            rel = local_rel_path(canon, external=True)
            local = root / rel
        else:
            root = _origin_mirror_root(exports, entry.origin)
            rel = local_rel_path(canon, external=False)
            local = root / rel

        if not dry_run:
            _write_bytes(local, result.body)
            entry.local = str(local.relative_to(exports))

        if result.content_type.startswith("text/html") or (
            not entry.external and _looks_like_html(result.body, result.content_type)
        ):
            html = result.body.decode("utf-8", errors="replace")
            new_urls = _enqueue_crawl_links(
                entries,
                base_url=result.final_url,
                html=html,
                target_ip=target_ip,
                internal_hosts=internal_hosts,
                origins=origins,
            )
            for new_url in new_urls:
                schedule(new_url)

        loc = entry.local or canon
        print(f"[+] {loc}  ({result.status}, {len(result.body)} bytes)")


def _looks_like_html(body: bytes, content_type: str) -> bool:
    if "html" in content_type:
        return True
    head = body[:256].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _build_origin_tree(entries: list[MirrorEntry]) -> dict:
    tree: dict = {}
    for entry in entries:
        if entry.external:
            continue
        parts = [p for p in entry.path.strip("/").split("/") if p]
        if not parts and entry.path != "/":
            continue
        status = entry.status if entry.status is not None else 0
        if not parts:
            continue
        _paths_tree_insert(tree, parts, status if status else 200)
    return tree


def _format_sitemap_md(
    ip: str,
    groups: list[tuple[str, list]],
    entries: dict[str, MirrorEntry],
    exports: Path,
) -> str:
    lines = [f"# SITEMAP  target {ip}", ""]
    by_origin: dict[str, list[MirrorEntry]] = {}
    external: list[MirrorEntry] = []

    for entry in entries.values():
        if entry.external:
            external.append(entry)
        else:
            by_origin.setdefault(entry.origin, []).append(entry)

    for origin, _ in groups:
        lines.append(origin)
        origin_entries = by_origin.get(origin, [])
        tree = _build_origin_tree(origin_entries)
        if tree:
            for line in _paths_tree_lines(tree, depth=0):
                lines.append(line)
        else:
            lines.append("  (no files fetched)")

        lines.append("")
        lines.append("files:")
        for entry in sorted(origin_entries, key=lambda e: e.path.lower()):
            if entry.status == 301:
                redir = f" → {entry.redirect_to}" if entry.redirect_to else ""
                lines.append(f"  {entry.path}  [301{redir}]")
            elif entry.local:
                lines.append(
                    f"  {entry.path}  [{entry.status or '?'}]  {entry.local}  ({entry.source})"
                )
            elif entry.error:
                lines.append(f"  {entry.path}  [failed]  {entry.error}")
        lines.append("")

    if external:
        lines.append("--- external images ---")
        for entry in sorted(external, key=lambda e: e.url.lower()):
            loc = entry.local or "(not fetched)"
            lines.append(f"  {entry.url}  →  {loc}")
        lines.append("")

    return "\n".join(lines)


def run_paths_tree_fetch(ip: str, *, dry_run: bool = False) -> int:
    if not looks_like_ipv4(ip):
        print(f"[-] invalid ip: {ip}", file=sys.stderr)
        return 1

    try:
        exports = Path(_case_exports_dir())
    except RuntimeError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    origins, groups, internal_hosts = _collect_path_seeds(ip)
    if not groups:
        print("(no PATHS — run scout -d / scout -ds first)")
        return 0

    entries = _build_seed_entries(groups)

    mirror_root = exports / "web_mirror"
    mirror_root.mkdir(parents=True, exist_ok=True)

    print("")
    print(f"[*] report-tree-fetch {ip}")
    print(f"[*] seeds: {sum(1 for e in entries.values() if e.source == 'paths')} paths entries")
    print(f"[*] output: {mirror_root}")
    if dry_run:
        print("[*] dry-run — no files written")
    print("")

    _fetch_all(
        entries,
        exports=exports,
        target_ip=ip,
        internal_hosts=internal_hosts,
        origins=origins,
        dry_run=dry_run,
    )

    if not dry_run:
        sitemap_json = mirror_root / "sitemap.json"
        payload = {
            "ip": ip,
            "origins": origins,
            "entries": [asdict(e) for e in sorted(entries.values(), key=lambda x: x.url)],
        }
        sitemap_json.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        sitemap_md = mirror_root / "SITEMAP.md"
        sitemap_md.write_text(
            _format_sitemap_md(ip, groups, entries, exports),
            encoding="utf-8",
        )
        print("")
        print(f"[+] sitemap: {sitemap_md}")
        print(f"[+] manifest: {sitemap_json}")

    fetched = sum(1 for e in entries.values() if e.fetched)
    external = sum(1 for e in entries.values() if e.external and e.fetched)
    print(
        f"[*] done: {fetched} file(s)"
        + (f", {external} external image(s)" if external else "")
    )
    return 0

