"""Scout file extension fuzz via ffuf + SecLists extension wordlists."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from url_util import canonicalize_url

SELECTOR_EXT_FUZZ = "ext-fuzz"
INTERESTING_FFUF_STATUS = frozenset({200, 301, 302, 401})
_EXT_FUZZ_MARKER_RE = re.compile(r"\.FUZZ$", re.I)


def _path_from_raw(raw: str) -> str:
    s = (raw or "").strip()
    if s.startswith(("http://", "https://")):
        from scout_run import coerce_web_url

        return urlparse(coerce_web_url(s)).path or "/"
    return s if s.startswith("/") else f"/{s}"


def _normalize_path(raw: str) -> str:
    return _path_from_raw(raw).rstrip("/") or "/"


def has_trailing_slash(raw: str) -> bool:
    """True when the user path ends with / (directory intent before normalization)."""
    s = (raw or "").strip()
    if not s:
        return False
    if s.startswith(("http://", "https://")):
        from scout_run import coerce_web_url

        path = urlparse(coerce_web_url(s)).path or "/"
    else:
        path = s if s.startswith("/") else f"/{s}"
    return len(path) > 1 and path.endswith("/")


def has_ext_fuzz_marker(raw: str) -> bool:
    """True when normalized path ends with .FUZZ (case-insensitive)."""
    path = _normalize_path(raw)
    return path != "/" and bool(_EXT_FUZZ_MARKER_RE.search(path))


def has_ext_wildcard_suffix(raw: str) -> bool:
    """True when path ends with literal .* (extension wildcard syntax)."""
    path = _normalize_path(raw)
    return path != "/" and path.endswith(".*")


def is_ext_fuzz_request(raw: str, *, dx: bool = False) -> bool:
    """True when user explicitly requested ffuf extension fuzz."""
    if not (raw or "").strip():
        return False
    path = _normalize_path(raw)
    if path == "/":
        return False
    # Trailing slash = enumerate that literal path (e.g. a dir named script.FUZZ).
    if has_trailing_slash(raw):
        return False
    if not dx:
        return False
    if has_ext_fuzz_marker(raw):
        return True
    if has_ext_wildcard_suffix(raw):
        return True
    return True


def parse_ext_fuzz_target(raw: str, *, dx: bool = False) -> tuple[str, str]:
    """Return (dir_part, stem) for ffuf script.FUZZ style fuzz."""
    if not is_ext_fuzz_request(raw, dx=dx):
        raise ValueError(
            f"not an extension-fuzz path: {raw!r}"
            " — use -dx (/path/stem, /path/stem.FUZZ, or -dx /path/stem.*)"
        )
    path = _normalize_path(raw)

    if has_ext_wildcard_suffix(raw):
        file_path = path[:-2]
    elif has_ext_fuzz_marker(raw):
        file_path = _EXT_FUZZ_MARKER_RE.sub("", path)
    else:
        file_path = path

    if "/" in file_path:
        dir_part, base = file_path.rsplit("/", 1)
    else:
        dir_part, base = "", file_path

    if not base:
        raise ValueError(f"extension-fuzz needs a filename stem: {raw!r}")

    dir_part = f"/{dir_part.strip('/')}/" if dir_part else "/"

    if (
        dx
        and "." in base
        and not has_ext_fuzz_marker(raw)
        and not has_ext_wildcard_suffix(raw)
    ):
        stem = base.rsplit(".", 1)[0]
    else:
        stem = base

    if not stem or stem.startswith("."):
        raise ValueError(f"invalid extension-fuzz stem from {raw!r}")

    return dir_part, stem


def ext_fuzz_seed_path(dir_part: str, stem: str) -> str:
    if dir_part == "/":
        return f"/{stem}"
    return f"{dir_part.rstrip('/')}/{stem}"


def split_ext_fuzz_stem(path: str) -> tuple[str, str]:
    """(/scripts/, script) from /scripts/script.txt — legacy helper."""
    return parse_ext_fuzz_target(path, dx=True)


def wordlist_extension_style(wordlist: str) -> str:
    """bare: old,txt → script.FUZZ  |  dotted: .old,.txt → scriptFUZZ"""
    path = Path(wordlist)
    if not path.is_file():
        return "bare"
    dotted = bare = 0
    for line in path.read_text(errors="replace").splitlines()[:40]:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("."):
            dotted += 1
        else:
            bare += 1
    return "dotted" if dotted > bare else "bare"


def ext_fuzz_fuzz_path(dir_part: str, stem: str, wordlist: str) -> str:
    rel = f"{dir_part.strip('/')}/{stem}" if dir_part != "/" else stem
    if wordlist_extension_style(wordlist) == "dotted":
        return f"{rel}FUZZ"
    return f"{rel}.FUZZ"


def resolve_ext_fuzz_urls(
    ip: str,
    raw: str,
    *,
    dx: bool = False,
    host_header: Optional[str] = None,
    wordlist: Optional[str] = None,
) -> tuple[str, str, Optional[int]]:
    """Return (seed_file_url, ffuf_url_with_FUZZ, port)."""
    _ = host_header
    from scout_run import resolve_dirs_target

    dir_part, stem = parse_ext_fuzz_target(raw, dx=dx)
    seed_path = ext_fuzz_seed_path(dir_part, stem)

    if (raw or "").strip().startswith(("http://", "https://")):
        from scout_run import coerce_web_url

        parsed = urlparse(coerce_web_url(raw.strip()))
        base = canonicalize_url(f"{parsed.scheme}://{parsed.netloc}{dir_part}")
        port = parsed.port
    else:
        base = resolve_dirs_target(ip, dir_part.rstrip("/") or "/")
        parsed = urlparse(base)
        port = parsed.port

    host = parsed.hostname or ip
    scheme = parsed.scheme or "http"
    if port is None:
        port = 443 if scheme == "https" else 80

    wl = wordlist or ""
    fuzz_rel = ext_fuzz_fuzz_path(dir_part, stem, wl) if wl else (
        f"{dir_part.strip('/')}/{stem}.FUZZ" if dir_part != "/" else f"{stem}.FUZZ"
    )
    ffuf_url = canonicalize_url(f"{scheme}://{host}:{port}/{fuzz_rel.lstrip('/')}")
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        ffuf_url = canonicalize_url(f"{scheme}://{host}/{fuzz_rel.lstrip('/')}")

    seed_url = canonicalize_url(f"{scheme}://{host}:{port}{seed_path}")
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        seed_url = canonicalize_url(f"{scheme}://{host}{seed_path}")

    return seed_url, ffuf_url, port


def build_ffuf_ext_argv(
    ffuf_url: str,
    wordlist: str,
    threads: int,
    *,
    json_path: str,
    host_header: Optional[str] = None,
    exclude_length: Optional[int] = None,
) -> list[str]:
    args = [
        "ffuf",
        "-u",
        ffuf_url,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "-ac",
        "-s",
        "-noninteractive",
        "-o",
        json_path,
        "-of",
        "json",
    ]
    if host_header:
        args.extend(["-H", f"Host: {host_header.strip()}"])
    if exclude_length is not None:
        args.extend(["-fs", str(exclude_length)])
    return args


def ext_fuzz_display_url(seed_url: str, host_header: Optional[str] = None) -> str:
    """Human label: vhost FQDN when -H set; ffuf -u still uses IP."""
    if not host_header:
        return seed_url
    parsed = urlparse(seed_url)
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port
    path = parsed.path or "/"
    if port is None:
        port = 443 if scheme == "https" else 80
    host = host_header.strip()
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def extract_ffuf_ext_findings(
    json_path: str,
    *,
    base_url: str,
) -> list[tuple[str, int]]:
    _ = base_url
    path = Path(json_path)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    best: dict[str, int] = {}
    for row in data.get("results") or []:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        try:
            status = int(row.get("status") or 0)
        except (TypeError, ValueError):
            continue
        if status not in INTERESTING_FFUF_STATUS:
            continue
        hit_path = urlparse(url).path or "/"
        if not hit_path.startswith("/"):
            hit_path = f"/{hit_path}"
        if _looks_like_file(hit_path):
            hit_path = hit_path.rstrip("/")
        prev = best.get(hit_path)
        if prev is None or status < prev:
            best[hit_path] = status
    return sorted(best.items(), key=lambda x: (x[0].lower(), x[1]))


def _looks_like_file(path: str) -> bool:
    base = (path or "").rstrip("/").rsplit("/", 1)[-1]
    return "." in base and not base.endswith(".")


def parse_ffuf_ext_hits(json_path: str, *, base_url: str, max_lines: int = 30) -> str:
    from scout_run import format_dir_findings

    return format_dir_findings(
        extract_ffuf_ext_findings(json_path, base_url=base_url),
        max_lines=max_lines,
    )


def ext_fuzz_stem_label(raw: str, *, dx: bool = False) -> str:
    _dir, stem = parse_ext_fuzz_target(raw, dx=dx)
    return stem
