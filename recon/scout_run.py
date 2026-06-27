"""
Scout: port scan (scan basic) + service-based probes + background gobuster dirs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin
from urllib.parse import urlparse

from db import connect
from db import dirs_command_host_header
from db import find_cached_scout_job
from db import find_done_scout_job
from db import find_running_scout_job
from db import format_scan_snapshot_lines
from db import format_scan_snapshot_case_lines
from db import case_has_basic_scan
from db import fetch_merged_open_ports
from db import get_scout_job
from db import insert_scout_job
from db import list_scout_jobs
from db import list_scout_jobs_for_case
from db import update_scout_job
from db import upsert_host
from db import _fetch_ports
from db import count_tcp_coverage_in_ports
from executor import run_command_or_cache
from scan_run import PROFILE_BASIC
from scan_run import PROFILE_FULL
from scan_run import is_profile_coverage_complete
from scan_run import run_scan
from url_util import canonicalize_url
from url_util import dirs_origin_url
from url_util import normalize_dirs_scan_url
from url_util import normalize_web_url
from url_util import url_path_key
from case_scope import case_name_from_env

PROBE_TIMEOUT_SEC = 30

DEFAULT_WATCH_INTERVAL_SEC = 2.0

# Status screen: show this many finished jobs (+ all running at bottom).
SCOUT_STATUS_SLOTS = max(1, int(os.environ.get("SCOUT_STATUS_SLOTS", "4")))

DEFAULT_GB_THREADS = int(os.environ.get("GB_THREADS", "40"))
DEFAULT_GB_DIR_THREADS = int(os.environ.get("GB_DIR_THREADS", "10"))
DEFAULT_DIRS_MULTI_THREADS = int(os.environ.get("GB_DIRS_THREADS", "15"))
DEFAULT_GB_TIMEOUT_SEC = int(os.environ.get("GB_TIMEOUT", "30"))
SCOUT_DIRS_AUTO_MAX = max(1, int(os.environ.get("SCOUT_DIRS_AUTO_MAX", "24")))
DIRS_PRIORITY_PORTS = (
    80,
    443,
    8080,
    8443,
    8000,
    8888,
    8008,
    3000,
    5000,
    9000,
)

# Webmin and similar: nmap may say "http" but the service speaks HTTPS on this port.
HTTPS_ONLY_PORTS = frozenset({10000})

WEB_SERVICE_HINTS = (
    "http",
    "https",
    "nginx",
    "apache",
    "http-proxy",
    "lighttpd",
    "tomcat",
    "microsoft-iis",
    "gunicorn",
    "unicorn",
    "web",
)

INTERESTING_HIT_STATUS = frozenset({200, 301, 302, 401})
GOBUSTER_HIT_RE = re.compile(r"^\s*(\S+)\s+\(Status:\s*(\d+)\)")
GOBUSTER_REDIRECT_RE = re.compile(r"\[-->\s*(https?://[^\]]+)\]")
GOBUSTER_WILDCARD_HINT_RE = re.compile(
    r"exclude the response length|wildcard option",
    re.I,
)
GOBUSTER_WILDCARD_LENGTH_RE = re.compile(r"Length:\s*(\d+)")
GOBUSTER_HIT_SIZE_RE = re.compile(r"\[Size:\s*(\d+)\]")
_EXCLUDE_LENGTH_CMD_RE = re.compile(r"--exclude-length\s+(\d+)")

# Hidden paths worth showing when found (not extension-fuzz noise).
_HIDDEN_DIR_OK = frozenset({".git", ".svn", ".well-known", ".env"})

# Prefer 200 over redirect over 401 when deduplicating the same path.
_STATUS_RANK = {200: 0, 301: 1, 302: 1, 401: 2}


@dataclass(frozen=True)
class ProbePlan:
    probe_id: str
    task_type: str
    command: str


@dataclass(frozen=True)
class DirsPlan:
    url: str
    port: Optional[int]
    wordlist: str
    threads: int
    extensions: Optional[str]
    command: str
    log_path: str
    exclude_length: Optional[int] = None
    host_header: Optional[str] = None
    user_agent: Optional[str] = None
    cookie: Optional[str] = None


def _normalize_service(service: str) -> str:
    return (service or "").strip().lower()


def is_web_service(service: str) -> bool:
    svc = _normalize_service(service)
    if not svc or svc in ("-", "unknown"):
        return False
    if "sftp" in svc:
        return False
    return any(hint in svc for hint in WEB_SERVICE_HINTS)


def web_scheme_for_port(port: int, service: str = "") -> str:
    if port in HTTPS_ONLY_PORTS or port == 443:
        return "https"
    if port == 80:
        return "http"
    svc = _normalize_service(service)
    if "https" in svc or svc.startswith("ssl/") or "miniserv" in svc or "webmin" in svc:
        return "https"
    return "http"


def coerce_web_url(url: str) -> str:
    """Upgrade http→https on ports that only accept TLS (e.g. Webmin :10000)."""
    base = normalize_web_url(url)
    parsed = urlparse(base)
    if not parsed.scheme or not parsed.hostname:
        return base
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get(parsed.scheme.lower(), 80)
    if parsed.scheme.lower() == "http" and port in HTTPS_ONLY_PORTS:
        path = parsed.path or "/"
        return canonicalize_url(f"https://{parsed.hostname}:{port}{path}")
    return base


def build_web_url(ip: str, port: int, service: str) -> str:
    scheme = web_scheme_for_port(port, service)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return canonicalize_url(f"{scheme}://{ip}/")
    return canonicalize_url(f"{scheme}://{ip}:{port}/")


def normalize_url(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return s
    if not s.startswith(("http://", "https://")):
        s = f"http://{s}"
    return s


def looks_like_vhost_hostname(s: str) -> bool:
    """Bare FQDN for scout -d/-H (mafialive.thm), not a URL path segment."""
    raw = (s or "").strip()
    if not raw or raw.startswith(("-", "/", ".", "http")):
        return False
    if raw.startswith(":") or looks_like_ipv4(raw):
        return False
    if "/" in raw:
        return False
    if "." not in raw:
        return False
    return bool(re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z0-9-]+$", raw))


def is_dirs_path_arg(s: str) -> bool:
    """Path or URL for scout -d (not an IP, vhost hostname, or flag)."""
    if not s or s.startswith("-"):
        return False
    if looks_like_vhost_hostname(s):
        return False
    if s.startswith(("http://", "https://", "/")):
        return True
    if _parse_port_path_shorthand(s) is not None:
        return True
    if looks_like_ipv4(s):
        return False
    return True


def looks_like_ipv4(s: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", (s or "").strip()))


def _parse_port_path_shorthand(s: str) -> tuple[int, str] | None:
    """Parse :65524/hidden/ → (65524, /hidden/) using current target IP."""
    raw = (s or "").strip()
    if not raw.startswith(":"):
        return None
    rest = raw[1:]
    if not rest or not rest[0].isdigit():
        return None
    if "/" in rest:
        port_s, path_tail = rest.split("/", 1)
    else:
        port_s, path_tail = rest, ""
    if not port_s.isdigit():
        return None
    path_tail = path_tail.strip("/")
    path = f"/{path_tail}/" if path_tail else "/"
    return int(port_s), path


def resolve_dirs_target(ip: str, path_or_url: str) -> str:
    """Turn /admin, :65524/hidden/, admin, or full URL into a gobuster -u target."""
    s = (path_or_url or "").strip()
    if s.startswith(("http://", "https://")):
        return coerce_web_url(s)

    port_path = _parse_port_path_shorthand(s)
    if port_path is not None:
        port, path = port_path
        scheme = web_scheme_for_port(port)
        if port not in HTTPS_ONLY_PORTS and port not in (80, 443):
            for web_port, url in discover_web_targets(ip):
                if web_port == port:
                    scheme = urlparse(url).scheme or scheme
                    break
        return canonicalize_url(f"{scheme}://{ip}:{port}{path}")

    path = s if s.startswith("/") else f"/{s}/"
    if not path.endswith("/"):
        path = f"{path}/"

    # Prefer scheme/port from an open Web port when unambiguous.
    web = discover_web_targets(ip)
    if len(web) == 1:
        base = web[0][1]
    elif web:
        base = build_web_url(ip, 80, "http")
        for port, url in web:
            if port == 80:
                base = url
                break
    else:
        base = f"http://{ip}/"

    return canonicalize_url(urljoin(base, path.lstrip("/")))


def resolve_dirs_targets(ip: str, raw_urls: list[str]) -> list[str]:
    return [resolve_dirs_target(ip, u) for u in raw_urls]


def _scout_case() -> str | None:
    return case_name_from_env()


def _scout_jobs(ip: str, **kwargs):
    case = _scout_case()
    if case:
        return list_scout_jobs_for_case(case, current_ip=ip, **kwargs)
    return list_scout_jobs(ip, **kwargs)


def discover_web_targets(ip: str) -> list[tuple[int, str]]:
    targets = []
    for row in fetch_merged_open_ports(ip):
        port = int(row[0])
        service = row[3] or ""
        if not is_web_service(service):
            continue
        targets.append((port, build_web_url(ip, port, service)))
    return targets


def _prioritize_web_targets(
    targets: list[tuple[int, str]], limit: int
) -> list[tuple[int, str]]:
    if len(targets) <= limit:
        return targets
    priority = {p: i for i, p in enumerate(DIRS_PRIORITY_PORTS)}

    def _sort_key(item: tuple[int, str]) -> tuple[int, int]:
        port, _url = item
        return (priority.get(port, len(DIRS_PRIORITY_PORTS)), port)

    return sorted(targets, key=_sort_key)[:limit]


def plan_vhost_schemes(ip: str, *, override: str | None = None) -> list[str]:
    """
    Schemes for scout -v, in execution order (HTTPS before HTTP when both).
    override: None (auto from nmap), 'both', 'http', 'https'.
    """
    mode = (override or "").strip().lower()
    if mode == "http":
        return ["http"]
    if mode == "https":
        return ["https"]
    if mode == "both":
        return ["https", "http"]

    has_80 = False
    has_443 = False
    for row in fetch_merged_open_ports(ip):
        port = int(row[0])
        if port == 80:
            has_80 = True
        elif port == 443:
            has_443 = True

    if has_443 and not has_80:
        return ["https"]
    if has_80 and not has_443:
        return ["http"]
    return ["https", "http"]


def resolve_dirs_targets(
    ip: str,
    *,
    urls: Optional[list[str]] = None,
    host_header: Optional[str] = None,
) -> list[tuple[Optional[int], str]]:
    """URL list for scout -d/-ds: explicit paths, DB web ports, or vhost fallback."""
    if urls:
        return [(None, resolve_dirs_target(ip, raw)) for raw in urls]
    targets = discover_web_targets(ip)
    if targets and len(targets) > SCOUT_DIRS_AUTO_MAX:
        total = len(targets)
        targets = _prioritize_web_targets(targets, SCOUT_DIRS_AUTO_MAX)
        print(
            f"[!] {total} web targets in DB — auto dirs capped at {len(targets)}"
            f" (SCOUT_DIRS_AUTO_MAX={SCOUT_DIRS_AUTO_MAX}; pass a URL or :port/path)",
            file=sys.stderr,
        )
    if targets:
        return targets
    if (host_header or "").strip():
        return [(None, f"http://{ip}/")]
    return []


def resolve_probe_plan(ip: str, port: int, service: str) -> Optional[ProbePlan]:
    """
    Decide one probe from nmap service name (no port-number guessing).
    Returns None when no rule matches (e.g. unknown / masquerade not handled yet).
    """
    svc = _normalize_service(service)

    if "ssh" in svc:
        return ProbePlan(
            probe_id="ssh",
            task_type="scout-ssh",
            command=f"nmap -p{port} --script ssh2-enum-algos {ip}",
        )

    if "ftp" in svc and "sftp" not in svc:
        url = canonicalize_url(f"ftp://{ip}:{port}/")
        return ProbePlan(
            probe_id="ftp",
            task_type="scout-ftp",
            command=f"curl -sS -m 10 {url}",
        )

    if is_web_service(service):
        url = build_web_url(ip, port, service)
        if url.startswith("https://"):
            return ProbePlan(
                probe_id="https",
                task_type="scout-https",
                command=f"curl -sSk -m 10 -D- {url}",
            )
        return ProbePlan(
            probe_id="http",
            task_type="scout-http",
            command=f"curl -sS -m 10 -D- {url}",
        )

    return None


def _case_logs_dir() -> Optional[str]:
    case_home = os.environ.get("CASE_HOME")
    if case_home:
        logs = Path(case_home) / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        return str(logs)

    if os.environ.get("CASE_LOOSE") == "1":
        root = os.environ.get("CASE_ROOT", "/workspace/cases")
        loose = Path(root) / "_unscoped" / "logs"
        loose.mkdir(parents=True, exist_ok=True)
        return str(loose)

    return None


def _url_host_slug(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/")[0]
    return host.replace(":", "_") or "target"


def _wordlist_slug(wordlist: str) -> str:
    base = Path(wordlist).name
    if base.endswith(".txt"):
        base = base[:-4]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", base)


def build_dirs_log_path(
    url: str,
    wordlist: str,
    *,
    dry_run: bool = False,
    host_header: Optional[str] = None,
) -> str:
    logs = _case_logs_dir()
    if not logs:
        if dry_run:
            logs = os.environ.get("TMPDIR", "/tmp")
        else:
            raise RuntimeError("case not set — cases set <name> first (or export CASE_LOOSE=1)")

    host = _url_host_slug(url)
    if host_header:
        vh = re.sub(r"[^a-zA-Z0-9._-]", "_", host_header.strip())
        host = f"{host}_{vh}"
    slug = _wordlist_slug(wordlist)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return str(Path(logs) / f"gobuster_{host}_{slug}_{ts}.log")


# Gobuster treats these as hits; identical body on random paths → wildcard soft-404.
_GOBUSTER_WILDCARD_STATUS = frozenset({200, 204, 301, 302, 307, 401, 403})

_VHOST_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_VHOST_PROBE_SAMPLE_COUNT = 3


@dataclass(frozen=True)
class VhostProbeResponse:
    status_code: int
    body_size: int
    redirect_url: str
    body_hash: str
    server: str
    set_cookie: str


@dataclass
class VhostWildcardProfile:
    suspicion: str  # strong | weak | none
    filter_mode: str  # fs | ac
    exclude_sizes: list[int]
    status_code: Optional[int]
    redirect_url: str
    sample_count: int

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_curl_response_headers(header_text: str) -> tuple[str, str]:
    server = ""
    set_cookie = ""
    for line in (header_text or "").splitlines():
        if not line or line.startswith("HTTP/"):
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        val = value.strip()
        if key == "server" and not server:
            server = val
        elif key == "set-cookie" and not set_cookie:
            set_cookie = val
    return server, set_cookie


def _probe_vhost_host(
    domain: str,
    host: str,
    *,
    scheme: str = "https",
    timeout_sec: Optional[int] = None,
) -> Optional[VhostProbeResponse]:
    if timeout_sec is None:
        timeout_sec = DEFAULT_GB_TIMEOUT_SEC
    domain = (domain or "").strip().lower().rstrip(".")
    host = (host or "").strip()
    if not domain or not host:
        return None
    scheme = (scheme or "https").strip().lower()
    if scheme not in ("http", "https"):
        scheme = "https"
    url = f"{scheme}://{domain}/"
    body_path = Path(os.environ.get("TMPDIR", "/tmp")) / f"vhost-probe-{uuid.uuid4().hex}.body"
    header_path = Path(os.environ.get("TMPDIR", "/tmp")) / f"vhost-probe-{uuid.uuid4().hex}.hdr"
    curl_args = [
        "curl",
        "-sS",
        "-m",
        str(timeout_sec),
        "-D",
        str(header_path),
        "-o",
        str(body_path),
        "-w",
        "%{http_code}\n%{size_download}\n%{redirect_url}",
        "-H",
        f"Host: {host}",
    ]
    if scheme == "https":
        curl_args.append("-k")
    curl_args.append(url)
    try:
        result = subprocess.run(
            curl_args,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 5,
            check=False,
        )
        lines = (result.stdout or "").strip().splitlines()
        if len(lines) < 3:
            return None
        status_code = int(lines[0])
        body_size = int(lines[1])
        redirect_url = (lines[2] or "").strip()
        if body_size < 0:
            return None
        body_bytes = body_path.read_bytes() if body_path.is_file() else b""
        body_hash = hashlib.sha256(body_bytes).hexdigest()[:16]
        header_text = header_path.read_text(encoding="utf-8", errors="replace") if header_path.is_file() else ""
        server, set_cookie = _parse_curl_response_headers(header_text)
        return VhostProbeResponse(
            status_code=status_code,
            body_size=body_size,
            redirect_url=redirect_url,
            body_hash=body_hash,
            server=server,
            set_cookie=set_cookie,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    finally:
        body_path.unlink(missing_ok=True)
        header_path.unlink(missing_ok=True)


def _vhost_probe_fingerprint(response: VhostProbeResponse) -> tuple:
    redirect = (response.redirect_url or "").strip().lower().rstrip("/")
    return (
        response.status_code,
        response.body_size,
        redirect,
        response.body_hash,
        response.server,
        response.set_cookie,
    )


def probe_vhost_wildcard_profile(
    domain: str,
    *,
    scheme: str = "https",
    timeout_sec: Optional[int] = None,
    sample_count: int = _VHOST_PROBE_SAMPLE_COUNT,
) -> VhostWildcardProfile:
    """
    Probe several random Host values and compare status, size, redirect, body hash,
    Server, and Set-Cookie. Strong suspicion → ffuf -fs; otherwise ffuf -ac.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return VhostWildcardProfile("none", "ac", [], None, "", 0)
    sample_count = max(2, int(sample_count))
    samples: list[VhostProbeResponse] = []
    for _ in range(sample_count):
        random_host = f"{uuid.uuid4().hex[:12]}.{domain}"
        sample = _probe_vhost_host(domain, random_host, scheme=scheme, timeout_sec=timeout_sec)
        if sample is not None:
            samples.append(sample)
    if len(samples) < 2:
        return VhostWildcardProfile("none", "ac", [], None, "", len(samples))

    fingerprints = [_vhost_probe_fingerprint(s) for s in samples]
    if len(set(fingerprints)) == 1:
        suspicion = "strong"
    elif len({(s.status_code, s.body_size) for s in samples}) == 1:
        suspicion = "weak"
    else:
        return VhostWildcardProfile("none", "ac", [], None, "", len(samples))

    first = samples[0]
    if first.status_code not in _GOBUSTER_WILDCARD_STATUS and first.status_code not in _VHOST_REDIRECT_STATUS:
        return VhostWildcardProfile("none", "ac", [], None, "", len(samples))
    if first.body_size == 0 and first.status_code not in _VHOST_REDIRECT_STATUS:
        return VhostWildcardProfile("none", "ac", [], None, "", len(samples))

    exclude_sizes = sorted({s.body_size for s in samples})
    filter_mode = "fs" if suspicion == "strong" else "ac"
    return VhostWildcardProfile(
        suspicion=suspicion,
        filter_mode=filter_mode,
        exclude_sizes=exclude_sizes,
        status_code=first.status_code,
        redirect_url=first.redirect_url,
        sample_count=len(samples),
    )


def assess_http_vhost_value(
    domain: str,
    *,
    timeout_sec: Optional[int] = None,
) -> dict:
    """
    HTTP port 80 is often uninformative for vhost discovery (redirect-only).
    Returns advisory metadata; does not skip ffuf unless caller opts in.
    """
    profile = probe_vhost_wildcard_profile(domain, scheme="http", timeout_sec=timeout_sec)
    out: dict = {
        "advisory": None,
        "message": "",
        "run_ffuf": True,
        "profile": profile.to_dict(),
    }
    if profile.suspicion != "strong":
        return out
    if profile.status_code not in _VHOST_REDIRECT_STATUS or not profile.exclude_sizes or profile.exclude_sizes != [0]:
        return out
    redirect = (profile.redirect_url or "").strip().lower()
    if not redirect.startswith("https://"):
        return out
    parsed = urlparse(redirect)
    host = (parsed.hostname or "").lower().rstrip(".")
    domain_norm = (domain or "").strip().lower().rstrip(".")
    if host != domain_norm and not host.endswith(f".{domain_norm}"):
        return out
    out["advisory"] = "strong_redirect_suspicion"
    out["message"] = (
        "HTTP probes consistent: redirect to HTTPS with empty body "
        "(port 80 unlikely to discriminate vhosts — verify on HTTPS pass)"
    )
    return out


def probe_wildcard_exclude_length(
    url: str,
    *,
    timeout_sec: Optional[int] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    cookie: Optional[str] = None,
) -> Optional[int]:
    """Probe a random path; if the server soft-404s with a fixed body, return its length."""
    if timeout_sec is None:
        timeout_sec = DEFAULT_GB_TIMEOUT_SEC
    base = coerce_web_url(url)
    parsed = urlparse(base)
    probe = urljoin(base if base.endswith("/") else f"{base}/", str(uuid.uuid4()))
    curl_args = [
        "curl",
        "-sS",
        "-m",
        str(timeout_sec),
        "-w",
        "%{http_code}\n%{size_download}",
        "-o",
        "/dev/null",
    ]
    if parsed.scheme == "https":
        curl_args.append("-k")
    if host_header:
        curl_args.extend(["-H", f"Host: {host_header.strip()}"])
    if cookie:
        curl_args.extend(["-H", f"Cookie: {cookie.strip()}"])
    if user_agent:
        curl_args.extend(["-A", user_agent.strip()])
    curl_args.append(probe)
    try:
        result = subprocess.run(
            curl_args,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 5,
            check=False,
        )
        # MiniServ/Webmin often ends TLS with EOF (curl exit 56) while still returning body.
        lines = (result.stdout or "").strip().splitlines()
        if len(lines) < 2:
            return None
        status_code = int(lines[0])
        size = int(lines[1])
        if status_code not in _GOBUSTER_WILDCARD_STATUS or size <= 0:
            return None
        return size
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def probe_vhost_wildcard_length(
    domain: str,
    *,
    scheme: str = "https",
    timeout_sec: Optional[int] = None,
) -> Optional[int]:
    """Backward-compatible helper: first exclude size when suspicion is strong."""
    profile = probe_vhost_wildcard_profile(domain, scheme=scheme, timeout_sec=timeout_sec)
    if profile.suspicion == "strong" and profile.exclude_sizes:
        return profile.exclude_sizes[0]
    return None


def probe_vhost_http_redirect_wildcard(
    domain: str,
    *,
    timeout_sec: Optional[int] = None,
) -> bool:
    """
    Deprecated boolean helper. True only on strong redirect suspicion (advisory).
    scout -v no longer skips HTTP ffuf based on this alone.
    """
    assessment = assess_http_vhost_value(domain, timeout_sec=timeout_sec)
    return assessment.get("advisory") == "strong_redirect_suspicion"


def parse_wildcard_exclude_length(log_path: str) -> Optional[int]:
    """Read gobuster wildcard error from log → body length to exclude."""
    path = Path(log_path)
    if not path.is_file():
        return None
    text = path.read_text(errors="replace")
    if not GOBUSTER_WILDCARD_HINT_RE.search(text):
        return None
    match = GOBUSTER_WILDCARD_LENGTH_RE.search(text)
    return int(match.group(1)) if match else None


def parse_soft404_size_from_hits(log_path: str) -> Optional[int]:
    """When every hit shares one body size, treat it as wildcard exclude-length."""
    path = Path(log_path)
    if not path.is_file():
        return None
    sizes: list[int] = []
    for line in path.read_text(errors="replace").splitlines():
        if not GOBUSTER_HIT_RE.match(line):
            continue
        match = GOBUSTER_HIT_SIZE_RE.search(line)
        if match:
            sizes.append(int(match.group(1)))
    if sizes and len(set(sizes)) == 1:
        return sizes[0]
    return None


def _command_header_values(command: str) -> list[str]:
    try:
        argv = shlex.split(command or "")
    except ValueError:
        return []
    values: list[str] = []
    for idx, token in enumerate(argv):
        if token == "-H" and idx + 1 < len(argv):
            values.append(argv[idx + 1])
    return values


def _command_header_value(command: str, name: str) -> Optional[str]:
    want = (name or "").strip().lower()
    if not want:
        return None
    for raw in _command_header_values(command):
        header_name, sep, header_value = raw.partition(":")
        if sep and header_name.strip().lower() == want:
            value = header_value.strip()
            if value:
                return value
    return None


def _command_option_value(command: str, *flags: str) -> Optional[str]:
    wanted = set(flags)
    if not wanted:
        return None
    try:
        argv = shlex.split(command or "")
    except ValueError:
        return None
    for idx, token in enumerate(argv):
        if token in wanted and idx + 1 < len(argv):
            value = argv[idx + 1].strip()
            if value:
                return value
    return None


def _known_exclude_length_from_scope(target_ip: str, url: str) -> Optional[int]:
    """Reuse exclude-length learned on lineage IPs for the same scan base."""
    from url_util import url_path_key

    want = url_path_key(coerce_web_url(url))
    if not want:
        return None
    for row in _scout_jobs(target_ip, kind="dirs", limit=200):
        if url_path_key(row["url"] or "") != want:
            continue
        cmd = row["command"] or ""
        match = _EXCLUDE_LENGTH_CMD_RE.search(cmd)
        if match:
            return int(match.group(1))
        log_path = row["log_path"] or ""
        if not log_path:
            continue
        xl = parse_wildcard_exclude_length(log_path)
        if xl is not None:
            return xl
        xl = parse_soft404_size_from_hits(log_path)
        if xl is not None:
            return xl
    return None


def _threads_from_gobuster_command(command: str) -> int:
    match = re.search(r"(?:^|\s)-t\s+(\d+)", command or "")
    if match:
        return int(match.group(1))
    return DEFAULT_GB_DIR_THREADS


def build_gobuster_dir_argv(
    url: str,
    wordlist: str,
    threads: int,
    extensions: Optional[str] = None,
    exclude_length: Optional[int] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    cookie: Optional[str] = None,
) -> list[str]:
    args = [
        "gobuster",
        "dir",
        "-u",
        url,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "--timeout",
        f"{DEFAULT_GB_TIMEOUT_SEC}s",
        "-q",
    ]
    if urlparse(url).scheme == "https":
        args.append("-k")
    if host_header:
        args.extend(["-H", f"Host:{host_header.strip()}"])
    if cookie:
        args.extend(["-H", f"Cookie:{cookie.strip()}"])
    if user_agent:
        args.extend(["-a", user_agent.strip()])
    if exclude_length is not None:
        args.extend(["--exclude-length", str(exclude_length)])
    if extensions:
        args.extend(["--extensions", extensions])
    return args


def build_dirs_plan(
    url: str,
    *,
    ip: Optional[str] = None,
    port: Optional[int] = None,
    wordlist: Optional[str] = None,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
    dry_run: bool = False,
    exclude_length_override: Optional[int] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    cookie: Optional[str] = None,
) -> DirsPlan:
    from wordlists.scout import resolve_scout_wordlist

    url = coerce_web_url(normalize_web_url(url))
    try:
        wl = resolve_scout_wordlist(wordlist, extensions=extensions)
    except ValueError as exc:
        raise FileNotFoundError(str(exc)) from exc
    th = threads if threads is not None else DEFAULT_GB_DIR_THREADS
    if not dry_run and not Path(wl).is_file():
        raise FileNotFoundError(f"wordlist not found: {wl}")

    target_ip = (ip or urlparse(coerce_web_url(url)).hostname or "").strip()

    vhost = (host_header or "").strip() or None

    if exclude_length_override is not None:
        exclude_length = exclude_length_override
    else:
        exclude_length = probe_wildcard_exclude_length(
            url,
            host_header=vhost,
            user_agent=user_agent,
            cookie=cookie,
        )
        if exclude_length is None and target_ip:
            exclude_length = _known_exclude_length_from_scope(target_ip, url)
            if exclude_length is not None:
                print(
                    f"    [i] exclude-length {exclude_length}"
                    " (from lineage / prior scan)",
                    file=sys.stderr,
                )
        if exclude_length is None:
            print(
                "    [!] wildcard probe failed — gobuster may stop;"
                " retry will parse Length from log if needed",
                file=sys.stderr,
            )
    argv = build_gobuster_dir_argv(
        url,
        wl,
        th,
        extensions,
        exclude_length=exclude_length,
        host_header=vhost,
        user_agent=user_agent,
        cookie=cookie,
    )
    log_path = build_dirs_log_path(url, wl, dry_run=dry_run, host_header=vhost)
    command = " ".join(shlex.quote(a) for a in argv)
    return DirsPlan(
        url=url,
        port=port,
        wordlist=wl,
        threads=th,
        extensions=extensions,
        command=command,
        log_path=log_path,
        exclude_length=exclude_length,
        host_header=vhost,
        user_agent=user_agent,
        cookie=cookie,
    )


def build_ext_fuzz_log_path(
    seed_url: str,
    wordlist: str,
    *,
    dry_run: bool = False,
    host_header: Optional[str] = None,
) -> str:
    logs = _case_logs_dir()
    if not logs:
        if dry_run:
            logs = os.environ.get("TMPDIR", "/tmp")
        else:
            raise RuntimeError("case not set — cases set <name> first (or export CASE_LOOSE=1)")

    host = _url_host_slug(seed_url)
    if host_header:
        vh = re.sub(r"[^a-zA-Z0-9._-]", "_", host_header.strip())
        host = f"{host}_{vh}"
    path_slug = re.sub(
        r"[^a-zA-Z0-9._-]",
        "_",
        (urlparse(seed_url).path or "file").strip("/"),
    )[:80]
    slug = _wordlist_slug(wordlist)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return str(Path(logs) / f"ffuf_ext_{host}_{path_slug}_{slug}_{ts}.json")


def build_ext_fuzz_plan(
    ip: str,
    raw_path: str,
    *,
    wordlist: Optional[str] = None,
    threads: Optional[int] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    dry_run: bool = False,
    wordlist_from_flag: bool = False,
    dx: bool = False,
) -> DirsPlan:
    from scout_ext_fuzz import build_ffuf_ext_argv
    from scout_ext_fuzz import resolve_ext_fuzz_urls
    from wordlists.scout import resolve_ext_fuzz_wordlist

    if wordlist and Path(wordlist).is_file():
        wl = wordlist
    else:
        wl = resolve_ext_fuzz_wordlist(wordlist, from_flag=wordlist_from_flag)

    seed_url, ffuf_url, port = resolve_ext_fuzz_urls(
        ip, raw_path, dx=dx, host_header=host_header, wordlist=wl
    )
    th = threads if threads is not None else DEFAULT_GB_DIR_THREADS
    if not dry_run and not Path(wl).is_file():
        raise FileNotFoundError(f"wordlist not found: {wl}")

    json_path = build_ext_fuzz_log_path(
        seed_url, wl, dry_run=dry_run, host_header=host_header
    )
    vhost = (host_header or "").strip() or None
    argv = build_ffuf_ext_argv(
        ffuf_url,
        wl,
        th,
        json_path=json_path,
        host_header=vhost,
        user_agent=user_agent,
    )
    command = " ".join(shlex.quote(a) for a in argv)
    return DirsPlan(
        url=seed_url,
        port=port,
        wordlist=wl,
        threads=th,
        extensions=None,
        command=command,
        log_path=json_path,
        exclude_length=None,
        host_header=vhost,
        user_agent=user_agent,
    )


def _is_gobuster_noise(path_part: str) -> bool:
    if path_part in (".", ""):
        return True
    base = path_part.rstrip("/")
    if base in _HIDDEN_DIR_OK:
        return False
    if base.startswith("."):
        return True
    return False


def _looks_like_file(path: str) -> bool:
    name = path.rstrip("/").split("/")[-1]
    if not name or name == "/":
        return False
    if name in _HIDDEN_DIR_OK:
        return False
    if name.startswith("."):
        return True
    return "." in name


def _normalize_dir_path(path_part: str, full_line: str) -> Optional[str]:
    redir_m = GOBUSTER_REDIRECT_RE.search(full_line)
    if redir_m:
        try:
            parsed = urlparse(redir_m.group(1))
        except ValueError:
            parsed = None
        if parsed is not None:
            p = parsed.path or "/"
            if p == "/":
                return None
            if not p.startswith("/"):
                p = f"/{p}"
            if _looks_like_file(p):
                return p.rstrip("/")
            if not p.endswith("/"):
                p = f"{p}/"
            return p

    if _is_gobuster_noise(path_part):
        return None

    clean = path_part.strip("/")
    if not clean:
        return None

    p = f"/{clean}"
    if _looks_like_file(p):
        return p
    return f"{p}/"


def _base_path_from_url(url: str) -> str:
    p = urlparse(normalize_url(url)).path or "/"
    if not p.endswith("/"):
        p = f"{p}/"
    return p


def resolve_site_path(base_url: str, path: str) -> str:
    """Map a gobuster hit to a site-root path (respecting the scan base URL)."""
    path = path if path.startswith("/") else f"/{path}"
    if _looks_like_file(path):
        path = path.rstrip("/")
    elif not path.endswith("/"):
        path = f"{path}/"
    base_p = _base_path_from_url(base_url)
    if base_p == "/":
        return path
    if path.startswith(base_p):
        return path
    return f"{base_p.rstrip('/')}{path}"


def extract_dir_findings(
    log_path: str,
    base_url: Optional[str] = None,
) -> list[tuple[str, int]]:
    """Parse gobuster log → site-root paths as (/path/, status), deduped."""
    path = Path(log_path)
    if not path.is_file():
        return []

    best: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        m = GOBUSTER_HIT_RE.match(line)
        if not m:
            continue
        path_part, status_s = m.group(1), m.group(2)
        try:
            status = int(status_s)
        except ValueError:
            continue
        if status not in INTERESTING_HIT_STATUS:
            continue

        norm = _normalize_dir_path(path_part, line)
        if not norm:
            continue
        if base_url:
            norm = resolve_site_path(base_url, norm)

        prev = best.get(norm)
        if prev is None or _STATUS_RANK[status] < _STATUS_RANK[prev]:
            best[norm] = status

    return sorted(best.items(), key=lambda x: (x[0].lower(), x[1]))


def format_dir_findings(findings: list[tuple[str, int]], *, max_lines: int = 30) -> str:
    if not findings:
        return ""
    lines = [f"{p}  {status}" for p, status in findings]
    if len(lines) > max_lines:
        extra = len(lines) - max_lines
        lines = lines[:max_lines]
        lines.append(f"... +{extra} more (see log)")
    return "\n".join(lines)


def parse_gobuster_hits(
    log_path: str,
    *,
    base_url: Optional[str] = None,
    max_lines: int = 20,
) -> str:
    return format_dir_findings(
        extract_dir_findings(log_path, base_url=base_url),
        max_lines=max_lines,
    )


def _pid_alive(pid: Optional[int]) -> bool:
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def reconcile_scout_job(job_id: int) -> None:
    row = get_scout_job(job_id)
    if not row or row["status"] != "running":
        return

    pid = row["pid"]
    exit_code = None
    # waitpid before _pid_alive: exited children stay as zombies and still
    # answer kill(0), so status would never flip to done during -ws watch.
    if pid:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                exit_code = os.waitstatus_to_exitcode(status)
        except (ChildProcessError, ProcessLookupError):
            pass

    if exit_code is None and _pid_alive(pid):
        return

    log_path = row["log_path"] or ""
    if row["kind"] == "ext-fuzz":
        from scout_ext_fuzz import parse_ffuf_ext_hits

        hits = parse_ffuf_ext_hits(log_path, base_url=row["url"]) if log_path else ""
    else:
        hits = parse_gobuster_hits(log_path, base_url=row["url"]) if log_path else ""
    failed = exit_code not in (None, 0)
    if failed and log_path and Path(log_path).is_file() and hits:
        failed = False

    if (
        failed
        and log_path
        and row["kind"] == "dirs"
        and "--exclude-length" not in (row["command"] or "")
        and not hits
    ):
        xl = parse_wildcard_exclude_length(log_path)
        if xl is not None:
            update_scout_job(
                job_id,
                status="failed",
                exit_code=exit_code,
                hits_summary="wildcard — retrying with exclude-length",
                ended_at=datetime.now().isoformat(timespec="seconds"),
            )
            if find_running_scout_job(
                row["ip"],
                row["kind"] or "dirs",
                row["url"] or "",
                row["wordlist"] or "",
                host_header=_command_header_value(row["command"] or "", "Host"),
            ):
                return
            try:
                plan = build_dirs_plan(
                    row["url"] or "",
                    ip=row["ip"],
                    wordlist=row["wordlist"],
                    threads=_threads_from_gobuster_command(row["command"] or ""),
                    exclude_length_override=xl,
                    host_header=_command_header_value(row["command"] or "", "Host"),
                    user_agent=_command_option_value(row["command"] or "", "-a", "-A"),
                    cookie=_command_header_value(row["command"] or "", "Cookie"),
                )
            except (FileNotFoundError, ValueError) as exc:
                print(f"    [-] wildcard retry failed: {exc}", file=sys.stderr)
                return
            print(f"    [i] wildcard retry — exclude-length {xl}")
            _dispatch_dirs_job(row["ip"], plan, force=True)
            return

    update_scout_job(
        job_id,
        status="failed" if failed else "done",
        exit_code=exit_code,
        hits_summary=hits or None,
        ended_at=datetime.now().isoformat(timespec="seconds"),
    )


def reconcile_scout_jobs(ip: str) -> None:
    for row in _scout_jobs(ip, status="running", limit=200):
        reconcile_scout_job(int(row["id"]))


def _dispatch_dirs_job(
    ip: str,
    plan: DirsPlan,
    *,
    dry_run: bool = False,
    force: bool = False,
) -> Optional[int]:
    if force:
        print("    [i] --force: re-dispatch dirs")

    if not force:
        cached, cached_status = find_cached_scout_job(
            ip, "dirs", plan.url, plan.wordlist, host_header=plan.host_header
        )
        if cached:
            where = (
                f" on lineage {cached['ip']}"
                if cached["ip"] != ip
                else ""
            )
            if cached_status == "running":
                print(
                    f"    -> skip (running{where} job id={cached['id']} pid={cached['pid']})"
                    " — use --force to start another"
                )
            elif cached_status == "done":
                print(
                    f"    -> skip (done{where} job id={cached['id']})"
                    " — use --force to rerun"
                )
            else:
                print(
                    f"    -> skip (failed{where} job id={cached['id']})"
                    " — use --force to rerun"
                )
            return None

    print(f"    -> dirs {plan.url}")
    if plan.host_header:
        print(f"    [i] vhost Host: {plan.host_header}")
    if plan.exclude_length is not None:
        print(f"    [i] wildcard soft-404 — exclude-length {plan.exclude_length}")
    print(f"    $ {plan.command}")
    print(f"    log: {plan.log_path}")

    if dry_run:
        return None

    log_path = Path(plan.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as logf:
        proc = subprocess.Popen(
            build_gobuster_dir_argv(
                plan.url,
                plan.wordlist,
                plan.threads,
                plan.extensions,
                exclude_length=plan.exclude_length,
                host_header=plan.host_header,
                user_agent=plan.user_agent,
                cookie=plan.cookie,
            ),
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    job_id = insert_scout_job(
        ip,
        "dirs",
        plan.url,
        port=plan.port,
        wordlist=plan.wordlist,
        command=plan.command,
        log_path=plan.log_path,
        status="running",
        pid=proc.pid,
    )
    print(f"    -> job_id={job_id} pid={proc.pid}  scout status")
    return job_id


def _dispatch_ext_fuzz_job(
    ip: str,
    plan: DirsPlan,
    *,
    raw_path: str,
    dry_run: bool = False,
    force: bool = False,
    dx: bool = False,
) -> Optional[int]:
    from scout_ext_fuzz import build_ffuf_ext_argv
    from scout_ext_fuzz import ext_fuzz_display_url
    from scout_ext_fuzz import ext_fuzz_stem_label

    kind = "ext-fuzz"
    if force:
        print("    [i] --force: re-dispatch ext-fuzz")

    if not force:
        cached, cached_status = find_cached_scout_job(
            ip, kind, plan.url, plan.wordlist, host_header=plan.host_header
        )
        if cached:
            where = (
                f" on lineage {cached['ip']}"
                if cached["ip"] != ip
                else ""
            )
            if cached_status == "running":
                print(
                    f"    -> skip (running{where} job id={cached['id']} pid={cached['pid']})"
                    " — use --force to start another"
                )
            elif cached_status == "done":
                print(
                    f"    -> skip (done{where} job id={cached['id']})"
                    " — use --force to rerun"
                )
            else:
                print(
                    f"    -> skip (failed{where} job id={cached['id']})"
                    " — use --force to rerun"
                )
            return None

    stem = ext_fuzz_stem_label(raw_path, dx=dx)
    label = ext_fuzz_display_url(plan.url, plan.host_header)
    print(f"    -> ext-fuzz {label}")
    if plan.host_header:
        print(f"    [i] ffuf -u uses IP; request Host: {plan.host_header}")
    print(f"    [i] stem {stem} + SecLists extensions (ffuf)")
    print(f"    $ {plan.command}")
    print(f"    log: {plan.log_path}")

    if dry_run:
        return None

    log_path = Path(plan.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    from scout_ext_fuzz import resolve_ext_fuzz_urls

    _seed, ffuf_url, _port = resolve_ext_fuzz_urls(
        ip,
        raw_path,
        dx=dx,
        host_header=plan.host_header,
        wordlist=plan.wordlist,
    )
    argv = build_ffuf_ext_argv(
        ffuf_url,
        plan.wordlist,
        plan.threads,
        json_path=plan.log_path,
        host_header=plan.host_header,
        user_agent=plan.user_agent,
    )
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    job_id = insert_scout_job(
        ip,
        kind,
        plan.url,
        port=plan.port,
        wordlist=plan.wordlist,
        command=plan.command,
        log_path=plan.log_path,
        status="running",
        pid=proc.pid,
    )
    print(f"    -> job_id={job_id} pid={proc.pid}  scout status")
    return job_id


def _run_ext_fuzz_phase(
    ip: str,
    *,
    urls: list[str],
    wordlist: Optional[str] = None,
    threads: Optional[int] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    dx: bool = False,
) -> int:
    if _case_logs_dir() is None and not dry_run:
        print("[-] case not set — cases set <name> first (or export CASE_LOOSE=1)")
        return 1

    print("")
    print("[*] phase 3: extension fuzz (ffuf + SecLists, background)")
    started = 0
    for raw in urls:
        try:
            plan = build_ext_fuzz_plan(
                ip,
                raw,
                wordlist=wordlist,
                threads=threads,
                host_header=host_header,
                user_agent=user_agent,
                dry_run=dry_run,
                dx=dx,
            )
        except FileNotFoundError as e:
            print(f"[-] {e}")
            return 1
        except RuntimeError as e:
            print(f"[-] {e}")
            return 1
        except ValueError as e:
            print(f"[-] {e}")
            return 1

        job_id = _dispatch_ext_fuzz_job(
            ip,
            plan,
            raw_path=raw,
            dry_run=dry_run,
            force=force,
            dx=dx,
        )
        if job_id is not None or dry_run:
            started += 1

    if started and not dry_run:
        print("")
        print(f"[*] {started} ext-fuzz job(s) started — scout status")
    print("")
    return 0


def _run_dirs_phase(
    ip: str,
    *,
    urls: Optional[list[str]] = None,
    wordlist: Optional[str] = None,
    wordlists: Optional[list[str]] = None,
    dirs_multi: bool = False,
    dirs_preset: str = "standard",
    dirs_multi_preset_from_flag: bool = False,
    dirs_multi_preset_is_next: bool = False,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    cookie: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
) -> int:
    from wordlists.scout import resolve_dirs_multi_wordlist_ids
    from wordlists.scout import resolve_dirs_multi_wordlists

    targets = resolve_dirs_targets(ip, urls=urls, host_header=host_header)

    if not targets:
        print("[*] no Web targets — skip")
        print("[i] run scout first, or: scout --dirs http://$IP:port/")
        return 0

    if _case_logs_dir() is None and not dry_run:
        print("[-] case not set — cases set <name> first (or export CASE_LOOSE=1)")
        return 1

    print("")
    rc = 0
    started = 0
    header_printed = False

    for port, url in targets:
        wl_paths: list[str] = []

        if dirs_multi and dirs_multi_preset_is_next:
            try:
                ids, label = resolve_dirs_multi_wordlist_ids(
                    preset="next",
                    extensions=extensions,
                    preset_is_next=True,
                    ip=ip,
                    url=url,
                    host_header=host_header,
                )
            except ValueError as e:
                print(f"[-] {e}")
                return 1
            if not ids:
                print(f"[*] {url}  all preset tiers done")
                continue
            wl_paths = resolve_dirs_multi_wordlists(
                wordlist_ids=ids,
                extensions=extensions,
            )
            tier = label.split("/", 1)[-1]
            src = f"next/{tier} ({len(wl_paths)} wordlists"
            if extensions:
                src += f", -x {extensions}"
            src += ")"
            print(f"[*] phase 3: directory brute (multi, {src}, background)")
        elif dirs_multi:
            wl_paths = list(wordlists or [])
            if not header_printed:
                if dirs_multi_preset_from_flag:
                    src = f"preset {dirs_preset} ({len(wl_paths)} wordlists"
                elif extensions:
                    src = f"standard ({len(wl_paths)} wordlists, -x {extensions})"
                else:
                    src = f"standard ({len(wl_paths)} wordlists)"
                if extensions and dirs_multi_preset_from_flag:
                    src += f", -x {extensions}"
                src += ")"
                print(f"[*] phase 3: directory brute (multi, {src}, background)")
                if (
                    dirs_multi_preset_from_flag
                    and dirs_preset in ("deep", "wide")
                    and not dry_run
                ):
                    print(
                        f"[!] {dirs_preset} tier runs {len(wl_paths)} jobs per URL"
                        " — consider: scout -ds -p deep -t 10",
                        file=sys.stderr,
                    )
                header_printed = True
        else:
            if wordlists:
                wl_paths = list(wordlists)
            elif wordlist:
                wl_paths = [wordlist]
            if not header_printed:
                print("[*] phase 3: directory brute (gobuster dir, background)")
                header_printed = True

        wl_batch: list[Optional[str]] = wl_paths if wl_paths else [None]

        for wl in wl_batch:
            try:
                plan = build_dirs_plan(
                    url,
                    ip=ip,
                    port=port,
                    wordlist=wl,
                    threads=threads,
                    extensions=extensions,
                    dry_run=dry_run,
                    host_header=host_header,
                    user_agent=user_agent,
                    cookie=cookie,
                )
            except FileNotFoundError as e:
                print(f"[-] {e}")
                return 1
            except RuntimeError as e:
                print(f"[-] {e}")
                return 1

            job_id = _dispatch_dirs_job(ip, plan, dry_run=dry_run, force=force)
            if job_id is not None or dry_run:
                started += 1

    if started and not dry_run:
        print("")
        print(f"[*] {started} dir job(s) started — scout status")
    print("")
    return rc


def _probe_open_rows(ip: str):
    """All open ports; resolve_probe_plan filters by service (ssh / web / ftp)."""
    return sorted(fetch_merged_open_ports(ip), key=lambda r: int(r[0]))


def _format_port_row(row) -> str:
    port, proto, _state, service, version = row
    svc = service or "-"
    ver = (version or "").strip()
    if ver:
        return f"{port}/{proto}  service={svc}  ({ver})"
    return f"{port}/{proto}  service={svc}"


def _run_probe_phase(ip: str, *, dry_run: bool = False) -> int:
    rows = _probe_open_rows(ip)
    print("")
    print("[*] phase 2: probes (all open ports, ssh + web by service)")

    if not rows:
        print("[*] no open ports — skip")
        return 0

    rc = 0
    for row in rows:
        port = int(row[0])
        service = row[3]
        print(f"[*] {_format_port_row(row)}")

        plan = resolve_probe_plan(ip, port, service)
        if not plan:
            print("    -> skip (no probe rule for this service)")
            continue

        print(f"    -> {plan.probe_id} ({plan.task_type})")
        print(f"    $ {plan.command}")

        if dry_run:
            continue

        try:
            exec_id, cached = run_command_or_cache(
                ip,
                plan.command,
                timeout_sec=PROBE_TIMEOUT_SEC,
                stream=False,
                task_type=plan.task_type,
            )
            tag = "cached" if cached else "ran"
            print(f"    -> exec_id={exec_id} ({tag})  ev {exec_id}")
        except Exception as e:
            print(f"    -> failed: {e}")
            rc = 1

    print("")
    return rc


def _fetch_scout_executions(ip: str):
    case = _scout_case()
    conn = connect()
    cur = conn.cursor()
    if case:
        from case_scope import recon_scope_ips

        ips = recon_scope_ips(ip)
        if ips:
            placeholders = ",".join("?" * len(ips))
            rows = cur.execute(
                f"""
                SELECT id, task_type, command, status, exit_code, stdout, ended_at
                FROM executions
                WHERE task_type LIKE 'scout-%'
                  AND case_name = ?
                  AND ip IN ({placeholders})
                ORDER BY id ASC
                """,
                (case, *ips),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT id, task_type, command, status, exit_code, stdout, ended_at
                FROM executions
                WHERE task_type LIKE 'scout-%' AND case_name = ?
                ORDER BY id ASC
                """,
                (case,),
            ).fetchall()
    else:
        rows = cur.execute(
            """
            SELECT id, task_type, command, status, exit_code, stdout, ended_at
            FROM executions
            WHERE ip = ? AND task_type LIKE 'scout-%'
            ORDER BY id ASC
            """,
            (ip,),
        ).fetchall()
    conn.close()
    return rows


def _probe_stdout_hint(stdout: str, *, max_len: int = 100) -> str:
    if not stdout or not stdout.strip():
        return "(no output)"

    for line in stdout.splitlines():
        s = line.strip()
        if s.startswith("HTTP/"):
            return s[:max_len]

    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("|") or s.startswith("SF-"):
            continue
        return s[:max_len]

    return stdout.strip().splitlines()[0][:max_len]


def _latest_dirs_jobs(jobs, *, group_by_path: bool = False) -> list:
    by_url = {}
    for row in jobs:
        if row["kind"] != "dirs":
            continue
        key = url_path_key(row["url"] or "") if group_by_path else normalize_dirs_scan_url(row["url"] or "")
        prev = by_url.get(key)
        if prev is None or int(row["id"]) > int(prev["id"]):
            by_url[key] = row
    return sorted(by_url.values(), key=lambda r: (r["url"] or ""))


def _dirs_findings_for_job(row) -> list[tuple[str, int]]:
    log_path = row["log_path"] or ""
    base_url = row["url"] or ""
    hits = row["hits_summary"] or ""

    def _from_hits_summary() -> list[tuple[str, int]]:
        if not hits:
            return []
        out = []
        for line in hits.splitlines():
            if line.startswith("... "):
                continue
            parts = line.rsplit("  ", 1)
            if len(parts) == 2 and parts[1].isdigit():
                out.append((parts[0], int(parts[1])))
        return out

    if log_path:
        if row["kind"] == "ext-fuzz":
            from scout_ext_fuzz import extract_ffuf_ext_findings

            findings = extract_ffuf_ext_findings(log_path, base_url=base_url)
            if findings:
                return findings
            return _from_hits_summary()
        return extract_dir_findings(log_path, base_url=base_url)
    return _from_hits_summary()


def _merge_job_findings(rows) -> list[tuple[str, int]]:
    best: dict[str, int] = {}
    for row in rows:
        for path, status in _dirs_findings_for_job(row):
            prev = best.get(path)
            if prev is None or _STATUS_RANK[status] < _STATUS_RANK[prev]:
                best[path] = status
    return sorted(best.items(), key=lambda x: x[0].lower())


def _paths_tree_insert(tree: dict, parts: list[str], status: int) -> None:
    node = tree
    for i, part in enumerate(parts):
        node = node.setdefault(part, {"status": None, "children": {}})
        if i == len(parts) - 1:
            prev = node["status"]
            if prev is None or _STATUS_RANK[status] < _STATUS_RANK[prev]:
                node["status"] = status
        node = node["children"]


def _paths_tree_lines(tree: dict, *, depth: int = 0) -> list[str]:
    lines = []
    for name in sorted(tree.keys(), key=str.lower):
        entry = tree[name]
        indent = "  " * (depth + 1)
        st = entry["status"]
        suffix = f"  {st}" if st is not None else ""
        is_leaf = st is not None and not entry["children"]
        label = name if is_leaf and _looks_like_file(f"/{name}") else f"{name}/"
        lines.append(f"{indent}{label}{suffix}")
        lines.extend(_paths_tree_lines(entry["children"], depth=depth + 1))
    return lines


def format_paths_tree(
    findings: list[tuple[str, int]],
    *,
    root_label: str = "/",
) -> list[str]:
    tree: dict = {}
    for path, status in findings:
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            continue
        _paths_tree_insert(tree, parts, status)

    if not tree:
        return []
    lines = [root_label]
    lines.extend(_paths_tree_lines(tree))
    return lines


def _paths_row_vhost(row) -> str:
    try:
        cmd = row["command"] or ""
    except (KeyError, TypeError):
        cmd = ""
    return dirs_command_host_header(cmd) or ""


def _paths_group_origin(rows: list) -> str:
    if not rows:
        return ""
    return dirs_origin_url(rows[0]["url"] or "")


def _paths_display_label(origin: str, vhost: str) -> str:
    if not vhost:
        return origin
    parsed = urlparse(origin.rstrip("/") or origin)
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{vhost}/"
    return f"{scheme}://{vhost}:{port}/"


def _paths_report_groups(rows) -> list[tuple[str, list]]:
    """Group dirs jobs by site origin + vhost (IP-direct vs -H scans stay separate)."""
    groups: dict[tuple[str, str], list] = {}
    for row in rows:
        origin = dirs_origin_url(row["url"] or "")
        if not origin:
            continue
        vhost = _paths_row_vhost(row)
        groups.setdefault((origin, vhost), []).append(row)
    return [
        (_paths_display_label(origin, vhost), groups[(origin, vhost)])
        for origin, vhost in sorted(groups.keys(), key=lambda k: (k[0].lower(), k[1].lower()))
    ]


def _service_key_from_scan_url(url: str) -> str:
    """Listener key for merging reboot-chain dirs (scheme + port, not host)."""
    coerced = coerce_web_url((url or "").strip())
    parsed = urlparse(coerced)
    if not parsed.hostname:
        return ""
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get((parsed.scheme or "http").lower(), 80)
    scheme = web_scheme_for_port(port)
    return f"{scheme}:{port}"


def _display_origin_for_service(current_ip: str, service_key: str) -> str:
    _scheme, port_s = service_key.split(":", 1)
    port = int(port_s)
    return dirs_origin_url(build_web_url(current_ip, port, ""))


def _paths_report_groups_case(rows, *, current_ip: str) -> list[tuple[str, list]]:
    """Merge lineage dirs by service + vhost; display roots on the current target IP."""
    groups: dict[tuple[str, str], list] = {}
    for row in rows:
        service_key = _service_key_from_scan_url(row["url"] or "")
        if not service_key:
            continue
        vhost = _paths_row_vhost(row)
        groups.setdefault((service_key, vhost), []).append(row)
    return [
        (
            _paths_display_label(_display_origin_for_service(current_ip, service_key), vhost),
            groups[(service_key, vhost)],
        )
        for service_key, vhost in sorted(groups.keys(), key=lambda k: (k[0], k[1].lower()))
    ]


def _fetch_paths_report_state(ip: str) -> tuple[list, bool]:
    """All dirs + ext-fuzz jobs in recon scope (merged per origin in _print_paths_section)."""
    reconcile_scout_jobs(ip)
    jobs: list = []
    for kind in ("dirs", "ext-fuzz"):
        jobs.extend(_scout_jobs(ip, kind=kind, limit=200))
    running = any(r["status"] == "running" for r in jobs)
    return jobs, running


def _print_paths_section(
    ip: str,
    rows,
    *,
    header: bool = True,
) -> None:
    if header:
        print("--- PATHS ---")
    if not rows:
        print("(none)")
        return

    case = _scout_case()
    if case:
        groups = _paths_report_groups_case(rows, current_ip=ip)
    else:
        groups = _paths_report_groups(rows)
    if not groups:
        print("(none)")
        return

    printed = False
    for origin, origin_rows in groups:
        findings = _merge_job_findings(origin_rows)
        url_running = any(r["status"] == "running" for r in origin_rows)
        if not findings and not url_running:
            continue

        if findings:
            if printed:
                print("")
            for line in format_paths_tree(findings, root_label=origin):
                print(line)
            printed = True
        elif url_running:
            if printed:
                print("")
            print(origin)
            print("  (running)")
            printed = True

    if not printed:
        print("(none)")


def _job_sort_key(row) -> tuple:
    started = row["started_at"] or ""
    return (started, int(row["id"]))


def _select_status_jobs(rows, *, max_finished: int = SCOUT_STATUS_SLOTS) -> list:
    """
    Finished jobs: oldest→newest (recent near bottom), cap at max_finished.
    Running jobs: always last (bottom of screen), oldest→newest among themselves.
    """
    running = [r for r in rows if r["status"] == "running"]
    finished = [r for r in rows if r["status"] != "running"]
    finished.sort(key=_job_sort_key)
    if len(finished) > max_finished:
        finished = finished[-max_finished:]
    running.sort(key=_job_sort_key)
    return finished + running


def _print_scout_job_row(row) -> None:
    job_id = row["id"]
    status = row["status"]
    url = row["url"]
    wl = Path(row["wordlist"] or "").name or "-"
    pid = row["pid"]
    log_path = row["log_path"] or "-"
    started = row["started_at"] or "-"

    line = f"id={job_id}  {status:7}  {url}  wl={wl}"
    if pid:
        line += f"  pid={pid}"
    print(line)
    print(f"         started={started}  log={log_path}")
    print("")


def _print_recon_scope_header(ip: str) -> None:
    from case_scope import bootstrap_lineage_if_needed
    from case_scope import read_lineage
    from case_scope import recon_scope_ips

    if bootstrap_lineage_if_needed(current_ip=ip):
        print("[*] lineage bootstrapped from case history")
    lineage = read_lineage()
    scope = recon_scope_ips(ip)
    if lineage:
        print(f"[*] lineage: {', '.join(lineage)}")
    if scope:
        print(f"[*] recon scope: {', '.join(scope)}")


def show_scout_ports(ip: str) -> int:
    """DB snapshot: OPEN + CLOSED port tables only (no scan, no probes)."""
    from port_sets import FULL_TCP_END
    from port_sets import full_tcp_ports
    from port_sets import nmap_top1000_tcp

    basic_cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
    full_cov = count_tcp_coverage_in_ports(ip, full_tcp_ports())
    progress = f"[*] basic {basic_cov}/1000  full {full_cov}/{FULL_TCP_END}"

    case = _scout_case()
    print("")
    if case:
        print(f"[*] report-ports case {case}  target {ip}")
        _print_recon_scope_header(ip)
        port_lines = format_scan_snapshot_case_lines(case, ip, progress)
    else:
        print(f"[*] report-ports {ip}")
        port_lines = format_scan_snapshot_lines(ip, progress)
    for line in port_lines:
        print(line)
    print("")
    return 0


def show_scout_exploit_pack(ip: str) -> int:
    """Refresh searchsploit + MSF and print AI submission markdown."""
    from scout_exploit_pack import run_exploit_pack

    return run_exploit_pack(ip)


def show_scout_report_exploits(ip: str) -> int:
    """DB snapshot: EXPLOITS section only (no searchsploit)."""
    case = _scout_case()
    print("")
    if case:
        print(f"[*] report-exploits case {case}  target {ip}")
        _print_recon_scope_header(ip)
    else:
        print(f"[*] report-exploits {ip}")
    print("")
    print("--- EXPLOITS ---")
    from scout_exploit import format_exploit_report_lines

    exploit_lines = format_exploit_report_lines(ip)
    for line in exploit_lines:
        print(line)
    print("")
    print("[i] detail: ev <id>  |  scout -se  |  scout -r")
    print("[i] tried & N/A: erj <EDB> [--port 80/tcp]  |  undo: eru <EDB>")
    return 0


def show_scout_report_paths(ip: str) -> int:
    """DB snapshot: PATHS tree only (no gobuster)."""
    if _scout_case():
        from case_scope import bootstrap_lineage_if_needed

        bootstrap_lineage_if_needed(current_ip=ip)
    latest, _running = _fetch_paths_report_state(ip)
    case = _scout_case()
    print("")
    if case:
        print(f"[*] report-paths case {case}  target {ip}")
        _print_recon_scope_header(ip)
    else:
        print(f"[*] report-paths {ip}")
    _print_paths_section(ip, latest)
    print("")
    print("[i] detail: scout -s  |  scout -ws  |  scout -r  |  scout -rtf")
    return 0


def show_scout_report(ip: str) -> int:
    """DB snapshot: ports + scout probes + dirs hits (no nmap/curl/gobuster)."""
    from port_sets import FULL_TCP_END
    from port_sets import full_tcp_ports
    from port_sets import nmap_top1000_tcp

    if _scout_case():
        from case_scope import bootstrap_lineage_if_needed

        bootstrap_lineage_if_needed(current_ip=ip)
    reconcile_scout_jobs(ip)

    basic_cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
    full_cov = count_tcp_coverage_in_ports(ip, full_tcp_ports())
    progress = f"[*] basic {basic_cov}/1000  full {full_cov}/{FULL_TCP_END}"

    case = _scout_case()
    print("========================")
    if case:
        print(f"[SCOUT REPORT] case {case}  target {ip}")
        _print_recon_scope_header(ip)
    else:
        print(f"[SCOUT REPORT] {ip}")
    print("========================")
    print("")
    if case:
        port_lines = format_scan_snapshot_case_lines(case, ip, progress)
    else:
        port_lines = format_scan_snapshot_lines(ip, progress)
    for line in port_lines:
        print(line)
    print("")

    print("--- OS ---")
    from scout_os import format_os_report_lines

    for line in format_os_report_lines(ip):
        print(line)
    print("")

    print("--- PROBES ---")
    execs = _fetch_scout_executions(ip)
    if not execs:
        print("(none)")
    else:
        for row in execs:
            exec_id = row["id"]
            task_type = row["task_type"] or "-"
            status = row["status"] or "-"
            exit_code = row["exit_code"]
            code = "-" if exit_code is None else str(exit_code)
            hint = _probe_stdout_hint(row["stdout"] or "")
            print(f"ev {exec_id}  {task_type}  {status}  exit={code}  {hint}")
            print(f"         $ {row['command']}")
    print("")

    print("--- TASKS ---")
    from task_run import format_task_report_lines

    for line in format_task_report_lines(ip):
        print(line)
    print("")

    latest, _running = _fetch_paths_report_state(ip)
    _print_paths_section(ip, latest)
    print("")
    print("--- HINTS ---")
    from hints import format_hint_report_lines
    from hints import hint_scope_optional

    case = hint_scope_optional()
    if case:
        for line in format_hint_report_lines(case):
            print(line)
    else:
        print("(none — cases set <room> to attach hints)")
    print("")
    print("--- EXPLOITS ---")
    from scout_exploit import format_exploit_report_lines

    exploit_lines = format_exploit_report_lines(ip)
    for line in exploit_lines:
        print(line)
    print("")
    print("[i] detail: ev <id>  |  scout -s  |  scout -se  |  scout -re  |  scout -rt")
    print("[i] tasks: strike -l  |  strike")
    print("[i] hints: ha <text>  |  hl  |  hr <id>")
    print("[i] tried & N/A: erj <EDB>  |  undo: eru <EDB>")
    return 0


def show_scout_status(
    ip: str,
    *,
    wait_dirs: bool = False,
    interval_sec: float = DEFAULT_WATCH_INTERVAL_SEC,
) -> int:
    interval_sec = max(0.5, float(interval_sec))

    try:
        while True:
            if wait_dirs and sys.stdout.isatty():
                print("\033[2J\033[H", end="")

            reconcile_scout_jobs(ip)
            all_rows = _scout_jobs(ip, limit=200)
            running_total = sum(1 for r in all_rows if r["status"] == "running")
            rows = _select_status_jobs(all_rows)

            print("========================")
            case = _scout_case()
            if case:
                print(f"[SCOUT STATUS] case {case}  target {ip}")
            else:
                print(f"[SCOUT STATUS] {ip}")
            if wait_dirs:
                print(f"[*] -ws ({interval_sec:g}s) — Ctrl+C to stop")
            print("========================")

            if not all_rows:
                print("(no scout jobs)")
                return 0

            finished_total = len(all_rows) - running_total
            finished_shown = sum(1 for r in rows if r["status"] != "running")
            hidden = max(0, finished_total - finished_shown)
            line = f"jobs: {len(rows)} shown ({running_total} running)"
            if hidden:
                line += f", {hidden} older hidden"
            print(line)
            print("")

            for row in rows:
                _print_scout_job_row(row)

            if case:
                from case_scope import bootstrap_lineage_if_needed

                bootstrap_lineage_if_needed(current_ip=ip)
            paths_rows, _ = _fetch_paths_report_state(ip)
            _print_paths_section(ip, paths_rows)
            print("")

            if wait_dirs:
                sys.stdout.flush()

            if not wait_dirs or running_total == 0:
                if wait_dirs and running_total == 0:
                    print("[*] all dirs jobs finished")
                return 0

            time.sleep(interval_sec)
    except KeyboardInterrupt:
        print("\n[*] wait-dirs stopped")
        return 0


def _auto_wait_dirs(ip: str, *, dry_run: bool = False) -> int:
    """After scout dispatch, watch dirs until running jobs reach zero."""
    if dry_run:
        return 0
    reconcile_scout_jobs(ip)
    if not _scout_jobs(ip, limit=1):
        return 0
    print("")
    print("[*] dirs watch (-ws) — Ctrl+C to stop")
    return show_scout_status(ip, wait_dirs=True)


def run_scout(
    ip: str,
    *,
    force_scan: bool = False,
    force_dirs: bool = False,
    dry_run: bool = False,
    quiet_ports: bool = False,
    full_ports: bool = False,
    scan_jobs: int = 1,
    dirs_only: bool = False,
    dirs_multi: bool = False,
    dirs_preset: str = "standard",
    dirs_multi_preset_from_flag: bool = False,
    dirs_multi_preset_is_next: bool = False,
    dirs_urls: Optional[list[str]] = None,
    wordlist: Optional[str] = None,
    wordlists: Optional[list[str]] = None,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
    host_header: Optional[str] = None,
    user_agent: Optional[str] = None,
    cookie: Optional[str] = None,
    no_plan: bool = False,
    dirs_ext_fuzz: bool = False,
    ext_fuzz_wordlist: Optional[str] = None,
    quick_scan: bool = False,
    save_scan: bool = False,
):
    upsert_host(ip, status="up")

    if full_ports and (dirs_only or dirs_multi):
        print("[-] use -fp or -d/-ds, not both")
        return 1

    if full_ports:
        full_output_base = None
        if save_scan:
            full_output_base = (
                "logs/full-ports-quick" if quick_scan else "logs/full-ports"
            )
        print("========================")
        case = _scout_case()
        if case:
            print(f"[SCOUT] case {case}  target {ip}  (full port scan)")
        else:
            print(f"[SCOUT] {ip}  (full port scan)")
        print("========================")

        skip_scan = False
        if not force_scan and not dry_run and is_profile_coverage_complete(
            ip, PROFILE_FULL, quick=quick_scan
        ):
            label = "quick " if quick_scan else ""
            print(
                f"[*] {label}full port scan skipped (TCP 1-65535 already complete on {ip})"
            )
            print("[i] use scout -fp --force to rescan")
            skip_scan = True
        else:
            if quick_scan:
                print("[*] port scan (full TCP 1-65535, quick -sS)")
            else:
                print("[*] port scan (full TCP 1-65535, -sC -sV)")
            if scan_jobs > 1:
                print(f"[*] parallel workers: {scan_jobs}")
        print("")

        if skip_scan:
            return 0
        scan_rc = run_scan(
            ip,
            profile=PROFILE_FULL,
            force=force_scan,
            dry_run=dry_run,
            quiet_ports=quiet_ports,
            jobs=scan_jobs,
            quick=quick_scan,
            output_base=full_output_base,
        )
        if scan_rc != 0:
            return scan_rc

        if quick_scan:
            return 0

        from scout_exploit import run_exploit_phase

        return run_exploit_phase(ip, dry_run=dry_run, force=not dry_run)

    if dirs_only or dirs_multi:
        from scout_ext_fuzz import has_ext_wildcard_suffix
        from scout_ext_fuzz import has_trailing_slash
        from scout_ext_fuzz import is_ext_fuzz_request

        if dirs_urls:
            from scout_ext_fuzz import has_ext_fuzz_marker

            for u in dirs_urls:
                if has_ext_wildcard_suffix(u) and not dirs_ext_fuzz:
                    print(
                        f"[!] {u}: path ends with .* — use -dx for extension fuzz"
                        " (otherwise treated as a literal path)"
                    )
                elif (
                    has_ext_fuzz_marker(u)
                    and not dirs_ext_fuzz
                    and not has_trailing_slash(u)
                ):
                    print(
                        f"[!] {u}: .FUZZ marker — use -dx for extension fuzz"
                        " (append / to enumerate a literal script.FUZZ dir)"
                    )
                elif has_ext_fuzz_marker(u) and not dirs_ext_fuzz:
                    print(
                        f"[i] {u}: literal directory (trailing / disables .FUZZ marker)"
                    )
            ext_urls = [
                u for u in dirs_urls if is_ext_fuzz_request(u, dx=dirs_ext_fuzz)
            ]
            dir_urls = [
                u for u in dirs_urls if not is_ext_fuzz_request(u, dx=dirs_ext_fuzz)
            ]
            if ext_urls and (dirs_multi or extensions is not None):
                print("[-] file extension fuzz (ffuf) uses -dx only")
                print("[i] omit -ds / -x — optional: -w <ext-fuzz catalog id>")
                return 1
            if ext_urls:
                if not resolve_dirs_targets(ip, urls=ext_urls, host_header=host_header):
                    print("[-] no Web targets in DB — run scout first, or pass a URL")
                    return 1
                rc = _run_ext_fuzz_phase(
                    ip,
                    urls=ext_urls,
                    wordlist=ext_fuzz_wordlist or wordlist,
                    threads=threads,
                    host_header=host_header,
                    user_agent=user_agent,
                    dry_run=dry_run,
                    force=force_dirs,
                    dx=dirs_ext_fuzz,
                )
                if dir_urls:
                    rc2 = _run_dirs_phase(
                        ip,
                        urls=dir_urls,
                        wordlist=wordlist,
                        wordlists=wordlists,
                        dirs_multi=dirs_multi,
                        dirs_preset=dirs_preset,
                        dirs_multi_preset_from_flag=dirs_multi_preset_from_flag,
                        dirs_multi_preset_is_next=dirs_multi_preset_is_next,
                        threads=threads,
                        extensions=extensions,
                        host_header=host_header,
                        user_agent=user_agent,
                        cookie=cookie,
                        dry_run=dry_run,
                        force=force_dirs,
                    )
                    rc = max(rc, rc2)
                wait_rc = _auto_wait_dirs(ip, dry_run=dry_run)
                return max(rc, wait_rc)

        if not resolve_dirs_targets(ip, urls=dirs_urls, host_header=host_header):
            print("[-] no Web targets in DB — run scout first, or pass a URL")
            return 1
        rc = _run_dirs_phase(
            ip,
            urls=dirs_urls,
            wordlist=wordlist,
            wordlists=wordlists,
            dirs_multi=dirs_multi,
            dirs_preset=dirs_preset,
            dirs_multi_preset_from_flag=dirs_multi_preset_from_flag,
            dirs_multi_preset_is_next=dirs_multi_preset_is_next,
            threads=threads,
            extensions=extensions,
            host_header=host_header,
            user_agent=user_agent,
            cookie=cookie,
            dry_run=dry_run,
            force=force_dirs,
        )
        wait_rc = _auto_wait_dirs(ip, dry_run=dry_run)
        return max(rc, wait_rc)

    print("========================")
    case = _scout_case()
    if case:
        print(f"[SCOUT] case {case}  target {ip}")
    else:
        print(f"[SCOUT] {ip}")
    print("========================")

    scan_profile = PROFILE_BASIC
    skip_scan = False
    if not force_scan and not dry_run:
        if is_profile_coverage_complete(ip, scan_profile, quick=quick_scan):
            label = "quick " if quick_scan else ""
            print(f"[*] phase 1: {label}port scan skipped (top 1000 already complete on {ip})")
            print("[i] use scout --force to rescan this target")
            skip_scan = True
        elif not quick_scan and case and case_has_basic_scan(case, current_ip=ip):
            print("[*] phase 1: port scan skipped (case already has basic scan on a prior IP)")
            print("[i] use scout --force to rescan this target")
            skip_scan = True

    if not skip_scan:
        if quick_scan:
            print("[*] phase 1: port scan (top 1000, quick -sS)")
        else:
            print("[*] phase 1: port scan (top 1000, -sC -sV)")
        sys.stdout.flush()
    print("")

    if skip_scan:
        rc = 0
    else:
        basic_output_base = None
        if save_scan and not quick_scan:
            basic_output_base = "logs/ports"
        rc = run_scan(
            ip,
            profile=scan_profile,
            force=force_scan,
            dry_run=dry_run,
            quiet_ports=quiet_ports,
            jobs=1,
            quick=quick_scan,
            output_base=basic_output_base,
        )
        if rc != 0:
            return rc

    if quick_scan:
        from scan_run import _print_quick_hint

        _print_quick_hint()
        return 0

    from scout_os import run_os_detect_phase

    os_rc = run_os_detect_phase(ip, dry_run=dry_run, force=force_scan)
    if os_rc != 0:
        return os_rc

    rc = _run_probe_phase(ip, dry_run=dry_run)
    if rc != 0:
        return rc

    from task_run import run_task_plan_phase

    if not no_plan:
        plan_rc = run_task_plan_phase(ip, dry_run=dry_run)
        if plan_rc != 0:
            return plan_rc

    from scout_exploit import run_exploit_phase

    exploit_rc = run_exploit_phase(ip, dry_run=dry_run)
    if exploit_rc != 0:
        return exploit_rc

    dirs_rc = _run_dirs_phase(
        ip,
        urls=dirs_urls,
        wordlist=wordlist,
        threads=threads,
        extensions=extensions,
        host_header=host_header,
        user_agent=user_agent,
        cookie=cookie,
        dry_run=dry_run,
        force=force_dirs,
    )
    wait_rc = _auto_wait_dirs(ip, dry_run=dry_run)
    return max(rc, exploit_rc, dirs_rc, wait_rc)
