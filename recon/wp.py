"""WordPress assessment CLI."""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import urljoin
from urllib.parse import urlparse
from urllib.request import Request
from urllib.request import urlopen


DEFAULT_TIMEOUT = 15
WPSCAN_TIMEOUT = 20 * 60

WP_USAGE = """usage: wp <command> [options]

Commands:
  assess   Execute pre-attack WordPress reconnaissance

Run 'wp <command> --help' for command-specific help.
"""

ASSESS_USAGE = """usage: wp assess [--fast|--full] [--use-api] [--out DIR] <URL>

Modes:
  default  normal
  --fast   lightweight checks only
  --full   expanded exposure checks

Options:
  --use-api   use WPSCAN_API_TOKEN with WPScan
  --out DIR   write the report to DIR

Output:
  default output directory is CASE_HOME/exports or ./exports
  WPScan logs go to the sibling logs/ directory
  report filename is wp_assess_<host>_<path>_<mode>_<api>.md

Notes:
  - URL must be a WordPress base path, e.g. http://target/wordpress/
  - WordPress discovery tools are not run here
"""


@dataclass(slots=True)
class HttpCheck:
    path: str
    status: str
    method: str = "GET"


@dataclass(slots=True)
class Finding:
    name: str
    version: str = ""
    latest_version: str = ""
    confidence: str = ""
    version_confidence: str = ""
    location: str = ""
    status: str = ""
    outdated: bool = False
    is_main_theme: bool = False
    found_by: list[str] = field(default_factory=list)
    vulnerabilities: list["VulnerabilityFinding"] = field(default_factory=list)


@dataclass(slots=True)
class VulnerabilityFinding:
    title: str
    cves: list[str] = field(default_factory=list)
    edb_ids: list[str] = field(default_factory=list)
    fixed_in: str = ""
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InterestingFinding:
    kind: str
    title: str
    url: str = ""
    status: str = ""
    confidence: str = ""
    found_by: list[str] = field(default_factory=list)
    entries: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VulnApiInfo:
    used: bool = False
    plan: str = ""
    requests_used: str = ""
    requests_remaining: str = ""


@dataclass(slots=True)
class XmlRpcAssessment:
    get_check: HttpCheck
    post_check: HttpCheck
    state: str
    evidence: str


@dataclass(slots=True)
class UserFinding:
    username: str
    confidence: str = ""
    found_by: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WpScanResult:
    raw: dict[str, Any]
    version: str = ""
    version_confidence: str = ""
    version_status: str = ""
    version_release_date: str = ""
    version_vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    plugins: list[Finding] = field(default_factory=list)
    themes: list[Finding] = field(default_factory=list)
    main_theme: Finding | None = None
    users: list[UserFinding] = field(default_factory=list)
    interesting_findings: list[InterestingFinding] = field(default_factory=list)
    vuln_api: VulnApiInfo = field(default_factory=VulnApiInfo)
    detected: bool = False


@dataclass(slots=True)
class AssessResult:
    target_url: str
    mode: str
    use_api: bool
    wordpress_detected: bool
    login_page: str
    wp_json: str
    xmlrpc: str
    xmlrpc_http_status: str
    xmlrpc_evidence: str
    version: str
    plugins: list[Finding]
    themes: list[Finding]
    users: list[UserFinding]
    http_checks: list[HttpCheck]
    exposure_checks: list[HttpCheck]
    next_actions: list[str]
    report_path: Path
    errors: list[str]
    xmlrpc_get_status: str = ""
    xmlrpc_post_status: str = ""
    xmlrpc_get_evidence: str = ""
    xmlrpc_post_evidence: str = ""
    version_status: str = ""
    version_release_date: str = ""
    version_confidence: str = ""
    version_vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    interesting_findings: list[InterestingFinding] = field(default_factory=list)
    vuln_api: VulnApiInfo = field(default_factory=VulnApiInfo)
    warnings: list[str] = field(default_factory=list)


class AssessError(Exception):
    pass


def normalize_target_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise AssessError("target URL is required")
    if not value.startswith(("http://", "https://")):
        value = f"http://{value}"

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise AssessError(f"invalid URL: {raw}")
    if not parsed.path or parsed.path == "/":
        raise AssessError(
            "WordPress base URL must include a path, for example /wordpress/ or /blog/"
        )

    path = parsed.path if parsed.path.endswith("/") else f"{parsed.path}/"
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc}{path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    return normalized


def _default_assess_out_dir() -> Path:
    case_home = os.environ.get("CASE_HOME", "").strip()
    if case_home:
        return Path(case_home) / "exports"
    return Path.cwd() / "exports"


def _assess_report_name(target_url: str, mode: str, use_api: bool) -> str:
    parsed = urlparse(target_url)
    host = _slugify(parsed.hostname or parsed.netloc or "target")
    path = _slugify((parsed.path or "/").strip("/"), fallback="root")
    api_state = "api-on" if use_api else "api-off"
    return f"wp_assess_{host}_{path}_{mode}_{api_state}.md"


def _assess_report_path(out_dir: Path, target_url: str, mode: str, use_api: bool) -> Path:
    return out_dir / _assess_report_name(target_url, mode, use_api)


def parse_args(argv: list[str]) -> dict[str, Any]:
    mode = "normal"
    use_api = False
    out_dir = _default_assess_out_dir()
    target = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            raise AssessError(ASSESS_USAGE)
        if arg == "--fast":
            if mode == "full":
                raise AssessError("--fast and --full are mutually exclusive")
            mode = "fast"
            i += 1
            continue
        if arg == "--full":
            if mode == "fast":
                raise AssessError("--fast and --full are mutually exclusive")
            mode = "full"
            i += 1
            continue
        if arg == "--use-api":
            use_api = True
            i += 1
            continue
        if arg == "--out":
            if i + 1 >= len(argv):
                raise AssessError("--out requires a directory")
            out_dir = Path(argv[i + 1])
            i += 2
            continue
        if arg.startswith("-"):
            raise AssessError(f"unknown option: {arg}")
        if target is not None:
            raise AssessError(f"unexpected extra argument: {arg}")
        target = arg
        i += 1
    if not target:
        raise AssessError(ASSESS_USAGE)
    return {"mode": mode, "use_api": use_api, "out_dir": out_dir, "target": target}


def request_url(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> int | None:
    req = Request(url, method="GET", headers={"User-Agent": "wp-assess/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            try:
                resp.read(512)
            except Exception:
                pass
            return int(getattr(resp, "status", resp.getcode()))
    except HTTPError as exc:
        try:
            exc.read(128)
        except Exception:
            pass
        return int(exc.code)
    except (URLError, TimeoutError, OSError):
        return None


def fetch_url(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int | None, str]:
    req_headers = {"User-Agent": "wp-assess/1.0"}
    if headers:
        req_headers.update(headers)
    req = Request(url, data=data, method=method, headers=req_headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            try:
                body = resp.read(2048).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return int(getattr(resp, "status", resp.getcode())), body
    except HTTPError as exc:
        try:
            body = exc.read(2048).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return int(exc.code), body
    except (URLError, TimeoutError, OSError):
        return None, ""


def probe_path(base_url: str, path: str) -> HttpCheck:
    url = urljoin(base_url, path)
    status = request_url(url)
    return HttpCheck(path=path, status=str(status) if status is not None else "unreachable")


def probe_xmlrpc(base_url: str) -> XmlRpcAssessment:
    xmlrpc_url = urljoin(base_url, "xmlrpc.php")
    get_status, _ = fetch_url(xmlrpc_url, method="GET", timeout=DEFAULT_TIMEOUT)
    body = (
        "<?xml version=\"1.0\"?>"
        "<methodCall>"
        "<methodName>system.listMethods</methodName>"
        "<params/>"
        "</methodCall>"
    ).encode("utf-8")
    post_status, response = fetch_url(
        xmlrpc_url,
        method="POST",
        data=body,
        headers={"Content-Type": "text/xml"},
        timeout=DEFAULT_TIMEOUT,
    )
    get_http_status = str(get_status) if get_status is not None else "unreachable"
    post_http_status = str(post_status) if post_status is not None else "unreachable"
    normalized = response.lower()
    if post_status is None or post_status in (404, 410):
        state = "disabled"
        evidence = "xmlrpc.php returned 404/410 or was unreachable"
    elif post_status == 405:
        state = "not confirmed"
        evidence = "POST was rejected with 405"
    elif post_status in (401, 403):
        if "<methodresponse" in normalized or "<fault>" in normalized or "xml-rpc" in normalized:
            state = "reachable"
            evidence = "XML-RPC style response was returned"
        else:
            state = "not confirmed"
            evidence = "endpoint exists but confirmation is incomplete"
    elif post_status == 200:
        if "<methodresponse" in normalized or "<fault>" in normalized or "xml-rpc" in normalized:
            state = "reachable"
            evidence = "XML-RPC response markers were returned"
        else:
            state = "not confirmed"
            evidence = "200 response did not confirm XML-RPC behavior"
    elif re.search(r"xmlrpc|xml-rpc", normalized):
        state = "reachable"
        evidence = "XML-RPC markers were present in the response body"
    else:
        state = "not confirmed"
        evidence = "response did not confirm XML-RPC behavior"
    return XmlRpcAssessment(
        get_check=HttpCheck(method="GET", path="xmlrpc.php", status=get_http_status),
        post_check=HttpCheck(method="POST", path="xmlrpc.php", status=post_http_status),
        state=state,
        evidence=evidence,
    )


def _slugify(value: str, *, fallback: str = "target") -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", (value or "").strip())
    slug = slug.strip("_")
    return slug or fallback


VULN_PRIORITY_KEYWORDS = (
    "RCE",
    "SQL INJECTION",
    "PRIVILEGE ESCALATION",
    "LFI",
    "FILE UPLOAD",
    "PATH TRAVERSAL",
    "DIRECTORY TRAVERSAL",
    "SSRF",
    "XSS",
)

INTERESTING_PRIORITY = {
    "upload_directory_listing": 70,
    "wp_cron": 25,
    "readme": 20,
    "license": 20,
    "xmlrpc": 40,
}


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _stringify_values(value: Any) -> list[str]:
    items: list[str] = []
    if isinstance(value, str):
        text = value.strip()
        if text:
            items.append(text)
        return items
    if isinstance(value, (int, float, bool)):
        items.append(str(value))
        return items
    if isinstance(value, dict):
        for key in ("cve", "cves", "edb", "edbs", "exploitdb", "url", "urls", "reference", "references"):
            if key not in value:
                continue
            items.extend(_stringify_values(value[key]))
        return items
    if isinstance(value, (list, tuple, set)):
        for item in value:
            items.extend(_stringify_values(item))
    return items


def _string_list(value: Any) -> list[str]:
    return _dedupe_text(_stringify_values(value))


def _collect_from_mapping(value: Any, keys: tuple[str, ...]) -> list[str]:
    if not isinstance(value, dict):
        return _string_list(value)
    items: list[str] = []
    for key in keys:
        items.extend(_string_list(value.get(key)))
    return _dedupe_text(items)


def _pick_first_text(value: Any, keys: tuple[str, ...]) -> str:
    if not isinstance(value, dict):
        return ""
    for key in keys:
        candidate = value.get(key)
        text = _to_text(candidate)
        if text:
            return text
    return ""


def _extract_found_by(value: Any) -> list[str]:
    if isinstance(value, dict):
        for key in ("found_by", "foundby", "source", "sources"):
            if key in value:
                return _string_list(value.get(key))
        return []
    return _string_list(value)


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "outdated"}
    return False


def _wpscan_signature(
    base_url: str,
    mode: str,
    use_api: bool,
    *,
    api_token: str = "",
) -> dict[str, str]:
    enumerate_map = {
        "fast": "vp,vt",
        "normal": "vp,vt,u",
        "full": "vp,vt,u,cb,dbe",
    }
    signature: dict[str, str] = {
        "url": base_url,
        "mode": mode,
        "enumerate": enumerate_map[mode],
        "plugins_detection": "aggressive" if mode in ("normal", "full") else "default",
        "api": "1" if use_api else "0",
    }
    if use_api:
        signature["api_token_sha256"] = hashlib.sha256(api_token.encode("utf-8")).hexdigest()
    return signature


def _signature_hash(signature: dict[str, str]) -> str:
    payload = json.dumps(signature, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def _wpscan_raw_path(base_url: str, mode: str, use_api: bool, log_dir: Path, *, api_token: str = "") -> Path:
    parsed = urlparse(base_url)
    host = _slugify(parsed.hostname or parsed.netloc or "target")
    path = _slugify((parsed.path or "/").strip("/"), fallback="root")
    sig = _signature_hash(_wpscan_signature(base_url, mode, use_api, api_token=api_token))
    return log_dir / f"wpscan_{host}_{path}_{mode}_{sig}.json"


def run_wpscan(
    base_url: str,
    mode: str,
    use_api: bool,
    *,
    log_dir: Path,
) -> tuple[dict[str, Any], list[str]]:
    api_token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
    if use_api and not api_token:
        raise AssessError("--use-api was specified but WPSCAN_API_TOKEN is not set")

    signature = _wpscan_signature(base_url, mode, use_api, api_token=api_token)
    cmd = [
        "wpscan",
        "--url",
        base_url,
        "--enumerate",
        signature["enumerate"],
        "--random-user-agent",
    ]
    if signature["plugins_detection"] == "aggressive":
        cmd.extend(["--plugins-detection", "aggressive"])
    if use_api:
        cmd.extend(["--api-token", api_token])
    log_dir.mkdir(parents=True, exist_ok=True)
    raw_log_path = _wpscan_raw_path(base_url, mode, use_api, log_dir, api_token=api_token)
    cmd.extend(["--format", "json", "--output", str(raw_log_path)])
    child_env = os.environ.copy()
    if not use_api:
        child_env.pop("WPSCAN_API_TOKEN", None)

    errors: list[str] = []
    completed = None
    cache_is_valid = False
    if raw_log_path.is_file():
        cached_text = raw_log_path.read_text(encoding="utf-8", errors="replace").strip()
        cached_payload = _parse_json_payload(cached_text) if cached_text else {}
        if cached_payload and not _payload_is_aborted(cached_payload):
            cache_is_valid = True
        else:
            raw_log_path.unlink(missing_ok=True)
    if not cache_is_valid:
        print(f"[*] running WPScan signature: {raw_log_path.name}", flush=True)
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=WPSCAN_TIMEOUT,
                check=False,
                env=child_env,
            )
        except FileNotFoundError as exc:
            raise AssessError("wpscan not found in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise AssessError("wpscan timed out") from exc
    else:
        print(f"[*] reusing WPScan log: {raw_log_path}", flush=True)

    if completed is not None and completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        if stderr:
            errors.append(stderr)
        if stdout and stdout not in errors:
                errors.append(stdout)

    payload: dict[str, Any] = {}
    raw_text = ""
    if raw_log_path.is_file():
        raw_text = raw_log_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw_text and completed is not None:
        raw_text = (completed.stdout or "").strip()
        if raw_text:
            raw_log_path.write_text(raw_text, encoding="utf-8")

    if raw_text:
        payload = _parse_json_payload(raw_text)
    if _payload_is_aborted(payload):
        errors.append(str(payload["scan_aborted"]))
    if not payload and completed is not None and completed.returncode != 0:
        raise AssessError("wpscan failed and no JSON output was produced")
    return payload, errors


def _parse_json_payload(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    first = text.find("{")
    last = text.rfind("}")
    if first >= 0 and last > first:
        try:
            data = json.loads(text[first : last + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {}


def _payload_is_aborted(payload: dict[str, Any]) -> bool:
    return bool(payload.get("scan_aborted"))


def _version_from_value(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("number", "version", "value", "display", "string"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip()
    return ""


def _extract_vulnerabilities(section: Any) -> list[VulnerabilityFinding]:
    items: list[VulnerabilityFinding] = []
    if isinstance(section, dict):
        iterable = section.values()
    elif isinstance(section, list):
        iterable = section
    else:
        return items

    for value in iterable:
        if not isinstance(value, dict):
            continue
        title = _pick_first_text(value, ("title", "name", "slug")) or "Unknown vulnerability"
        fixed_in = _pick_first_text(value, ("fixed_in", "fixed", "fixed_version", "fixed_version_string"))
        cves = _collect_from_mapping(value, ("cve", "cves"))
        edb_ids = _collect_from_mapping(value, ("edb", "edbs", "exploitdb", "exploitdb_ids"))
        references: list[str] = []
        for candidate in (
            value.get("references"),
            value.get("reference"),
            value.get("references_urls"),
            value.get("url"),
            value.get("urls"),
        ):
            references.extend(_string_list(candidate))
        items.append(
            VulnerabilityFinding(
                title=title,
                cves=cves,
                edb_ids=edb_ids,
                fixed_in=fixed_in,
                references=_dedupe_text(references),
            )
        )
    return _dedupe_vulnerabilities(items)


def _dedupe_vulnerabilities(items: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    seen: set[tuple[str, tuple[str, ...], tuple[str, ...], str]] = set()
    unique: list[VulnerabilityFinding] = []
    for item in items:
        key = (item.title, tuple(item.cves), tuple(item.edb_ids), item.fixed_in)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _extract_findings(section: Any) -> list[Finding]:
    items: list[Finding] = []
    if isinstance(section, dict):
        iterable = section.items()
    elif isinstance(section, list):
        iterable = enumerate(section)
    else:
        return items

    for key, value in iterable:
        if not isinstance(value, dict):
            continue
        name = ""
        for candidate in ("slug", "name", "title"):
            candidate_value = value.get(candidate)
            if isinstance(candidate_value, str) and candidate_value.strip():
                name = candidate_value.strip()
                break
        if not name:
            name = str(key)
        version_value = value.get("version")
        version = _version_from_value(version_value)
        latest_version = _version_from_value(value.get("latest_version") or value.get("latest"))
        confidence = _pick_first_text(value, ("confidence",))
        version_confidence = _pick_first_text(version_value, ("confidence",)) if isinstance(version_value, dict) else ""
        location = _pick_first_text(value, ("location", "url", "path"))
        status = _pick_first_text(value, ("status",))
        outdated = _parse_bool(value.get("outdated"))
        found_by = _extract_found_by(value)
        vulnerabilities = _extract_vulnerabilities(value.get("vulnerabilities"))
        items.append(
            Finding(
                name=name,
                version=version,
                latest_version=latest_version,
                confidence=confidence,
                version_confidence=version_confidence,
                location=location,
                status=status,
                outdated=outdated,
                vulnerabilities=vulnerabilities,
                found_by=found_by,
            )
        )
    return _dedupe_findings(items)


def _extract_users(section: Any) -> list[UserFinding]:
    users: list[UserFinding] = []
    if isinstance(section, dict):
        iterable = section.items()
    elif isinstance(section, list):
        iterable = enumerate(section)
    else:
        return users

    for key, value in iterable:
        username = ""
        confidence = ""
        found_by: list[str] = []
        if isinstance(value, dict):
            for candidate in ("username", "login", "name", "slug"):
                candidate_value = value.get(candidate)
                if isinstance(candidate_value, str) and candidate_value.strip():
                    username = candidate_value.strip()
                    break
            confidence = _pick_first_text(value, ("confidence",))
            found_by = _extract_found_by(value)
        elif isinstance(value, str):
            username = value.strip()
        if not username:
            username = str(key)
        users.append(UserFinding(username=username, confidence=confidence, found_by=found_by))
    seen: set[str] = set()
    unique: list[UserFinding] = []
    for user in users:
        if user.username in seen:
            continue
        seen.add(user.username)
        unique.append(user)
    return unique


def _extract_main_theme(section: Any) -> Finding | None:
    if not isinstance(section, dict):
        return None
    name = _pick_first_text(section, ("slug", "name", "title"))
    if not name:
        return None
    version_value = section.get("version")
    return Finding(
        name=name,
        version=_version_from_value(version_value),
        version_confidence=_pick_first_text(version_value, ("confidence",)) if isinstance(version_value, dict) else "",
        confidence=_pick_first_text(section, ("confidence",)),
        latest_version=_version_from_value(section.get("latest_version") or section.get("latest")),
        location=_pick_first_text(section, ("location", "url", "path")),
        status=_pick_first_text(section, ("status",)),
        outdated=_parse_bool(section.get("outdated")),
        is_main_theme=True,
        found_by=_extract_found_by(section),
        vulnerabilities=_extract_vulnerabilities(section.get("vulnerabilities")),
    )


def _extract_interesting_findings(section: Any) -> list[InterestingFinding]:
    findings: list[InterestingFinding] = []
    if isinstance(section, dict):
        iterable = section.items()
    elif isinstance(section, list):
        iterable = enumerate(section)
    else:
        return findings

    for key, value in iterable:
        if isinstance(value, dict):
            kind = _pick_first_text(value, ("type", "kind", "name")) or str(key)
            title = _pick_first_text(value, ("to_s", "title", "description", "value"))
            url = _pick_first_text(value, ("url", "uri", "location"))
            status = _pick_first_text(value, ("status",))
            confidence = _pick_first_text(value, ("confidence",))
            found_by = _extract_found_by(value)
            entries: list[str] = []
            for candidate in (value.get("interesting_entries"), value.get("entries"), value.get("data")):
                if isinstance(candidate, dict):
                    for entry_key, entry_value in candidate.items():
                        text = _to_text(entry_value)
                        if text:
                            entries.append(f"{entry_key}: {text}")
                else:
                    entries.extend(_string_list(candidate))
            if not title:
                if kind == "upload_directory_listing":
                    title = "uploads directory listing"
                elif kind == "wp_cron":
                    title = "WP-Cron enabled"
                elif kind == "readme":
                    title = "readme.html"
                elif kind == "license":
                    title = "license.txt"
                elif kind == "xmlrpc":
                    title = "XML-RPC"
                elif kind == "headers":
                    title = "Server Information"
                elif url:
                    title = f"{kind}: {url}"
                else:
                    title = kind
            if kind == "readme":
                title = "readme.html"
            elif kind == "license":
                title = "license.txt"
            findings.append(
                InterestingFinding(
                    kind=kind,
                    title=title,
                    url=url,
                    status=status,
                    confidence=confidence,
                    found_by=found_by,
                    entries=_dedupe_text(entries),
                )
            )
        elif isinstance(value, str):
            text = value.strip()
            if text:
                findings.append(
                    InterestingFinding(
                        kind=str(key),
                        title=text,
                    )
                )
    return findings


def _extract_vuln_api(section: Any) -> VulnApiInfo:
    if not isinstance(section, dict):
        return VulnApiInfo()
    used = any(_parse_bool(section.get(candidate)) for candidate in ("used", "enabled", "present"))
    return VulnApiInfo(
        used=used,
        plan=_pick_first_text(section, ("plan", "tier", "type")),
        requests_used=_pick_first_text(section, ("requests_used", "used", "requests")),
        requests_remaining=_pick_first_text(section, ("requests_remaining", "remaining", "left")),
    )


def _dedupe_findings(items: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for item in items:
        key = (item.name, item.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def parse_wpscan_result(payload: dict[str, Any]) -> WpScanResult:
    raw_version = payload.get("version")
    version = ""
    version_confidence = ""
    version_status = ""
    version_release_date = ""
    version_vulnerabilities: list[VulnerabilityFinding] = []
    if isinstance(raw_version, dict):
        version = _version_from_value(raw_version)
        version_confidence = _pick_first_text(raw_version, ("confidence",))
        version_status = _pick_first_text(raw_version, ("status",))
        version_release_date = _pick_first_text(raw_version, ("release_date", "released_at", "released"))
        version_vulnerabilities = _extract_vulnerabilities(raw_version.get("vulnerabilities"))
    elif isinstance(raw_version, str):
        version = raw_version.strip()
    if not version_status and version_vulnerabilities:
        version_status = "insecure"

    plugins = _extract_findings(payload.get("plugins"))
    themes = _extract_findings(payload.get("themes"))
    main_theme = _extract_main_theme(payload.get("main_theme"))
    if main_theme and all(theme.name != main_theme.name or theme.version != main_theme.version for theme in themes):
        themes.append(main_theme)
    users = _extract_users(payload.get("users"))
    interesting_findings = _extract_interesting_findings(payload.get("interesting_findings"))
    vuln_api = _extract_vuln_api(payload.get("vuln_api"))

    detected = bool(
        version
        or version_vulnerabilities
        or plugins
        or themes
        or users
        or interesting_findings
        or vuln_api.used
    )
    return WpScanResult(
        raw=payload,
        version=version,
        version_confidence=version_confidence,
        version_status=version_status,
        version_release_date=version_release_date,
        version_vulnerabilities=version_vulnerabilities,
        plugins=plugins,
        themes=themes,
        main_theme=main_theme,
        users=users,
        interesting_findings=interesting_findings,
        vuln_api=vuln_api,
        detected=detected,
    )


def build_http_checks(mode: str, base_url: str, *, xmlrpc_assessment: XmlRpcAssessment | None = None) -> list[HttpCheck]:
    checks = [
        probe_path(base_url, ""),
        probe_path(base_url, "wp-login.php"),
        probe_path(base_url, "wp-json"),
    ]
    if mode in ("normal", "full"):
        if xmlrpc_assessment is None:
            xmlrpc_assessment = probe_xmlrpc(base_url)
        checks.extend(
            [
                xmlrpc_assessment.get_check,
                xmlrpc_assessment.post_check,
                probe_path(base_url, "readme.html"),
                probe_path(base_url, "license.txt"),
            ]
        )
    if mode == "full":
        checks.extend(
            [
                probe_path(base_url, "wp-content/backups/"),
                probe_path(base_url, "wp-content/debug.log"),
                probe_path(base_url, "wp-content/error_log"),
                probe_path(base_url, "wp-config.php.bak"),
                probe_path(base_url, "wp-config.php.old"),
                probe_path(base_url, "wp-config.php.save"),
                probe_path(base_url, "wp-admin/install.php"),
                probe_path(base_url, "wp-admin/upgrade.php"),
                probe_path(base_url, "wp-content/uploads/"),
            ]
        )
    return checks


def build_exposure_checks(mode: str, http_checks: list[HttpCheck]) -> list[HttpCheck]:
    exposure_paths = {
        "readme.html",
        "license.txt",
    }
    if mode == "full":
        exposure_paths.update(
            {
                "wp-content/backups/",
                "wp-content/debug.log",
                "wp-content/error_log",
                "wp-config.php.bak",
                "wp-config.php.old",
                "wp-config.php.save",
                "wp-admin/install.php",
                "wp-admin/upgrade.php",
                "wp-content/uploads/",
            }
        )
    by_path = {check.path: check for check in http_checks}
    return [by_path[path] for path in sorted(exposure_paths) if path in by_path]


def is_exposed_status(status: str) -> bool:
    return status not in {"404", "410", "unreachable"}


def _sort_vulnerabilities(vulnerabilities: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    return sorted(
        vulnerabilities,
        key=lambda vulnerability: (
            -int(bool(vulnerability.cves)),
            -int(bool(vulnerability.edb_ids)),
            -_vulnerability_priority_bonus(vulnerability.title),
            vulnerability.title,
        ),
    )


def _format_vulnerability_evidence(vulnerability: VulnerabilityFinding) -> list[str]:
    evidence = [vulnerability.title]
    if vulnerability.cves:
        evidence.append(f"CVE: {', '.join(vulnerability.cves)}")
    if vulnerability.edb_ids:
        evidence.append(f"ExploitDB: {', '.join(vulnerability.edb_ids)}")
    if vulnerability.fixed_in:
        evidence.append(f"Fixed in: {vulnerability.fixed_in}")
    return evidence


def build_wordpress_version_assessment(result: AssessResult) -> list[str]:
    if not result.version:
        return [
            "Version: not confirmed",
            "Assessment:",
            "- WordPress version was not confidently identified",
            "Confidence: Low",
            "Source: HTTP verification",
            "Score: 0",
        ]
    lines = [f"Version: {result.version}"]
    if result.version_status:
        lines.append(f"Status: {result.version_status}")
    if result.version_release_date:
        lines.append(f"Release date: {result.version_release_date}")
    lines.append("Assessment:")
    if not result.use_api:
        lines.append("- Version disclosure confirmed")
        lines.append("- Outdated release")
        lines.append("- Exploit research candidate")
    elif result.version_vulnerabilities:
        lines.append("- Known vulnerabilities were found")
        lines.append("- WordPress core investigation candidate")
    else:
        lines.append("- Version disclosure confirmed")
        lines.append("- WordPress core investigation candidate")
    lines.append("Confidence: High")
    lines.append("Source: WPScan")
    lines.append(f"Score: {_score_version_vulnerabilities(result.version_vulnerabilities)}")
    if result.version_vulnerabilities:
        lines.append("Vulnerabilities:")
        for vulnerability in _sort_vulnerabilities(result.version_vulnerabilities)[:10]:
            lines.append(f"- {vulnerability.title}")
            if vulnerability.cves:
                lines.append(f"  - CVE: {', '.join(vulnerability.cves)}")
            if vulnerability.edb_ids:
                lines.append(f"  - ExploitDB: {', '.join(vulnerability.edb_ids)}")
            if vulnerability.fixed_in:
                lines.append(f"  - Fixed in: {vulnerability.fixed_in}")
        if len(result.version_vulnerabilities) > 10:
            lines.append(f"... and {len(result.version_vulnerabilities) - 10} more")
    return lines


def build_vulnerabilities_section(result: AssessResult) -> list[str]:
    lines: list[str] = []
    if not (result.use_api and result.vuln_api.used):
        lines.append("Status: Not Available")
        lines.append("Reason:")
        lines.append("- WPScan vulnerability database was not used")
        lines.append("- Only locally observable findings are included")
        lines.append("")
        return lines
    if result.version_vulnerabilities:
        lines.append("### WordPress Core")
        for vulnerability in _sort_vulnerabilities(result.version_vulnerabilities)[:10]:
            lines.append(f"- {vulnerability.title}")
            if vulnerability.cves:
                lines.append(f"  - CVE: {', '.join(vulnerability.cves)}")
            if vulnerability.edb_ids:
                lines.append(f"  - ExploitDB: {', '.join(vulnerability.edb_ids)}")
            if vulnerability.fixed_in:
                lines.append(f"  - Fixed in: {vulnerability.fixed_in}")
        if len(result.version_vulnerabilities) > 10:
            lines.append(f"... and {len(result.version_vulnerabilities) - 10} more")
        lines.append("")

    plugin_vulnerabilities = [
        (plugin, vulnerability)
        for plugin in result.plugins
        for vulnerability in plugin.vulnerabilities
    ]
    if plugin_vulnerabilities:
        lines.append("### Plugins")
        for plugin in result.plugins:
            if not plugin.vulnerabilities:
                continue
            lines.append(f"- {plugin.name}{f' {plugin.version}' if plugin.version else ''}")
            for vulnerability in _sort_vulnerabilities(plugin.vulnerabilities):
                lines.append(f"  - {vulnerability.title}")
                if vulnerability.cves:
                    lines.append(f"    - CVE: {', '.join(vulnerability.cves)}")
                if vulnerability.edb_ids:
                    lines.append(f"    - ExploitDB: {', '.join(vulnerability.edb_ids)}")
                if vulnerability.fixed_in:
                    lines.append(f"    - Fixed in: {vulnerability.fixed_in}")
        lines.append("")

    theme_vulnerabilities = [
        (theme, vulnerability)
        for theme in result.themes
        for vulnerability in theme.vulnerabilities
    ]
    if theme_vulnerabilities:
        lines.append("### Themes")
        for theme in result.themes:
            if not theme.vulnerabilities:
                continue
            lines.append(f"- {theme.name}{f' {theme.version}' if theme.version else ''}")
            for vulnerability in _sort_vulnerabilities(theme.vulnerabilities):
                lines.append(f"  - {vulnerability.title}")
                if vulnerability.cves:
                    lines.append(f"    - CVE: {', '.join(vulnerability.cves)}")
                if vulnerability.edb_ids:
                    lines.append(f"    - ExploitDB: {', '.join(vulnerability.edb_ids)}")
                if vulnerability.fixed_in:
                    lines.append(f"    - Fixed in: {vulnerability.fixed_in}")
        lines.append("")

    return lines


def build_server_information(result: AssessResult) -> list[str]:
    lines: list[str] = []
    for finding in result.interesting_findings:
        if finding.kind.lower() != "headers":
            continue
        if finding.entries:
            lines.extend(_dedupe_text(finding.entries))
        elif finding.title:
            lines.append(finding.title)
        if finding.found_by:
            lines.extend(f"Source: {_format_found_by_label(item)}" for item in finding.found_by if _format_found_by_label(item))
    return _dedupe_text(lines)


def build_plugin_assessment(plugins: list[Finding]) -> list[str]:
    if not plugins:
        return ["Plugin: none detected", "Assessment:", "- No plugin target was identified from the current sweep"]
    lines: list[str] = []
    for plugin in plugins:
        label = plugin.name if not plugin.version else f"{plugin.name} {plugin.version}"
        lines.append(f"Plugin: {label}")
        lines.append("Assessment:")
        lines.append("- High-priority attack surface candidate")
        lines.append("- Plugins are often a primary attack path")
        lines.append("")
    return lines


def build_exposure_assessment(result: AssessResult) -> list[ExposureEntry]:
    assessments: list[ExposureEntry] = []
    seen: set[str] = set()

    def add_entry(path: str, score: int, reason: str, confidence: str, source: str, evidence_url: str = "") -> None:
        key = path.lower().strip()
        if key in seen:
            return
        seen.add(key)
        assessments.append(
            ExposureEntry(
                path=path,
                score=score,
                reason=reason,
                confidence=confidence,
                source=source,
                evidence_url=evidence_url,
            )
        )

    for finding in result.interesting_findings:
        kind = finding.kind.lower()
        if kind not in {"readme", "license", "upload_directory_listing", "wp_cron"}:
            continue
        path = _canonical_interesting_title(finding)
        reason = {
            "readme": "Supplementary WordPress information disclosure",
            "license": "Version inference support",
            "upload_directory_listing": "Potential exposure of uploaded files",
            "wp_cron": "Publicly reachable endpoint",
        }[kind]
        add_entry(
            path,
            30 if kind == "wp_cron" else _score_interesting_finding(finding),
            reason,
            "Medium" if kind == "wp_cron" else "High",
            "WPScan",
            finding.url or urljoin(result.target_url, path),
        )

    for check in result.exposure_checks:
        if not is_exposed_status(check.status):
            continue
        path = {
            "readme.html": "readme.html",
            "license.txt": "license.txt",
            "wp-content/uploads/": "uploads directory listing",
            "wp-content/backups/": "wp-content/backups/",
            "wp-content/debug.log": "wp-content/debug.log",
            "wp-content/error_log": "wp-content/error_log",
            "wp-config.php.bak": "wp-config.php.bak",
            "wp-config.php.old": "wp-config.php.old",
            "wp-config.php.save": "wp-config.php.save",
            "wp-admin/install.php": "wp-admin/install.php",
            "wp-admin/upgrade.php": "wp-admin/upgrade.php",
        }.get(check.path, check.path)
        if path.lower() in seen:
            continue
        reason = {
            "readme.html": "Potential WordPress information disclosure",
            "license.txt": "Version inference support",
            "wp-content/backups/": "Potential backup exposure",
            "wp-content/debug.log": "Potential debug log exposure",
            "wp-content/error_log": "Potential error log exposure",
            "wp-config.php.bak": "Potential configuration backup exposure",
            "wp-config.php.old": "Potential configuration backup exposure",
            "wp-config.php.save": "Potential configuration backup exposure",
            "wp-admin/install.php": "Potential initialization or reconfiguration entry point",
            "wp-admin/upgrade.php": "Potential upgrade flow entry point",
            "uploads directory listing": "Potential uploaded file exposure",
        }.get(check.path, "Exposure candidate")
        confidence = "Low" if check.path in {"readme.html", "license.txt", "wp-content/uploads/"} else "Medium"
        add_entry(
            path,
            _score_exposure(check.path),
            reason,
            confidence,
            "HTTP verification",
            urljoin(result.target_url, check.path),
        )

    assessments.sort(key=lambda entry: (-entry.score, entry.path))
    return assessments


def summarize_key_findings(result: AssessResult) -> dict[str, list[str]]:
    critical: list[str] = []
    high: list[str] = []
    medium: list[str] = []
    low: list[str] = []
    informational: list[str] = []

    for score, title in build_top_targets(result):
        if score >= 90:
            critical.append(title)
        elif score >= 70:
            high.append(title)
        elif score >= 40:
            medium.append(title)
        elif score > 0:
            low.append(title)
        else:
            informational.append(title)

    return {"Critical": critical, "High": high, "Medium": medium, "Low": low, "Informational": informational}


def _vulnerability_severity(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def _vulnerability_category(title: str) -> str:
    title_upper = title.upper()
    if "SQL INJECTION" in title_upper or "SQLI" in title_upper:
        return "SQL Injection"
    if "XSS" in title_upper:
        return "XSS"
    if "ARBITRARY FILE DELETION" in title_upper:
        return "Arbitrary File Deletion"
    if "OBJECT INJECTION" in title_upper:
        return "Object Injection"
    if "OPEN REDIRECT" in title_upper:
        return "Open Redirect"
    if "CSRF" in title_upper or "CROSS SITE REQUEST FORGERY" in title_upper:
        return "CSRF"
    if "PRIVILEGE ESCALATION" in title_upper:
        return "Privilege Escalation"
    if "SSRF" in title_upper:
        return "SSRF"
    if "DIRECTORY TRAVERSAL" in title_upper:
        return "Directory Traversal"
    if "PATH TRAVERSAL" in title_upper:
        return "Path Traversal"
    if "FILE UPLOAD" in title_upper:
        return "File Upload"
    if "LFI" in title_upper or "LOCAL FILE INCLUDE" in title_upper or "LOCAL FILE INCLUSION" in title_upper:
        return "LFI"
    if "AUTHENTICATION BYPASS" in title_upper or "AUTH BYPASS" in title_upper:
        return "Authentication Bypass"
    if "INFORMATION DISCLOSURE" in title_upper:
        return "Information Disclosure"
    if "RCE" in title_upper or "REMOTE CODE EXECUTION" in title_upper:
        return "RCE"
    return "Other"


def _vulnerability_label(prefix: str, vulnerability: VulnerabilityFinding) -> str:
    if prefix:
        return f"{prefix} - {vulnerability.title}"
    return vulnerability.title


def _vulnerability_summary_severity(vulnerability: VulnerabilityFinding) -> str:
    category = _vulnerability_category(vulnerability.title)
    if category in {"RCE", "SQL Injection", "LFI", "Authentication Bypass", "File Upload", "Privilege Escalation"}:
        return "Critical"
    if category in {"SSRF", "Directory Traversal", "Path Traversal", "Object Injection", "Arbitrary File Deletion"}:
        return "High"
    if category in {"Information Disclosure", "CSRF", "Open Redirect"}:
        return "Medium"
    return "Low" if category in {"XSS", "Other"} else "Low"


CORE_VULN_PRIORITY = {
    "RCE": 1,
    "SQL Injection": 1,
    "LFI": 1,
    "File Upload": 1,
    "Authentication Bypass": 1,
    "Privilege Escalation": 1,
    "SSRF": 2,
    "Directory Traversal": 2,
    "Path Traversal": 2,
    "Arbitrary File Deletion": 2,
    "Object Injection": 2,
    "Information Disclosure": 3,
    "Open Redirect": 3,
    "CSRF": 3,
    "XSS": 4,
    "Other": 5,
}


def _core_vulnerability_priority(category: str) -> int:
    return CORE_VULN_PRIORITY.get(category, 5)


def _group_core_vulnerabilities(result: AssessResult) -> dict[str, list[VulnerabilityFinding]]:
    grouped: dict[str, list[VulnerabilityFinding]] = {}
    for vulnerability in result.version_vulnerabilities:
        category = _vulnerability_category(vulnerability.title)
        grouped.setdefault(category, []).append(vulnerability)
    return grouped


def _representative_vulnerability(vulnerabilities: list[VulnerabilityFinding]) -> VulnerabilityFinding:
    return sorted(
        vulnerabilities,
        key=lambda vulnerability: (
            -int(bool(vulnerability.cves)),
            -int(bool(vulnerability.edb_ids)),
            -_vulnerability_priority_bonus(vulnerability.title),
            vulnerability.title,
        ),
    )[0]


def build_vulnerability_summary(result: AssessResult) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {"Critical": [], "High": [], "Medium": [], "Low": []}
    core_groups = _group_core_vulnerabilities(result)
    core_order = sorted(core_groups, key=lambda category: (_core_vulnerability_priority(category), category))
    for category in core_order:
        vulnerabilities = core_groups[category]
        representative = _representative_vulnerability(vulnerabilities)
        label = f"WordPress Core - {category}"
        if len(vulnerabilities) > 1:
            label = f"{label} ({len(vulnerabilities)} findings)"
        buckets[_vulnerability_summary_severity(representative)].append(label)

    plugin_entries: list[tuple[int, str, str]] = []
    for plugin in result.plugins:
        for vulnerability in plugin.vulnerabilities:
            plugin_entries.append((_score_vulnerability_finding(vulnerability), _format_plugin_label(plugin), vulnerability.title))

    plugin_entries.sort(key=lambda item: (-item[0], item[2]))
    for _score, prefix, title in plugin_entries[:10]:
        buckets[_vulnerability_summary_severity(VulnerabilityFinding(title=title))].append(
            _vulnerability_label(prefix, VulnerabilityFinding(title=title))
        )
    return buckets


def build_core_vulnerability_groups(result: AssessResult) -> dict[str, int]:
    grouped = _group_core_vulnerabilities(result)
    return {key: len(value) for key, value in grouped.items() if value}


def build_next_actions(result: AssessResult) -> list[str]:
    actions: list[str] = [title for _, title, _ in build_top_target_rows(result)[:3]]
    if not actions:
        actions.append("No clear target identified")
    return actions


@dataclass(slots=True)
class TargetEntry:
    title: str
    score: int
    evidence: list[str]
    why: list[str] = field(default_factory=list)
    suggested_investigation: list[str] = field(default_factory=list)
    evidence_url: str = ""
    confidence: str = ""
    source: str = ""
    found_by: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExposureEntry:
    path: str
    score: int
    reason: str
    confidence: str
    source: str
    evidence_url: str = ""


def _dedupe_text(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _canonical_interesting_title(finding: InterestingFinding) -> str:
    kind = finding.kind.lower()
    if kind == "readme":
        return "readme.html"
    if kind == "license":
        return "license.txt"
    if kind == "upload_directory_listing":
        return "uploads directory listing"
    if kind == "wp_cron":
        return "WP-Cron"
    return finding.title


def _interesting_kind_present(result: AssessResult, kind: str) -> bool:
    return any(finding.kind.lower() == kind for finding in result.interesting_findings)


def _xmlrpc_wpscan_detected(result: AssessResult) -> bool:
    return _interesting_kind_present(result, "xmlrpc")


def _xmlrpc_effective_state(result: AssessResult) -> str:
    http_state = result.xmlrpc or "not checked"
    if _xmlrpc_wpscan_detected(result):
        if not result.use_api:
            return "unknown"
        if http_state in {"skipped", "not checked", "unknown"}:
            return "unknown"
        if http_state in {"disabled", "unreachable"}:
            return "conflicting"
        return "enabled"
    return http_state


def _format_plugin_label(plugin: Finding) -> str:
    return plugin.name if not plugin.version else f"{plugin.name} {plugin.version}"


def _format_theme_label(theme: Finding) -> str:
    return theme.name if not theme.version else f"{theme.name} {theme.version}"


def _format_vulnerability_label(vulnerability: VulnerabilityFinding) -> str:
    return vulnerability.title


def _normalize_version_display(version: str) -> str:
    return version or "not confirmed"


def _theme_is_outdated(theme: Finding) -> bool:
    if theme.outdated:
        return True
    if theme.version and theme.latest_version and theme.version != theme.latest_version:
        return True
    return False


def _vulnerability_priority_bonus(title: str) -> int:
    title_upper = title.upper()
    return 30 if any(keyword in title_upper for keyword in VULN_PRIORITY_KEYWORDS) else 0


def _score_vulnerability_finding(vulnerability: VulnerabilityFinding) -> int:
    score = 40
    if vulnerability.cves:
        score += 35
    if vulnerability.edb_ids:
        score += 10
    score += _vulnerability_priority_bonus(vulnerability.title)
    return min(score, 100)


def _score_version_vulnerabilities(vulnerabilities: list[VulnerabilityFinding]) -> int:
    if vulnerabilities:
        return 80
    return 70


def _score_wordpress_version(version: str) -> int:
    return 50 if version else 0


def _score_plugin(plugin: Finding) -> int:
    if not plugin.name:
        return 0
    return 100 if plugin.vulnerabilities else 55


def _score_theme(theme: Finding) -> int:
    if not theme.name:
        return 0
    if theme.vulnerabilities:
        return 95
    return 60 if _theme_is_outdated(theme) or theme.is_main_theme else 55


def _score_user(user: UserFinding) -> int:
    return 65 if user.username else 0


def _score_xmlrpc(result: AssessResult) -> int:
    state = _xmlrpc_effective_state(result)
    if state in {"reachable", "enabled"}:
        return 40
    if state == "conflicting":
        return 30
    if state in {"unknown", "not confirmed"}:
        return 20
    return 0


def _score_interesting_finding(finding: InterestingFinding) -> int:
    kind = finding.kind.lower()
    if kind == "upload_directory_listing":
        return 70
    if kind == "wp_cron":
        return 25
    if kind in {"readme", "license"}:
        return 20
    if kind == "headers":
        return 10
    if kind == "xmlrpc":
        return 40
    return INTERESTING_PRIORITY.get(kind, 0)


def _score_exposure(path: str) -> int:
    if path in {"readme.html", "license.txt"}:
        return 20
    if path in {"wp-content/backups/", "wp-content/debug.log", "wp-content/error_log", "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save", "wp-content/uploads/"}:
        return 35
    if path in {"wp-admin/install.php", "wp-admin/upgrade.php"}:
        return 25
    return 15


def _score_version(result: AssessResult) -> int:
    if not result.version:
        return 0
    if result.use_api and result.vuln_api.used and result.version_vulnerabilities:
        return 80
    return 70


def _score_plugin_entry(result: AssessResult, plugin: Finding) -> int:
    if not plugin.name:
        return 0
    if result.use_api and result.vuln_api.used and plugin.vulnerabilities:
        return 100
    return 55


def _score_theme_entry(result: AssessResult, theme: Finding) -> int:
    if not theme.name:
        return 0
    if result.use_api and result.vuln_api.used and theme.vulnerabilities:
        return 95
    return 60 if _theme_is_outdated(theme) or theme.is_main_theme else 55


def _normalize_confidence_label(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered in {"high", "medium", "low"}:
        return lowered.capitalize()
    if text.isdigit():
        number = int(text)
        if number >= 75:
            return "High"
        if number >= 40:
            return "Medium"
        return "Low"
    return "Low"


def _format_confidence(value: str) -> str:
    normalized = _normalize_confidence_label(value)
    return normalized or "Low"


def _confidence_output(value: str) -> str:
    text = (value or "").strip()
    return text


def _format_found_by_label(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    normalized = text.replace("_", " ").strip()
    if normalized.lower() == "headers":
        return "Headers (Passive Detection)"
    if normalized.lower() == "direct access":
        return "Direct Access (Aggressive Detection)"
    if normalized.lower() in {"css style in homepage", "css style homepage"}:
        return "Css Style In Homepage (Passive Detection)"
    return normalized[:1].upper() + normalized[1:]


def _found_by_lines(values: list[str]) -> list[str]:
    lines: list[str] = []
    for value in _dedupe_text(values):
        label = _format_found_by_label(value)
        if label:
            lines.append(label)
    return lines


def _confidence_from_evidence(*, title: str, evidence: list[str], source: str, kind: str = "") -> str:
    evidence_text = " ".join(evidence).lower()
    title_text = title.lower()
    kind_text = kind.lower()
    source_text = source.lower()

    if title_text == "xml-rpc":
        if source_text == "wpscan":
            return "Low"
        if kind_text in {"reachable", "enabled", "conflicting"} or "http verification" in source_text:
            return "Medium"
        return "Low"

    if "version:" in evidence_text or "username:" in evidence_text or "location:" in evidence_text:
        return "High"
    if "directory listing" in title_text or "uploads" in title_text:
        return "High"
    if "state:" in evidence_text or "status:" in evidence_text:
        return "Medium"
    if source_text == "wpscan":
        return "Low"
    if kind_text in {"readme", "license"}:
        return "Medium"
    return "Medium"


def _top_target_priority(title: str) -> int:
    normalized = title.lower().strip()
    if normalized.startswith("vulnerable plugin:") or normalized.startswith("plugin:"):
        return 0
    if normalized.startswith("wordpress ") or normalized.startswith("wordpress version:") or normalized.startswith("vulnerable wordpress core"):
        return 1
    if "uploads directory listing" in normalized or normalized in {"readme.html", "license.txt", "wp-cron"} or "backup" in normalized or "debug log" in normalized or "error log" in normalized or normalized == "xml-rpc":
        return 2
    if normalized.startswith("user:") or normalized == "elyana":
        return 3
    if normalized.startswith("outdated theme:") or normalized.startswith("theme:"):
        return 4
    return 5


def _suggested_investigation_for_title(title: str) -> list[str]:
    normalized = title.lower().strip()
    if normalized.startswith("wordpress "):
        return ["Review version-related exposure"]
    if normalized.startswith("user:"):
        return ["Review user exposure"]
    if normalized.startswith("theme:") or normalized.startswith("outdated theme:"):
        return ["Review theme files"]
    if "uploads directory listing" in normalized:
        return ["Review exposed files"]
    if normalized == "xml-rpc":
        return ["Review XML-RPC behavior"]
    if normalized == "wp-cron":
        return ["Review WP-Cron exposure"]
    if normalized in {"readme.html", "license.txt"}:
        return ["Review exposed content"]
    return ["Review exposed content"]


def build_top_targets(result: AssessResult) -> list[tuple[int, str]]:
    return [(score, title) for score, title, _ in build_top_target_rows(result)]


def _vulnerability_reason_summary(vulnerabilities: list[VulnerabilityFinding]) -> str:
    reasons: list[str] = []
    title_text = " ".join(vulnerability.title.upper() for vulnerability in vulnerabilities)
    for keyword, label in (
        ("RCE", "RCE"),
        ("SQL INJECTION", "SQLi"),
        ("SQLI", "SQLi"),
        ("LFI", "LFI"),
        ("LOCAL FILE INCLUSION", "LFI"),
        ("FILE UPLOAD", "File Upload"),
        ("PATH TRAVERSAL", "Path Traversal"),
        ("DIRECTORY TRAVERSAL", "Directory Traversal"),
        ("PRIVILEGE ESCALATION", "Privilege Escalation"),
        ("SSRF", "SSRF"),
        ("XSS", "XSS"),
        ("INFORMATION DISCLOSURE", "Info Disclosure"),
    ):
        if keyword in title_text:
            reasons.append(label)
    if not reasons:
        return "Known vulnerabilities"
    return ", ".join(_dedupe_text(reasons))


def build_top_target_rows(result: AssessResult) -> list[tuple[int, str, str]]:
    rows: list[tuple[int, str, str]] = []
    seen_titles: set[str] = set()
    interesting_kinds = {finding.kind.lower() for finding in result.interesting_findings}

    def add_row(score: int, title: str, reason: str) -> None:
        key = title.lower().strip()
        if key in seen_titles:
            return
        seen_titles.add(key)
        rows.append((score, title, reason))

    for plugin in result.plugins:
        title = f"{plugin.name}{f' {plugin.version}' if plugin.version else ''}"
        score = _score_plugin_entry(result, plugin)
        reason = _vulnerability_reason_summary(plugin.vulnerabilities) if result.use_api and result.vuln_api.used and plugin.vulnerabilities else "Plugin detected"
        add_row(score, title, reason)

    for theme in result.themes:
        if not _theme_is_outdated(theme) and not theme.is_main_theme and not theme.vulnerabilities:
            continue
        title = f"{theme.name}{f' {theme.version}' if theme.version else ''}"
        reason = (
            _vulnerability_reason_summary(theme.vulnerabilities)
            if result.use_api and result.vuln_api.used and theme.vulnerabilities
            else "Outdated theme"
            if _theme_is_outdated(theme)
            else "Theme"
        )
        add_row(_score_theme_entry(result, theme), f"Theme: {title}", reason)

    if result.version:
        add_row(
            _score_version(result),
            f"WordPress {result.version}",
            _vulnerability_reason_summary(result.version_vulnerabilities) if result.use_api and result.vuln_api.used and result.version_vulnerabilities else "Version disclosure",
        )

    for user in result.users:
        add_row(_score_user(user), f"User: {user.username}", "User enumeration")

    xmlrpc_score = _score_xmlrpc(result)
    if xmlrpc_score > 0 or _xmlrpc_wpscan_detected(result):
        add_row(xmlrpc_score, "XML-RPC", "xmlrpc.php exposed")

    for finding in result.interesting_findings:
        score = _score_interesting_finding(finding)
        if not score or finding.kind.lower() == "headers":
            continue
        if finding.kind.lower() == "xmlrpc":
            continue
        reason = {
            "upload_directory_listing": "Directory listing enabled",
            "wp_cron": "External WP-Cron",
            "readme": "readme.html exposed",
            "license": "license.txt exposed",
            "xmlrpc": "xmlrpc.php exposed",
        }.get(finding.kind.lower(), finding.title)
        title = _canonical_interesting_title(finding)
        add_row(score, title, reason)

    for check in result.exposure_checks:
        if not is_exposed_status(check.status):
            continue
        if check.path == "readme.html" and "readme" in interesting_kinds:
            continue
        if check.path == "license.txt" and "license" in interesting_kinds:
            continue
        if check.path == "wp-content/uploads/" and "upload_directory_listing" in interesting_kinds:
            continue
        title = {
            "readme.html": "readme.html",
            "license.txt": "license.txt",
            "wp-content/uploads/": "uploads directory listing",
            "wp-content/backups/": "backups directory",
            "wp-content/debug.log": "debug log",
            "wp-content/error_log": "error log",
            "wp-config.php.bak": "wp-config backup",
            "wp-config.php.old": "wp-config backup",
            "wp-config.php.save": "wp-config backup",
            "wp-admin/install.php": "install.php",
            "wp-admin/upgrade.php": "upgrade.php",
        }.get(check.path, check.path)
        add_row(_score_exposure(check.path), title, "Exposed file")

    rows.sort(key=lambda item: (-item[0], _top_target_priority(item[1]), item[1]))
    return rows


def build_attack_surface(result: AssessResult) -> list[TargetEntry]:
    entries: list[TargetEntry] = []
    seen_titles: set[str] = set()

    def add_entry(entry: TargetEntry) -> None:
        key = entry.title.lower().strip()
        if key in seen_titles:
            return
        seen_titles.add(key)
        entries.append(entry)

    for plugin in result.plugins:
        title = f"Plugin: {_format_plugin_label(plugin)}"
        evidence = [f"Version: {_normalize_version_display(plugin.version)}"]
        if plugin.latest_version:
            evidence.append(f"Latest version: {plugin.latest_version}")
        if plugin.location:
            evidence.append(f"Location: {plugin.location}")
        evidence_url = plugin.location or urljoin(result.target_url, f"wp-content/plugins/{_slugify(plugin.name, fallback='plugin')}/")
        if result.use_api and result.vuln_api.used and plugin.vulnerabilities:
            for vulnerability in plugin.vulnerabilities:
                evidence.append(_format_vulnerability_label(vulnerability))
                if vulnerability.cves:
                    evidence.append(f"CVE: {', '.join(vulnerability.cves)}")
                if vulnerability.edb_ids:
                    evidence.append(f"ExploitDB: {', '.join(vulnerability.edb_ids)}")
        add_entry(
            TargetEntry(
                title=title,
                score=_score_plugin_entry(result, plugin),
                evidence=evidence + ([f"URL: {evidence_url}"] if evidence_url else []),
                evidence_url=evidence_url,
                confidence=plugin.confidence or plugin.version_confidence,
                found_by=_found_by_lines(plugin.found_by),
            )
        )

    for theme in result.themes:
        if not _theme_is_outdated(theme) and not theme.vulnerabilities and not theme.is_main_theme:
            continue
        title = f"Theme: {_format_theme_label(theme)}"
        evidence = [f"Version: {_normalize_version_display(theme.version)}"]
        if theme.latest_version:
            evidence.append(f"Latest version: {theme.latest_version}")
        if theme.location:
            evidence.append(f"Location: {theme.location}")
        evidence.append(f"Outdated: {'true' if _theme_is_outdated(theme) else 'false'}")
        evidence_url = theme.location or urljoin(result.target_url, f"wp-content/themes/{_slugify(theme.name, fallback='theme')}/")
        add_entry(
            TargetEntry(
                title=title,
                score=_score_theme_entry(result, theme),
                evidence=evidence,
                evidence_url=evidence_url,
                confidence=theme.confidence or theme.version_confidence,
                found_by=_found_by_lines(theme.found_by),
            )
        )

    if result.version:
        evidence = [f"Version: {result.version}"]
        if result.version_status:
            evidence.append(f"Status: {result.version_status}")
        if result.version_release_date:
            evidence.append(f"Release date: {result.version_release_date}")
        if result.use_api and result.vuln_api.used and result.version_vulnerabilities:
            total_core = len(result.version_vulnerabilities)
            evidence.append(f"Core vulnerabilities: {total_core}")
            breakdown = build_core_vulnerability_groups(result)
            evidence.append("Breakdown:")
            for category in (
                "SQL Injection",
                "RCE",
                "File Upload",
                "Privilege Escalation",
                "Authentication Bypass",
                "SSRF",
                "Directory Traversal",
                "Path Traversal",
                "Arbitrary File Deletion",
                "Object Injection",
                "Open Redirect",
                "CSRF",
                "XSS",
                "Information Disclosure",
                "Other",
            ):
                count = breakdown.get(category)
                if count:
                    evidence.append(f"- {category}: {count}")
        add_entry(
            TargetEntry(
                title=f"WordPress {result.version}",
                score=_score_version(result),
                evidence=evidence + ([f"URL: {result.target_url}"] if result.target_url else []),
                evidence_url=result.target_url,
                confidence=result.version_confidence,
            )
        )

    for user in result.users:
        add_entry(
            TargetEntry(
                title=f"User: {user.username}",
                score=_score_user(user),
                evidence=[f"Username: {user.username}"],
                evidence_url=urljoin(result.target_url, "wp-login.php"),
                confidence=user.confidence,
                found_by=_found_by_lines(user.found_by),
            )
        )

    xmlrpc_finding = next((finding for finding in result.interesting_findings if finding.kind.lower() == "xmlrpc"), None)
    xmlrpc_score = _score_xmlrpc(result)
    if xmlrpc_score > 0 or xmlrpc_finding is not None:
        evidence = [f"URL: {urljoin(result.target_url, 'xmlrpc.php')}"]
        add_entry(
            TargetEntry(
                title="XML-RPC",
                score=xmlrpc_score,
                evidence=evidence,
                evidence_url=urljoin(result.target_url, "xmlrpc.php"),
                confidence=xmlrpc_finding.confidence if xmlrpc_finding else "",
                found_by=_found_by_lines(xmlrpc_finding.found_by) if xmlrpc_finding else [],
            )
        )

    for finding in result.interesting_findings:
        score = _score_interesting_finding(finding)
        if not score:
            continue
        if finding.kind.lower() in {"headers", "xmlrpc"}:
            continue
        title = finding.title
        evidence = []
        if finding.url:
            evidence.append(f"URL: {finding.url}")
        if finding.status:
            evidence.append(f"Status: {finding.status}")
        if finding.entries:
            evidence.extend(finding.entries)
        add_entry(
            TargetEntry(
                title=_canonical_interesting_title(finding),
                score=score,
                evidence=(evidence or [f"Kind: {finding.kind}"]) + ([f"URL: {finding.url}"] if finding.url else []),
                evidence_url=(
                    finding.url
                    or (
                        urljoin(result.target_url, "wp-content/uploads/")
                        if finding.kind.lower() == "upload_directory_listing"
                        else urljoin(result.target_url, "readme.html")
                        if finding.kind.lower() == "readme"
                        else urljoin(result.target_url, "license.txt")
                        if finding.kind.lower() == "license"
                        else urljoin(result.target_url, "xmlrpc.php")
                        if finding.kind.lower() == "xmlrpc"
                        else ""
                    )
                ),
                confidence=finding.confidence,
                found_by=_found_by_lines(finding.found_by),
            )
        )

    for check in result.exposure_checks:
        if not is_exposed_status(check.status):
            continue
        if check.path == "xmlrpc.php":
            continue
        add_entry(
            TargetEntry(
                title=check.path,
                score=_score_exposure(check.path),
                evidence=[f"HTTP status: {check.status}", f"URL: {urljoin(result.target_url, check.path)}"],
                evidence_url=urljoin(result.target_url, check.path),
                confidence=check.confidence,
            )
        )

    entries.sort(key=lambda entry: (-entry.score, _top_target_priority(entry.title), entry.title))
    return entries


def render_markdown(result: AssessResult) -> str:
    lines: list[str] = []
    attack_surface = build_attack_surface(result)
    top_rows = build_top_target_rows(result)
    lines.append("# WordPress Assessment Report")
    lines.append("")
    lines.append("## Target")
    lines.append(f"- URL: `{result.target_url}`")
    lines.append(f"- Mode: `{result.mode}`")
    lines.append(f"- WPScan API requested: `{ 'yes' if result.use_api else 'no' }`")
    lines.append(f"- WPScan API used: `{ 'yes' if result.vuln_api.used else 'no' }`")
    lines.append("- Primary Source: `WPScan`")
    if result.vuln_api.used:
        if result.vuln_api.plan:
            lines.append(f"- WPScan API plan: `{result.vuln_api.plan}`")
        if result.vuln_api.requests_used:
            lines.append(f"- WPScan API requests used: `{result.vuln_api.requests_used}`")
        if result.vuln_api.requests_remaining:
            lines.append(f"- WPScan API requests remaining: `{result.vuln_api.requests_remaining}`")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- WordPress detected: `{ 'yes' if result.wordpress_detected else 'no' }`")
    lines.append(f"- Users found: `{len(result.users)}`")
    lines.append(f"- Plugins found: `{len(result.plugins)}`")
    lines.append(f"- Themes found: `{len(result.themes)}`")
    lines.append(f"- WordPress version: `{result.version or 'not confirmed'}`")
    lines.append(f"- Attack Surface Count: `{len(attack_surface)}`")
    lines.append(f"- Verification: `{ 'executed' if result.http_checks else 'skipped' }`")
    lines.append("")
    lines.append("## Report Mode")
    if result.vuln_api.used:
        lines.append("Mode: Vulnerability correlation")
        lines.append("Vulnerability correlation: Available")
        lines.append("Risk scoring basis: Known vulnerabilities + observable attack surface")
    else:
        lines.append("Mode: Enumeration-only")
        lines.append("Vulnerability correlation: Not Available")
        lines.append("Risk scoring basis: Observable attack surface")
    lines.append("")
    lines.append("## Assessment")
    overall_risk = "Low"
    if top_rows:
        top_score = top_rows[0][0]
        if top_score >= 90:
            overall_risk = "Critical"
        elif top_score >= 70:
            overall_risk = "High"
        elif top_score >= 40:
            overall_risk = "Medium"
    lines.append(f"Overall Risk: {overall_risk}")
    if top_rows:
        primary_target = top_rows[0][1]
        lines.append(f"Primary Target: {primary_target}")
        secondary_targets = [title for _, title, _ in top_rows[1:3]]
        if secondary_targets:
            lines.append("Secondary Targets:")
            for target in secondary_targets:
                lines.append(f"- {target}")
    lines.append("")
    lines.append("## Warnings")
    if result.warnings:
        for warning in result.warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Top Targets")
    top_targets = top_rows[:10]
    if top_targets:
        lines.append("| Score | Target | Reason |")
        lines.append("|------:|--------|--------|")
        for score, title, reason in top_targets:
            lines.append(f"| {score} | {title} | {reason} |")
    else:
            lines.append("| Score | Target | Reason |")
            lines.append("|------:|--------|--------|")
            lines.append("| 0 | No clear target identified | - |")
    lines.append("")

    lines.append("## Attack Surface")
    if attack_surface:
        for entry in attack_surface:
            lines.append(f"### {entry.title}")
            lines.append(f"Score: {entry.score}")
            lines.append("")
            lines.append("Evidence:")
            evidence_lines = _dedupe_text(entry.evidence)
            for evidence in evidence_lines:
                lines.append(f"- {evidence}")
            if entry.found_by:
                lines.append("Found by:")
                for source in _dedupe_text(entry.found_by):
                    lines.append(f"- {source}")
            lines.append("")
    else:
        lines.append("- No clear attack surface identified")
        lines.append("")

    lines.append("## Investigation Queue")
    for index, action in enumerate(build_next_actions(result), start=1):
        lines.append(f"{index}. {action}")
    lines.append("")

    lines.append("## Server Information")
    server_info_lines = build_server_information(result)
    if server_info_lines:
        for item in server_info_lines:
            lines.append(f"- {item}")
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def assess(argv: list[str]) -> int:
    args = parse_args(argv)
    target_url = normalize_target_url(args["target"])
    out_dir = args["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = out_dir.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []
    if args["use_api"] and not os.environ.get("WPSCAN_API_TOKEN", "").strip():
        errors.append("--use-api was specified but WPSCAN_API_TOKEN is not set")

    print(f"[*] target: {target_url}", flush=True)
    print(f"[*] mode: {args['mode']}", flush=True)
    print(f"[*] api: {'enabled' if args['use_api'] else 'disabled'}", flush=True)
    if args["use_api"]:
        print("[*] running HTTP verification...", flush=True)
    else:
        print("[*] skipping HTTP verification (WPScan-only report)", flush=True)
    xmlrpc_assessment: XmlRpcAssessment | None = None
    if args["use_api"] and args["mode"] in ("normal", "full"):
        print("[*] checking XML-RPC...", flush=True)
        xmlrpc_assessment = probe_xmlrpc(target_url)
        print(f"[+] XML-RPC: {xmlrpc_assessment.state}", flush=True)
    http_checks = build_http_checks(args["mode"], target_url, xmlrpc_assessment=xmlrpc_assessment) if args["use_api"] else []
    if args["use_api"]:
        print("[+] HTTP verification done", flush=True)

    login_status = next((check.status for check in http_checks if check.path == "wp-login.php"), "skipped")
    wp_json_status = next((check.status for check in http_checks if check.path == "wp-json"), "skipped")
    xmlrpc_status = xmlrpc_assessment.state if xmlrpc_assessment is not None else "unknown"
    xmlrpc_http_status = xmlrpc_assessment.post_check.status if xmlrpc_assessment is not None else ""
    xmlrpc_evidence = xmlrpc_assessment.evidence if xmlrpc_assessment is not None else ""
    xmlrpc_get_status = xmlrpc_assessment.get_check.status if xmlrpc_assessment is not None else ""
    xmlrpc_post_status = xmlrpc_assessment.post_check.status if xmlrpc_assessment is not None else ""
    xmlrpc_get_evidence = f"GET /xmlrpc.php returned {xmlrpc_get_status}" if xmlrpc_get_status else ""
    xmlrpc_post_evidence = xmlrpc_evidence

    wpscan_payload: dict[str, Any] = {}
    wpscan_errors: list[str] = []
    if not errors:
        print("[*] running WPScan...", flush=True)
        try:
            wpscan_payload, wpscan_errors = run_wpscan(
                target_url,
                args["mode"],
                args["use_api"],
                log_dir=log_dir,
            )
        except AssessError as exc:
            errors.append(str(exc))
        else:
            if wpscan_errors:
                errors.extend(wpscan_errors)
        print("[+] WPScan done", flush=True)
    else:
        print("[!] skipping WPScan due to earlier error", flush=True)

    print("[*] parsing results...", flush=True)
    wpscan = parse_wpscan_result(wpscan_payload) if wpscan_payload else WpScanResult(raw={})
    warnings: list[str] = []
    if bool(args["use_api"]) != bool(wpscan.vuln_api.used):
        warnings.append("WPScan API request state does not match actual WPScan API use.")

    print("[*] building report...", flush=True)
    exposure_checks = build_exposure_checks(args["mode"], http_checks) if args["use_api"] else []
    wordpress_detected = bool(
        wpscan.detected
        or login_status not in ("404", "unreachable", "skipped")
        or wp_json_status not in ("404", "unreachable", "skipped")
        or xmlrpc_status in ("reachable", "not confirmed")
    )

    result = AssessResult(
        target_url=target_url,
        mode=args["mode"],
        use_api=args["use_api"],
        wordpress_detected=wordpress_detected,
        login_page=login_status,
        wp_json=wp_json_status,
        xmlrpc=xmlrpc_status,
        xmlrpc_http_status=xmlrpc_http_status,
        xmlrpc_evidence=xmlrpc_evidence,
        version=wpscan.version,
        plugins=wpscan.plugins,
        themes=wpscan.themes,
        users=wpscan.users,
        http_checks=http_checks,
        exposure_checks=exposure_checks,
        next_actions=[],
        report_path=_assess_report_path(out_dir, target_url, args["mode"], args["use_api"]),
        errors=errors,
        xmlrpc_get_status=xmlrpc_get_status,
        xmlrpc_post_status=xmlrpc_post_status,
        xmlrpc_get_evidence=xmlrpc_get_evidence,
        xmlrpc_post_evidence=xmlrpc_post_evidence,
        version_status=wpscan.version_status,
        version_release_date=wpscan.version_release_date,
        version_confidence=wpscan.version_confidence,
        version_vulnerabilities=wpscan.version_vulnerabilities,
        interesting_findings=wpscan.interesting_findings,
        vuln_api=wpscan.vuln_api,
        warnings=warnings,
    )
    result.next_actions = build_next_actions(result)

    markdown = render_markdown(result)
    result.report_path.write_text(markdown, encoding="utf-8")
    print("[+] report written", flush=True)

    print(f"Target: {result.target_url}")
    print(f"Mode: {result.mode}")
    print(f"WordPress detected: {'yes' if result.wordpress_detected else 'no'}")
    print(f"Login page: {result.login_page}")
    print(f"XML-RPC: {_xmlrpc_effective_state(result)}")
    print(f"Users: {len(result.users)}  Plugins: {len(result.plugins)}  Themes: {len(result.themes)}")
    print(f"Report: {result.report_path}")
    print(f"Logs: {log_dir}", flush=True)

    if errors:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(WP_USAGE, end="" if WP_USAGE.endswith("\n") else "\n")
        return 1
    cmd = args[0]
    if cmd in ("-h", "--help"):
        print(WP_USAGE, end="" if WP_USAGE.endswith("\n") else "\n")
        return 0
    if cmd != "assess":
        print(f"unknown command: {cmd}")
        print(WP_USAGE, end="" if WP_USAGE.endswith("\n") else "\n")
        return 1
    try:
        return assess(args[1:])
    except AssessError as exc:
        message = str(exc)
        if message == ASSESS_USAGE:
            print(message, end="" if message.endswith("\n") else "\n")
            return 0
        print(f"error: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
