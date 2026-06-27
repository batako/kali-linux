"""OS detection via nmap -O for scout."""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from typing import Optional

from db import add_artifact
from db import connect
from db import fetch_merged_open_ports
from executor import run_command
from executor import run_command_or_cache

OS_DETECT_KIND = "os_detect"
OS_DETECT_TASK = "scout-os"
OS_DETECT_TIMEOUT_SEC = int(os.environ.get("SCOUT_OS_TIMEOUT", "120"))


def build_os_detect_command(ip: str) -> str:
    return f"nmap -Pn -O --osscan-guess --max-os-tries 2 -oX - {ip}"


def parse_nmap_os_xml(xml_data: str) -> dict:
    """Parse nmap -oX - output; return matches sorted by accuracy."""
    text = (xml_data or "").strip()
    if not text:
        return {"matches": [], "best": None}

    start = text.find("<?xml")
    if start < 0:
        start = text.find("<nmaprun")
    if start < 0:
        return {"matches": [], "best": None}
    text = text[start:]

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {"matches": [], "best": None}

    matches: list[dict] = []
    for host in root.findall("host"):
        os_el = host.find("os")
        if os_el is None:
            continue
        for osmatch in os_el.findall("osmatch"):
            name = (osmatch.attrib.get("name") or "").strip()
            accuracy = (osmatch.attrib.get("accuracy") or "").strip()
            osclass = osmatch.find("osclass")
            family = vendor = gen = ""
            if osclass is not None:
                family = (osclass.attrib.get("osfamily") or "").strip()
                vendor = (osclass.attrib.get("vendor") or "").strip()
                gen = (osclass.attrib.get("osgen") or "").strip()
            if not name:
                continue
            matches.append(
                {
                    "name": name,
                    "accuracy": accuracy,
                    "family": family,
                    "vendor": vendor,
                    "gen": gen,
                }
            )

    def _accuracy(item: dict) -> int:
        try:
            return int(item.get("accuracy") or 0)
        except (TypeError, ValueError):
            return 0

    matches.sort(key=_accuracy, reverse=True)
    best = matches[0]["name"] if matches else None
    return {"matches": matches, "best": best}


def store_os_detect(ip: str, parsed: dict, *, execution_id: Optional[int] = None) -> None:
    add_artifact(
        ip,
        OS_DETECT_KIND,
        "latest",
        json.dumps(parsed, ensure_ascii=False),
        execution_id,
    )


def load_os_detect(ip: str) -> Optional[dict]:
    conn = connect()
    row = conn.execute(
        """
        SELECT value FROM artifacts
        WHERE ip = ? AND kind = ? AND key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, OS_DETECT_KIND, "latest"),
    ).fetchone()
    conn.close()
    if not row:
        return None
    try:
        data = json.loads(row["value"] or "")
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _fetch_execution_output(exec_id: int) -> str:
    conn = connect()
    row = conn.execute(
        "SELECT stdout, stderr FROM executions WHERE id = ?",
        (exec_id,),
    ).fetchone()
    conn.close()
    if not row:
        return ""
    return f"{row['stdout'] or ''}\n{row['stderr'] or ''}".strip()


def _has_open_ports(ip: str) -> bool:
    return any(True for _ in fetch_merged_open_ports(ip))


def format_os_report_lines(ip: str) -> list[str]:
    data = load_os_detect(ip)
    if not data:
        return ["(none — run scout to detect)"]

    matches = data.get("matches") or []
    if not matches:
        return ["(not detected)"]

    lines: list[str] = []
    for i, match in enumerate(matches[:3]):
        name = match.get("name") or "?"
        acc = match.get("accuracy") or "?"
        bits = []
        if match.get("family"):
            bits.append(f"family={match['family']}")
        if match.get("gen"):
            bits.append(f"gen={match['gen']}")
        suffix = f"  {' '.join(bits)}" if bits else ""
        label = "best" if i == 0 else f"alt{i}"
        lines.append(f"{label}: {name} ({acc}%){suffix}")
    return lines


def run_os_detect_phase(ip: str, *, dry_run: bool = False, force: bool = False) -> int:
    """Run nmap OS fingerprint when open ports exist; store artifact."""
    print("")
    print("[*] phase 1c: OS detection (nmap -O)")

    if not _has_open_ports(ip):
        print("[*] no open ports — skip")
        return 0

    cmd = build_os_detect_command(ip)
    print(f"    $ {cmd}")

    if dry_run:
        print("")
        return 0

    try:
        if force:
            exec_id = run_command(
                ip,
                cmd,
                timeout_sec=OS_DETECT_TIMEOUT_SEC,
                stream=False,
                task_type=OS_DETECT_TASK,
            )
            cached = False
        else:
            exec_id, cached = run_command_or_cache(
                ip,
                cmd,
                timeout_sec=OS_DETECT_TIMEOUT_SEC,
                stream=False,
                task_type=OS_DETECT_TASK,
            )
    except Exception as exc:
        print(f"    -> failed: {exc}")
        print("")
        return 1

    tag = "cached" if cached else "ran"
    print(f"    -> exec_id={exec_id} ({tag})  ev {exec_id}")

    output = _fetch_execution_output(exec_id)
    parsed = parse_nmap_os_xml(output)
    store_os_detect(ip, parsed, execution_id=exec_id)

    if parsed.get("best"):
        print(f"    -> {parsed['best']}")
    else:
        print("    -> (not detected)")

    print("")
    return 0
