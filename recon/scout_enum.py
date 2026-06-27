"""Open-port service enumeration via nmap -sC -sV for scout."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from db import add_artifact
from db import add_execution
from db import connect
from db import fetch_merged_open_ports
from db import find_done_execution
from db import finish_execution
from db import upsert_port
from scan_run import _nmap_output_base_suffix
from scan_run import _nmap_scan_options
from scan_run import _nmap_xml_suffix
from scan_run import _render_nmap_command
from scan_run import ports_to_nmap_arg

ENUM_KIND = "port_enum"
ENUM_TASK = "scout-enum"
ENUM_TIMEOUT_SEC = int(os.environ.get("SCOUT_ENUM_TIMEOUT", "300"))


def build_enum_command(ip: str) -> Optional[str]:
    rows = sorted(fetch_merged_open_ports(ip), key=lambda r: int(r[0]))
    if not rows:
        return None
    port_arg = ports_to_nmap_arg(int(row[0]) for row in rows)
    if not port_arg:
        return None
    return f"nmap {_nmap_scan_options()} -sC -sV -p {port_arg} {ip}"


def _clear_enum_artifacts(ip: str) -> None:
    conn = connect()
    conn.execute("DELETE FROM artifacts WHERE ip = ? AND kind = ?", (ip, ENUM_KIND))
    conn.commit()
    conn.close()


def _normalize_script_output(output: str) -> str:
    lines = [(line or "").strip() for line in (output or "").splitlines()]
    lines = [line for line in lines if line]
    return "\n".join(lines).strip()


def parse_nmap_enum_xml(xml_data: str) -> dict:
    text = (xml_data or "").strip()
    if not text:
        return {"ports": []}

    start = text.find("<?xml")
    if start < 0:
        start = text.find("<nmaprun")
    if start < 0:
        return {"ports": []}
    text = text[start:]

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {"ports": []}

    ports: list[dict] = []
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            portid = int(port_el.attrib.get("portid") or 0)
            proto = (port_el.attrib.get("protocol") or "tcp").strip() or "tcp"
            state_el = port_el.find("state")
            state = (
                (state_el.attrib.get("state") or "unknown").strip()
                if state_el is not None
                else "unknown"
            )
            service_el = port_el.find("service")
            service = (
                (service_el.attrib.get("name") or "").strip()
                if service_el is not None
                else ""
            )
            version = ""
            if service_el is not None:
                product = (service_el.attrib.get("product") or "").strip()
                ver = (service_el.attrib.get("version") or "").strip()
                extra = (service_el.attrib.get("extrainfo") or "").strip()
                version = " ".join(part for part in (product, ver, extra) if part).strip()

            scripts: list[dict] = []
            for script_el in port_el.findall("script"):
                script_id = (script_el.attrib.get("id") or "").strip()
                script_output = _normalize_script_output(
                    (script_el.attrib.get("output") or "").strip()
                )
                if not script_id and not script_output:
                    continue
                scripts.append({"id": script_id or "script", "output": script_output})

            ports.append(
                {
                    "port": portid,
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "version": version,
                    "scripts": scripts,
                }
            )

    ports.sort(key=lambda item: (int(item.get("port") or 0), item.get("proto") or "tcp"))
    return {"ports": ports}


def store_port_enum(ip: str, parsed: dict, *, execution_id: Optional[int] = None) -> None:
    _clear_enum_artifacts(ip)
    for item in parsed.get("ports") or []:
        port = int(item.get("port") or 0)
        proto = (item.get("proto") or "tcp").strip() or "tcp"
        state = (item.get("state") or "unknown").strip() or "unknown"
        service = (item.get("service") or "").strip()
        version = (item.get("version") or "").strip()
        upsert_port(ip, port, proto, state, service, version)
        add_artifact(
            ip,
            ENUM_KIND,
            f"{port}/{proto}",
            json.dumps(item, ensure_ascii=False),
            execution_id,
        )


def load_port_enum(ip: str) -> list[dict]:
    conn = connect()
    rows = conn.execute(
        """
        SELECT key, value
        FROM artifacts
        WHERE ip = ? AND kind = ?
        ORDER BY id ASC
        """,
        (ip, ENUM_KIND),
    ).fetchall()
    conn.close()

    out: list[dict] = []
    for row in rows:
        try:
            item = json.loads(row["value"] or "")
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    out.sort(key=lambda item: (int(item.get("port") or 0), item.get("proto") or "tcp"))
    return out


def _compact_script_output(output: str, *, max_len: int = 220) -> str:
    text = " | ".join(part.strip() for part in (output or "").splitlines() if part.strip())
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def format_port_enum_report_lines(ip: str) -> list[str]:
    rows = load_port_enum(ip)
    if not rows:
        return ["(none — run scout to enumerate)"]

    lines: list[str] = []
    shown = 0
    for item in rows:
        scripts = item.get("scripts") or []
        if not scripts:
            continue
        port = int(item.get("port") or 0)
        proto = (item.get("proto") or "tcp").strip() or "tcp"
        service = (item.get("service") or "-").strip() or "-"
        version = (item.get("version") or "").strip()
        header = f"{port}/{proto}  service={service}"
        if version:
            header += f"  ({version})"
        lines.append(header)
        for script in scripts:
            sid = (script.get("id") or "script").strip() or "script"
            output = _compact_script_output(script.get("output") or "")
            if output:
                lines.append(f"  {sid}: {output}")
            else:
                lines.append(f"  {sid}")
        shown += 1
    if shown == 0:
        return ["(no NSE highlights)"]
    return lines


def run_port_enum_phase(
    ip: str,
    *,
    dry_run: bool = False,
    force: bool = False,
    output_base: str | None = None,
) -> int:
    print("")
    print("[*] phase 1b: service enumeration (nmap -sC -sV on open ports)")

    cmd = build_enum_command(ip)
    if not cmd:
        print("[*] no open ports — skip")
        return 0

    display_cmd = _render_nmap_command(cmd, xml_path="-", output_base=output_base)
    print(f"    $ {display_cmd}")

    if dry_run:
        print("")
        return 0

    cached_exec = None if force else find_done_execution(ip, cmd)
    cached_rows = load_port_enum(ip) if cached_exec else []
    if cached_exec and cached_rows:
        print(f"    -> exec_id={cached_exec['id']} (cached)  ev {cached_exec['id']}")
        print("")
        return 0

    if force:
        _clear_enum_artifacts(ip)

    exec_id = add_execution(None, ip, ENUM_TASK, cmd, cwd="/", status="running")
    xml_path = ""
    try:
        if output_base:
            parent = os.path.dirname(output_base)
            if parent:
                os.makedirs(parent, exist_ok=True)
            xml_path = f"{output_base}.xml"
        else:
            with tempfile.NamedTemporaryFile(
                prefix="scout-enum-",
                suffix=".xml",
                delete=False,
            ) as tf:
                xml_path = tf.name

        full_cmd = cmd
        if output_base:
            full_cmd = f"{full_cmd} {_nmap_output_base_suffix(output_base)}"
        full_cmd = f"{full_cmd} {_nmap_xml_suffix(xml_path)}"
        proc = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=ENUM_TIMEOUT_SEC,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        finish_execution(
            exec_id,
            status="timeout",
            exit_code=None,
            stdout=(exc.stdout or "")[-20000:],
            stderr=(exc.stderr or "")[-20000:],
        )
        print("    -> timeout")
        print("")
        return 1
    except Exception as exc:
        finish_execution(exec_id, status="failed", exit_code=None, stdout="", stderr=str(exc)[-20000:])
        print(f"    -> failed: {exc}")
        print("")
        return 1

    xml_text = ""
    try:
        if xml_path and Path(xml_path).is_file():
            xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
    finally:
        if xml_path and not output_base:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

    status = "done" if proc.returncode == 0 else "failed"
    finish_execution(
        exec_id,
        status=status,
        exit_code=proc.returncode,
        stdout=(xml_text or proc.stdout or "")[-20000:],
        stderr=(proc.stderr or "")[-20000:],
    )

    parsed = parse_nmap_enum_xml(xml_text)
    if parsed.get("ports"):
        store_port_enum(ip, parsed, execution_id=exec_id)

    tag = "ran" if proc.returncode == 0 else f"failed rc={proc.returncode}"
    print(f"    -> exec_id={exec_id} ({tag})  ev {exec_id}")
    print("")
    return 0 if proc.returncode == 0 else 1
