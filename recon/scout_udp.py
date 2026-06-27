"""Light UDP service check via nmap -sU --top-ports for scout."""

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
from db import finish_execution
from db import upsert_port
from scan_run import _nmap_output_base_suffix
from scan_run import _nmap_scan_options
from scan_run import _nmap_xml_suffix
from scan_run import _render_nmap_command

UDP_KIND = "udp_scan"
UDP_TASK = "scout-udp"
UDP_TIMEOUT_SEC = int(os.environ.get("SCOUT_UDP_TIMEOUT", "300"))
UDP_TOP_PORTS = int(os.environ.get("SCOUT_UDP_TOP_PORTS", "20"))


def build_udp_command(ip: str) -> str:
    return f"nmap {_nmap_scan_options()} -sU --top-ports {UDP_TOP_PORTS} -sV {ip}"


def _clear_udp_artifacts(ip: str) -> None:
    conn = connect()
    conn.execute("DELETE FROM artifacts WHERE ip = ? AND kind = ?", (ip, UDP_KIND))
    conn.commit()
    conn.close()


def parse_nmap_udp_xml(xml_data: str) -> dict:
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
            proto = (port_el.attrib.get("protocol") or "").strip().lower()
            if proto != "udp":
                continue
            portid = int(port_el.attrib.get("portid") or 0)
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
            ports.append(
                {
                    "port": portid,
                    "proto": "udp",
                    "state": state,
                    "service": service,
                    "version": version,
                }
            )

    ports.sort(key=lambda item: int(item.get("port") or 0))
    return {"ports": ports}


def store_udp_scan(ip: str, parsed: dict, *, execution_id: Optional[int] = None) -> None:
    _clear_udp_artifacts(ip)
    for item in parsed.get("ports") or []:
        port = int(item.get("port") or 0)
        proto = "udp"
        state = (item.get("state") or "unknown").strip() or "unknown"
        service = (item.get("service") or "").strip()
        version = (item.get("version") or "").strip()
        upsert_port(ip, port, proto, state, service, version)
        add_artifact(
            ip,
            UDP_KIND,
            f"{port}/{proto}",
            json.dumps(item, ensure_ascii=False),
            execution_id,
        )


def load_udp_scan(ip: str) -> list[dict]:
    conn = connect()
    rows = conn.execute(
        """
        SELECT value
        FROM artifacts
        WHERE ip = ? AND kind = ?
        ORDER BY id ASC
        """,
        (ip, UDP_KIND),
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
    out.sort(key=lambda item: int(item.get("port") or 0))
    return out


def format_udp_report_lines(ip: str) -> list[str]:
    rows = load_udp_scan(ip)
    if not rows:
        return ["(none — run scout to check UDP)"]

    lines: list[str] = []
    for item in rows:
        port = int(item.get("port") or 0)
        state = (item.get("state") or "unknown").strip() or "unknown"
        service = (item.get("service") or "-").strip() or "-"
        version = (item.get("version") or "").strip()
        line = f"{port}/udp  state={state}  service={service}"
        if version:
            line += f"  ({version})"
        lines.append(line)
    return lines or ["(none — run scout to check UDP)"]


def run_udp_phase(
    ip: str,
    *,
    dry_run: bool = False,
    force: bool = False,
    output_base: str | None = None,
) -> int:
    print("")
    print(f"[*] phase 1d: UDP check (nmap -sU --top-ports {UDP_TOP_PORTS} -sV)")

    cmd = build_udp_command(ip)
    print(f"    $ {_render_nmap_command(cmd, xml_path='-', output_base=output_base)}")

    if dry_run:
        print("")
        return 0

    if force:
        _clear_udp_artifacts(ip)

    exec_id = add_execution(None, ip, UDP_TASK, cmd, cwd="/", status="running")
    xml_path = ""
    try:
        if output_base:
            parent = os.path.dirname(output_base)
            if parent:
                os.makedirs(parent, exist_ok=True)
            xml_path = f"{output_base}.xml"
        else:
            with tempfile.NamedTemporaryFile(
                prefix="scout-udp-",
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
            timeout=UDP_TIMEOUT_SEC,
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

    parsed = parse_nmap_udp_xml(xml_text)
    store_udp_scan(ip, parsed, execution_id=exec_id)
    tag = "ran" if proc.returncode == 0 else f"failed rc={proc.returncode}"
    print(f"    -> exec_id={exec_id} ({tag})  ev {exec_id}")
    print("")
    return 0 if proc.returncode == 0 else 1
