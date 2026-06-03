import subprocess
import xml.etree.ElementTree as ET

from db import upsert_host
from db import upsert_port
from db import add_task
from db import add_scan_range


def network_scan(cidr):
    cmd = f"nmap -sn {cidr} -oX -"
    out = subprocess.getoutput(cmd)

    parse_hosts_xml(out)


def host_scan(ip, mode):
    if mode == "quick":
        port_range = "1-1000"
        cmd = f"nmap -sV --top-ports 1000 {ip} -oX -"
    else:
        port_range = "1-65535"
        cmd = f"nmap -sV -p- {ip} -oX -"

    add_scan_range(ip, mode, *parse_range(port_range))

    out = subprocess.getoutput(cmd)

    parse_ports_xml(out, ip, mode)


def parse_hosts_xml(xml_data):
    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        status = host.find("status").attrib.get("state", "unknown")

        addr = host.find("address")
        if addr is None:
            continue

        ip = addr.attrib.get("addr")

        upsert_host(ip, status=status)


def parse_ports_xml(xml_data, ip, mode):
    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for p in ports.findall("port"):
            portid = int(p.attrib["portid"])
            proto = p.attrib["protocol"]

            state = p.find("state").attrib["state"]

            service_elem = p.find("service")
            service = service_elem.attrib.get("name", "") if service_elem is not None else ""
            version = service_elem.attrib.get("version", "") if service_elem is not None else ""

            upsert_port(ip, portid, proto, state, service, version)

            generate_tasks(ip, portid, service)


def generate_tasks(ip, port, service):
    service = (service or "").lower()

    if port == 21 or "ftp" in service:
        add_task(ip, "ftp-anon", "ftp anonymous check", priority=80, requires_human_ok=0)

    elif port == 80 or "http" in service:
        # brute-force can be noisy; start with human approval
        add_task(ip, "dir-brute", "web directory brute force", priority=90, requires_human_ok=1)

    elif port == 111:
        add_task(ip, "nfs-enum", "possible NFS enumeration", priority=40, requires_human_ok=0)

    elif port == 22 or "ssh" in service:
        add_task(ip, "ssh-audit", "check weak credentials / keys", priority=60, requires_human_ok=0)


def parse_range(r):
    parts = r.split("-")
    if len(parts) != 2:
        return (1, 1000)
    return (int(parts[0]), int(parts[1]))
