import subprocess
import xml.etree.ElementTree as ET

from db import upsert_host
from db import add_task


def network_scan(cidr):
    cmd = f"nmap -sn {cidr} -oX -"
    out = subprocess.getoutput(cmd)

    parse_hosts_xml(out)


def parse_hosts_xml(xml_data):
    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        status = host.find("status").attrib.get("state", "unknown")

        addr = host.find("address")
        if addr is None:
            continue

        ip = addr.attrib.get("addr")

        upsert_host(ip, status=status)


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
