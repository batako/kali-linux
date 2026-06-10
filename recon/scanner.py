import subprocess
import xml.etree.ElementTree as ET

from db import upsert_host


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
