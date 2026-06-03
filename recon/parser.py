import xml.etree.ElementTree as ET

from db import upsert_host
from db import upsert_port
from db import add_scan_range
from db import add_task


def parse_hosts_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()

    for host in root.findall("host"):
        status_el = host.find("status")

        if status_el is None:
            continue

        if status_el.attrib.get("state") != "up":
            continue

        addr_el = host.find("address")

        if addr_el is None:
            continue

        ip = addr_el.attrib.get("addr")

        hostname = ""

        hostnames = host.find("hostnames")

        if hostnames is not None:
            hn = hostnames.find("hostname")

            if hn is not None:
                hostname = hn.attrib.get("name", "")

        mac = ""

        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "mac":
                mac = addr.attrib.get("addr", "")

        upsert_host(
            ip=ip,
            hostname=hostname,
            mac=mac,
            status="alive"
        )


def generate_tasks(ip, services):
    if "ftp" in services:
        add_task(
            ip,
            "ftp-anon",
            "ftp anonymous check"
        )

    if "http" in services:
        add_task(
            ip,
            "dir-brute",
            "web directory brute force"
        )

    if "rpcbind" in services:
        add_task(
            ip,
            "nfs-enum",
            "possible NFS enumeration"
        )

    if "ssh" in services:
        add_task(
            ip,
            "ssh-audit",
            "check weak credentials / keys"
        )


def parse_ports_xml(path, ip, mode):
    tree = ET.parse(path)
    root = tree.getroot()

    services = set()

    for host in root.findall("host"):
        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):
            proto = port.attrib.get("protocol")
            portid = int(port.attrib.get("portid"))

            state_el = port.find("state")

            if state_el is None:
                continue

            state = state_el.attrib.get("state")

            service_el = port.find("service")

            service = ""
            version = ""

            if service_el is not None:
                service = service_el.attrib.get("name", "")

                product = service_el.attrib.get("product", "")
                ver = service_el.attrib.get("version", "")

                version = f"{product} {ver}".strip()

            services.add(service)

            upsert_port(
                ip=ip,
                port=portid,
                proto=proto,
                state=state,
                service=service,
                version=version
            )

    generate_tasks(ip, services)

    if mode == "quick":
        add_scan_range(ip, mode, 1, 1000)

    elif mode == "full":
        add_scan_range(ip, mode, 1, 65535)
