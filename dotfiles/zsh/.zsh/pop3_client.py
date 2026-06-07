#!/usr/bin/env python3
"""POP3 client for pop3.zsh — reads config from env vars."""

from __future__ import annotations

import os
import socket
import sys

HOST = os.environ["POP3_HOST"]
PORT = int(os.environ["POP3_PORT"])
USER = os.environ["POP3_USER"]
PASS = os.environ["POP3_PASS"]
INTERACTIVE = os.environ.get("POP3_INTERACTIVE", "1") == "1"
CMDS = [line for line in os.environ.get("POP3_CMDS", "").split("\n") if line.strip()]
DUMP_DIR = os.environ.get("POP3_DUMP_DIR", "").strip()

# RETR/LIST bodies can be large on slow THM links
SOCKET_TIMEOUT = int(os.environ.get("POP3_TIMEOUT", "120"))


class Pop3Reader:
    """Line-oriented reader that keeps a buffer (avoids losing data across recv)."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def read_line(self) -> str:
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        if b"\r\n" not in self.buf:
            line, self.buf = self.buf, b""
        else:
            idx = self.buf.index(b"\r\n")
            line, self.buf = self.buf[:idx], self.buf[idx + 2 :]
        return line.decode(errors="replace")

    def read_multiline(self) -> str:
        lines = []
        while True:
            line = self.read_line()
            if line == ".":
                break
            if line.startswith(".."):
                line = line[1:]
            lines.append(line)
        return "\n".join(lines)


def cmd_is_multiline(cmd: str) -> bool:
    head = (cmd.strip().split(None, 1) or [""])[0].upper()
    return head in ("RETR", "TOP", "LIST", "UIDL", "CAPA")


def send_cmd(reader: Pop3Reader, cmd: str, *, multiline: bool = False) -> str:
    reader.sock.sendall(f"{cmd}\r\n".encode())
    first = reader.read_line()
    if multiline and first.startswith("+OK"):
        body = reader.read_multiline()
        return f"{first}\n{body}" if body else first
    return first


def parse_list_nums(list_response: str) -> list[str]:
    lines = list_response.split("\n", 1)
    body = lines[1] if len(lines) > 1 else ""
    nums: list[str] = []
    for line in body.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            nums.append(parts[0])
    return nums


def dump_all(reader: Pop3Reader, out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    listing = send_cmd(reader, "LIST", multiline=True)
    if listing.startswith("-ERR"):
        print(listing, file=sys.stderr)
        return 1

    nums = parse_list_nums(listing)
    if not nums:
        print("[*] no messages", file=sys.stderr)
        return 0

    print(f"[*] dumping {len(nums)} message(s) → {out_dir}", file=sys.stderr)
    rc = 0
    for num in nums:
        print(f"[*] RETR {num} ...", file=sys.stderr, flush=True)
        out = send_cmd(reader, f"RETR {num}", multiline=True)
        if out.startswith("-ERR"):
            print(out, file=sys.stderr)
            rc = 1
            continue
        path = os.path.join(out_dir, f"{num}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out)
            if not out.endswith("\n"):
                fh.write("\n")
        print(f"[+] {path}", file=sys.stderr)
    return rc


def authenticate(reader: Pop3Reader) -> bool:
    print(reader.read_line(), flush=True)

    r = send_cmd(reader, f"USER {USER}")
    print(r, flush=True)
    if not r.startswith("+OK"):
        return False

    r = send_cmd(reader, f"PASS {PASS}")
    print(r, flush=True)
    if not r.startswith("+OK"):
        return False

    print(f"[+] authenticated: {USER}@{HOST}:{PORT}", file=sys.stderr)
    return True


def main() -> int:
    try:
        sock = socket.create_connection((HOST, PORT), timeout=20)
    except OSError as e:
        print(f"[-] connect failed: {e}", file=sys.stderr)
        return 1
    sock.settimeout(SOCKET_TIMEOUT)
    reader = Pop3Reader(sock)
    try:
        if not authenticate(reader):
            return 1

        if DUMP_DIR:
            rc = dump_all(reader, DUMP_DIR)
            send_cmd(reader, "QUIT")
            return rc

        if CMDS:
            rc = 0
            for cmd in CMDS:
                multiline = cmd_is_multiline(cmd)
                if multiline:
                    print(f"[*] {cmd} ...", file=sys.stderr, flush=True)
                out = send_cmd(reader, cmd, multiline=multiline)
                print(out, flush=True)
                if out.startswith("-ERR"):
                    rc = 1
            send_cmd(reader, "QUIT")
            return rc

        if not INTERACTIVE:
            send_cmd(reader, "QUIT")
            return 0

        print("[i] commands: LIST, RETR n, STAT, DELE n, QUIT", file=sys.stderr)
        while True:
            try:
                cmd = input("pop3> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("", file=sys.stderr)
                break
            if not cmd:
                continue
            if cmd.upper() in ("QUIT", "EXIT"):
                print(send_cmd(reader, "QUIT"), flush=True)
                break
            multiline = cmd_is_multiline(cmd)
            if multiline:
                print(f"[*] {cmd} ...", file=sys.stderr, flush=True)
            print(send_cmd(reader, cmd, multiline=multiline), flush=True)
    except socket.timeout:
        print("[-] timed out waiting for server (try again or use pop3-get)", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[-] connection error: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
