#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import select
import socket
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass, field
from http.client import BadStatusLine, HTTPConnection, HTTPSConnection, HTTPException, RemoteDisconnected
from typing import Callable


USAGE = """usage:
  svcguess [options] <host> <port>
  svcguess [options] <port>        # host defaults to $IP

options:
  -v             verbose output
  --json         emit JSON
  --timeout SEC  timeout in seconds (default: 3)
  -h             show this help
"""


@dataclass(slots=True)
class HttpProbe:
    scheme: str
    ok: bool
    tls_ok: bool = False
    status: int | None = None
    reason: str = ""
    server: str = ""
    location: str = ""
    body_preview: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""


@dataclass(slots=True)
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    san: str = ""
    not_before: str = ""
    not_after: str = ""


@dataclass(slots=True)
class ScanResult:
    host: str
    port: int
    tcp_banner: str = ""
    http: HttpProbe | None = None
    https: HttpProbe | None = None
    certificate: CertificateInfo | None = None


class ServiceDetector:
    """Heuristic detector with small, additive rules."""

    def __init__(self) -> None:
        self._rules: list[Callable[[ScanResult], str | None]] = [
            self._guess_ssh,
            self._guess_ftp,
            self._guess_pop3,
            self._guess_imap,
            self._guess_smtp,
            self._guess_https_web,
            self._guess_http_web,
        ]

    def register(self, rule: Callable[[ScanResult], str | None]) -> None:
        self._rules.append(rule)

    def guess(self, result: ScanResult) -> str:
        for rule in self._rules:
            guess = rule(result)
            if guess:
                return guess
        return "Unknown / custom service"

    def _first_line(self, result: ScanResult) -> str:
        for line in result.tcp_banner.splitlines():
            line = line.strip()
            if line:
                return line
        return ""

    def _banner_text(self, result: ScanResult) -> str:
        return result.tcp_banner.upper()

    def _guess_https_web(self, result: ScanResult) -> str | None:
        https = result.https
        if https and https.ok:
            return "HTTPS Web Server"
        if result.certificate and result.http and result.http.ok:
            return "HTTPS Web Server"
        return None

    def _guess_http_web(self, result: ScanResult) -> str | None:
        http = result.http
        if http and http.ok:
            return "HTTP Web Server"
        return None

    def _guess_ssh(self, result: ScanResult) -> str | None:
        first = self._first_line(result)
        if first.startswith("SSH-2.0") or "OPENSSH" in self._banner_text(result):
            return "SSH"
        return None

    def _guess_ftp(self, result: ScanResult) -> str | None:
        first = self._first_line(result)
        text = self._banner_text(result)
        if first.startswith("220") and "FTP" in text:
            return "FTP"
        if "FTP" in text and "HTTP" not in text:
            return "FTP"
        return None

    def _guess_pop3(self, result: ScanResult) -> str | None:
        first = self._first_line(result)
        if first.startswith("+OK"):
            return "POP3"
        return None

    def _guess_imap(self, result: ScanResult) -> str | None:
        first = self._first_line(result)
        if first.startswith("* OK"):
            return "IMAP"
        return None

    def _guess_smtp(self, result: ScanResult) -> str | None:
        first = self._first_line(result)
        text = self._banner_text(result)
        if "ESMTP" in text or "SMTP" in text or first.startswith("220 ") and "SMTP" in text:
            return "SMTP"
        return None


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="svcguess",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Unknown-service recon helper for THM / CTF initial triage.",
        epilog=USAGE,
    )
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?")
    parser.add_argument("-v", action="store_true", dest="verbose")
    parser.add_argument("--json", action="store_true", dest="json_out")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("-h", "--help", action="store_true", dest="help")
    ns = parser.parse_args(argv)
    if ns.help:
        print(USAGE, end="")
        raise SystemExit(0)
    if ns.host and not ns.port:
        if ns.host.isdigit():
            ns.port = ns.host
            ns.host = os.environ.get("IP", "").strip()
            if not ns.host:
                raise ValueError("missing <host> and IP env is unset")
        else:
            raise ValueError("missing <port>")
    if not ns.host and not ns.port:
        raise ValueError("missing <port>")
    if not ns.host and ns.port:
        ns.host = os.environ.get("IP", "").strip()
        if not ns.host:
            raise ValueError("missing <host> and IP env is unset")
    try:
        ns.port = int(ns.port)
    except ValueError as exc:
        raise ValueError("port must be an integer") from exc
    if ns.timeout <= 0:
        raise ValueError("--timeout must be positive")
    return ns


def _safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _normalize_preview(text: str, limit: int = 200) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _read_available(sock: socket.socket, timeout: float) -> bytes:
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([sock], [], [], remaining)
        if not ready:
            break
        try:
            data = sock.recv(4096)
        except (BlockingIOError, InterruptedError):
            continue
        if not data:
            break
        chunks.append(data)
        if len(data) < 4096:
            deadline = min(deadline, time.monotonic() + 0.15)
    return b"".join(chunks)


def probe_tcp_banner(host: str, port: int, timeout: float) -> str:
    probes = ("help", "?", "version", "hello")
    lines: list[str] = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        banner = _read_available(sock, timeout)
        if banner:
            lines.append(_safe_decode(banner).strip())
        for probe in probes:
            try:
                sock.sendall((probe + "\n").encode())
            except OSError:
                break
            reply = _read_available(sock, timeout)
            if reply:
                lines.append(_safe_decode(reply).strip())
    return "\n".join(line for line in lines if line)


def _probe_http_like(host: str, port: int, timeout: float, *, tls: bool) -> HttpProbe:
    conn: HTTPConnection | HTTPSConnection
    if tls:
        context = ssl._create_unverified_context()
        conn = HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = HTTPConnection(host, port, timeout=timeout)

    try:
        conn.request("GET", "/")
        response = conn.getresponse()
        body = response.read(2048)
        headers = {key.lower(): value for key, value in response.getheaders()}
        body_preview = _normalize_preview(_safe_decode(body))
        return HttpProbe(
            scheme="https" if tls else "http",
            ok=True,
            tls_ok=tls,
            status=response.status,
            reason=response.reason,
            server=headers.get("server", ""),
            location=headers.get("location", ""),
            body_preview=body_preview,
            headers=headers,
        )
    except (socket.timeout, OSError, RemoteDisconnected, BadStatusLine, HTTPException, ssl.SSLError, ValueError) as exc:
        return HttpProbe(
            scheme="https" if tls else "http",
            ok=False,
            tls_ok=tls,
            error=str(exc),
        )
    finally:
        conn.close()


def _flatten_name(components: list[tuple[str, str]]) -> str:
    values: list[str] = []
    for key, value in components:
        if value and value not in values:
            if key.upper() == "COMMONNAME":
                values.insert(0, value)
            else:
                values.append(value)
    return ", ".join(values)


def _flatten_san(entries: list[tuple[str, str]]) -> str:
    values: list[str] = []
    for key, value in entries:
        if value and value not in values:
            if key.upper() in {"DNS", "IP ADDRESS"}:
                values.append(value)
    return ", ".join(values)


def probe_certificate(host: str, port: int, timeout: float) -> CertificateInfo | None:
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
    except Exception:
        return None

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem", encoding="utf-8") as handle:
            handle.write(pem)
            temp_path = handle.name
        decode = getattr(ssl, "_ssl", None)
        if decode is None or not hasattr(decode, "_test_decode_cert"):
            return None
        cert = decode._test_decode_cert(temp_path)
    except Exception:
        return None
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    subject = _flatten_name([pair for part in cert.get("subject", []) for pair in part])
    issuer = _flatten_name([pair for part in cert.get("issuer", []) for pair in part])
    san = _flatten_san(list(cert.get("subjectAltName", [])))
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        san=san,
        not_before=cert.get("notBefore", ""),
        not_after=cert.get("notAfter", ""),
    )


def _render_http_section(title: str, probe: HttpProbe, verbose: bool) -> list[str]:
    lines = [f"[*] {title}"]
    if probe.ok:
        if probe.tls_ok:
            lines.append("TLS OK")
        lines.append(f"status={probe.status if probe.status is not None else '000'}")
        if probe.server:
            lines.append(f"server={probe.server}")
        if probe.location:
            lines.append(f"location={probe.location}")
        if probe.body_preview:
            lines.append(f"body={probe.body_preview}")
        if verbose:
            if probe.reason:
                lines.append(f"reason={probe.reason}")
            if probe.headers:
                lines.append("headers:")
                for key in sorted(probe.headers):
                    lines.append(f"  {key}: {probe.headers[key]}")
    else:
        if probe.tls_ok:
            lines.append("TLS FAIL")
        lines.append("status=000")
        if probe.error:
            lines.append(f"error={probe.error}")
    return lines


def _render_certificate(cert: CertificateInfo, verbose: bool) -> list[str]:
    lines = ["[*] Certificate"]
    if cert.subject:
        lines.append(f"CN={cert.subject}")
    if cert.san:
        lines.append(f"SAN={cert.san}")
    if verbose:
        if cert.issuer:
            lines.append(f"Issuer={cert.issuer}")
        if cert.not_before:
            lines.append(f"NotBefore={cert.not_before}")
        if cert.not_after:
            lines.append(f"NotAfter={cert.not_after}")
    return lines


def _result_to_json(result: ScanResult, guess: str, verbose: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "host": result.host,
        "port": result.port,
        "tcp_banner": result.tcp_banner,
        "guess": guess,
    }
    if result.http is not None:
        payload["http"] = {
            "ok": result.http.ok,
            "tls_ok": result.http.tls_ok,
            "status": result.http.status,
            "reason": result.http.reason if verbose else "",
            "server": result.http.server,
            "location": result.http.location,
            "body_preview": result.http.body_preview,
            "headers": result.http.headers if verbose else {},
            "error": result.http.error,
        }
    if result.https is not None:
        payload["https"] = {
            "ok": result.https.ok,
            "tls_ok": result.https.tls_ok,
            "status": result.https.status,
            "reason": result.https.reason if verbose else "",
            "server": result.https.server,
            "location": result.https.location,
            "body_preview": result.https.body_preview,
            "headers": result.https.headers if verbose else {},
            "error": result.https.error,
        }
    if result.certificate is not None:
        payload["certificate"] = {
            "subject": result.certificate.subject,
            "issuer": result.certificate.issuer,
            "san": result.certificate.san,
            "not_before": result.certificate.not_before,
            "not_after": result.certificate.not_after,
        }
    return payload


def run(argv: list[str]) -> int:
    try:
        ns = _parse_args(argv)
    except ValueError as exc:
        print(f"[-] svcguess: {exc}", file=sys.stderr)
        print(USAGE, end="")
        return 1

    host = ns.host
    port = ns.port
    timeout = float(ns.timeout)

    result = ScanResult(host=host, port=port)
    result.tcp_banner = ""
    try:
        result.tcp_banner = probe_tcp_banner(host, port, timeout)
    except Exception as exc:
        result.tcp_banner = f"(tcp probe failed: {exc})"

    result.http = _probe_http_like(host, port, timeout, tls=False)
    result.https = _probe_http_like(host, port, timeout, tls=True)
    if result.https.ok:
        result.certificate = probe_certificate(host, port, timeout)

    detector = ServiceDetector()
    guess = detector.guess(result)

    if ns.json_out:
        print(json.dumps(_result_to_json(result, guess, ns.verbose), ensure_ascii=False, indent=2 if ns.verbose else None))
        return 0

    sections: list[list[str]] = []
    tcp_lines = ["[*] TCP Banner"]
    tcp_lines.append(result.tcp_banner.strip() if result.tcp_banner.strip() else "(no response)")
    sections.append(tcp_lines)
    sections.append(_render_http_section("HTTP", result.http, ns.verbose))
    sections.append(_render_http_section("HTTPS", result.https, ns.verbose))
    if result.certificate is not None:
        sections.append(_render_certificate(result.certificate, ns.verbose))
    sections.append(["[+] Guess", guess])

    for index, lines in enumerate(sections):
        if index:
            print()
        for line in lines:
            print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())
