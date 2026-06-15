#!/usr/bin/env python3
# Minimal requests-compatible client.
# Implemented only for reqfuzz.
# Not a full replacement for the requests library.
# NOTE:
# This Session does not implement connection pooling or HTTP Keep-Alive reuse.
# Each response closes its underlying connection.
# Parallel execution in reqfuzz provides the current speedup.

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit


class RequestException(Exception):
    pass


class Timeout(RequestException):
    pass


class ConnectionError(RequestException):
    pass


@dataclass
class Response:
    _conn: http.client.HTTPConnection
    _resp: http.client.HTTPResponse

    def __post_init__(self) -> None:
        self.status_code = self._resp.status
        self.headers = dict(self._resp.getheaders())

    def iter_content(self, chunk_size: int = 8192):
        while True:
            chunk = self._resp.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def close(self) -> None:
        try:
            self._resp.close()
        finally:
            self._conn.close()


class Session:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.verify = True

    def mount(self, *_args, **_kwargs) -> None:
        return None

    def request(self, method: str, url: str, timeout=None, stream: bool = False, allow_redirects: bool = False, data=None, headers=None):
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise RequestException(f"unsupported scheme: {scheme}")

        connect_timeout = None
        read_timeout = None
        if isinstance(timeout, tuple):
            connect_timeout, read_timeout = timeout
        elif timeout is not None:
            connect_timeout = read_timeout = timeout

        if scheme == "https":
            context = ssl.create_default_context()
            if not self.verify:
                context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=connect_timeout, context=context)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=connect_timeout)

        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        merged_headers = dict(self.headers)
        if headers:
            merged_headers.update(headers)

        body = data
        if isinstance(body, str):
            body = body.encode()

        try:
            conn.request(method.upper(), path, body=body, headers=merged_headers)
            if conn.sock is not None and read_timeout is not None:
                conn.sock.settimeout(read_timeout)
            resp = conn.getresponse()
        except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
            conn.close()
            raise RequestException(str(exc)) from exc

        return Response(conn, resp)
