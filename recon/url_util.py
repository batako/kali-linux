"""URL normalization for probe commands and execution cache."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}

_URL_IN_COMMAND_RE = re.compile(r"((?:https?|ftp)://[^\s'\"]+)")


def canonicalize_url(url: str) -> str:
    """http://host:80/ and http://host/ → the same canonical form."""
    s = (url or "").strip()
    if not s:
        return s

    parsed = urlparse(s)
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname
    if not scheme or not host:
        return s

    port = parsed.port
    if port is None:
        port = _DEFAULT_PORTS.get(scheme, 80)

    path = parsed.path or "/"
    default = _DEFAULT_PORTS.get(scheme)
    if default and port == default:
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def canonicalize_probe_command(command: str) -> str:
    """Normalize URLs embedded in curl-style probe commands."""
    command = (command or "").strip()
    if not command:
        return command
    return _URL_IN_COMMAND_RE.sub(lambda m: canonicalize_url(m.group(1)), command)
