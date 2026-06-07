"""CTF hints / memos stored as recon DB artifacts (kind=hint, scoped by case)."""

from __future__ import annotations

import os

from db import add_artifact
from db import connect
from db import delete_artifact

HINT_KIND = "hint"


def hint_scope() -> str:
    """Current case name from CASE env (set by cs)."""
    case = (os.environ.get("CASE") or "").strip()
    if not case:
        raise ValueError("CASE not set — cs <case> first")
    return case


def hint_scope_optional() -> str | None:
    case = (os.environ.get("CASE") or "").strip()
    return case or None


def _find_hint_row(scope: str, tag: str, text: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT id
        FROM artifacts
        WHERE ip = ? AND kind = ? AND key = ? AND value = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (scope, HINT_KIND, tag or "", text),
    ).fetchone()
    conn.close()
    return row


def add_hint(scope: str, text: str, *, tag: str = "") -> tuple[str, int]:
    """Save hint text for case scope. Returns (status, artifact_id)."""
    text = (text or "").strip()
    if not text:
        raise ValueError("empty hint text")
    tag = (tag or "").strip()

    existing = _find_hint_row(scope, tag, text)
    if existing:
        return "unchanged", int(existing["id"])

    art_id = add_artifact(ip=scope, kind=HINT_KIND, key=tag, value=text, execution_id=None, case_name=scope)
    return "saved", art_id


def list_hints(scope: str, *, limit: int = 200) -> list[dict]:
    conn = connect()
    rows = conn.execute(
        """
        SELECT id, key, value, created_at
        FROM artifacts
        WHERE ip = ? AND kind = ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (scope, HINT_KIND, int(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def format_hint_line(row: dict) -> str:
    hid = row["id"]
    tag = (row.get("key") or "").strip()
    value = (row.get("value") or "").strip()
    if tag:
        return f"  {hid}  [{tag}] {value}"
    return f"  {hid}  {value}"


def format_hint_list_lines(scope: str) -> list[str]:
    rows = list_hints(scope)
    if not rows:
        return ["(none)"]
    return [format_hint_line(r) for r in rows]


def format_hint_report_lines(scope: str) -> list[str]:
    rows = list_hints(scope)
    if not rows:
        return ["(none)"]
    return [line.lstrip() for line in format_hint_list_lines(scope)]


def delete_hint(hint_id: int) -> bool:
    conn = connect()
    row = conn.execute(
        "SELECT id, kind FROM artifacts WHERE id = ?",
        (int(hint_id),),
    ).fetchone()
    conn.close()
    if row is None or row["kind"] != HINT_KIND:
        return False
    return delete_artifact(int(hint_id)) > 0
