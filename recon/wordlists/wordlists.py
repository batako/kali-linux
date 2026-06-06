"""SecLists wordlist catalog — load, resolve, list, validate.

The catalog (catalog.yaml) is curated in-repo (AI-maintained). There is no
user-facing generate command; ``validate`` ensures disk ↔ catalog parity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

CATALOG_DIR = Path(__file__).resolve().parent
DEFAULT_CATALOG_PATH = CATALOG_DIR / "catalog.yaml"
DEFAULT_ROOT = "/usr/share/seclists"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    path: str
    category_id: str
    lines: Optional[int] = None
    speed: Optional[str] = None
    use: Optional[str] = None

    @property
    def basename(self) -> str:
        return Path(self.path).name


@dataclass(frozen=True)
class SelectorSpec:
    id: str
    description: str
    default: Optional[str]
    recommended: Optional[str]
    entry_ids: tuple[str, ...]


@dataclass
class ValidationIssue:
    level: str  # error | warn
    message: str


class WordlistCatalog:
    def __init__(self, data: dict[str, Any], *, catalog_path: Path):
        self.catalog_path = catalog_path
        self.version = int(data.get("version", 0))
        self.root = str(data.get("root", DEFAULT_ROOT)).rstrip("/")
        self._raw = data
        self._entries_by_id: dict[str, CatalogEntry] = {}
        self._entries_by_path: dict[str, CatalogEntry] = {}
        self._selectors: dict[str, SelectorSpec] = {}
        self._build_indexes()

    @classmethod
    def load(cls, path: Optional[Path] = None) -> WordlistCatalog:
        catalog_path = Path(path or DEFAULT_CATALOG_PATH)
        with catalog_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"invalid catalog: {catalog_path}")
        return cls(data, catalog_path=catalog_path)

    def _build_indexes(self) -> None:
        categories = self._raw.get("categories") or []
        if not isinstance(categories, list):
            raise ValueError("catalog.categories must be a list")

        for cat in categories:
            if not isinstance(cat, dict):
                continue
            cat_id = str(cat.get("id") or "")
            entries = cat.get("entries") or []
            if not isinstance(entries, list):
                continue
            for raw in entries:
                if not isinstance(raw, dict):
                    continue
                eid = str(raw.get("id") or "").strip()
                path = str(raw.get("path") or "").strip().replace("\\", "/")
                if not eid or not path:
                    continue
                entry = CatalogEntry(
                    id=eid,
                    path=path,
                    category_id=cat_id,
                    lines=_optional_int(raw.get("lines")),
                    speed=_optional_str(raw.get("speed")),
                    use=_optional_str(raw.get("use")),
                )
                if eid in self._entries_by_id:
                    raise ValueError(f"duplicate catalog id: {eid}")
                if path in self._entries_by_path:
                    raise ValueError(f"duplicate catalog path: {path}")
                self._entries_by_id[eid] = entry
                self._entries_by_path[path] = entry

        selectors = self._raw.get("selectors") or {}
        if not isinstance(selectors, dict):
            raise ValueError("catalog.selectors must be a map")
        for sid, raw in selectors.items():
            if not isinstance(raw, dict):
                continue
            entry_ids = raw.get("entry_ids") or raw.get("entries") or []
            if not isinstance(entry_ids, list):
                entry_ids = []
            self._selectors[str(sid)] = SelectorSpec(
                id=str(sid),
                description=str(raw.get("description") or ""),
                default=_optional_str(raw.get("default")),
                recommended=_optional_str(raw.get("recommended")),
                entry_ids=tuple(str(x) for x in entry_ids),
            )

    @property
    def entries(self) -> list[CatalogEntry]:
        return list(self._entries_by_id.values())

    @property
    def selectors(self) -> dict[str, SelectorSpec]:
        return dict(self._selectors)

    def get(self, entry_id: str) -> Optional[CatalogEntry]:
        return self._entries_by_id.get(entry_id)

    def resolve(
        self,
        value: str,
        *,
        category: Optional[str] = None,
    ) -> str:
        """Map catalog id or absolute/relative path to absolute path under root."""
        value = (value or "").strip()
        if not value:
            raise ValueError("empty wordlist value")

        if value.startswith("/"):
            return value

        entry = self._entries_by_id.get(value)
        if entry is not None:
            return f"{self.root}/{entry.path}"

        if "/" in value or value.endswith(".txt"):
            rel = value.lstrip("/")
            if rel in self._entries_by_path:
                return f"{self.root}/{rel}"
            candidate = f"{self.root}/{rel}"
            if Path(candidate).is_file():
                return candidate
            raise ValueError(f"unknown wordlist path: {value}")

        hint = ""
        if category and category in self._selectors:
            hint = f" (selector: {category})"
        raise ValueError(f"unknown wordlist id: {value}{hint}")

    def list_selector(self, selector_id: str) -> list[CatalogEntry]:
        spec = self._selectors.get(selector_id)
        if spec is None:
            raise ValueError(f"unknown selector: {selector_id}")
        out: list[CatalogEntry] = []
        for eid in spec.entry_ids:
            entry = self._entries_by_id.get(eid)
            if entry is None:
                raise ValueError(
                    f"selector {selector_id!r} references missing entry id: {eid}"
                )
            out.append(entry)
        return out

    def validate(
        self,
        *,
        root: Optional[str] = None,
        strict_lines: bool = False,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        root_path = Path(root or self.root)
        if not root_path.is_dir():
            issues.append(ValidationIssue("error", f"root not found: {root_path}"))
            return issues

        if self.version < 1:
            issues.append(ValidationIssue("error", "catalog.version must be >= 1"))

        for eid, entry in self._entries_by_id.items():
            if not _ID_RE.match(eid):
                issues.append(
                    ValidationIssue("warn", f"id {eid!r} does not match {_ID_RE.pattern}")
                )
            full = root_path / entry.path
            if not full.is_file():
                issues.append(
                    ValidationIssue("error", f"missing file for id={eid}: {full}")
                )
            elif entry.lines is not None:
                actual = _count_lines(full)
                if actual != entry.lines:
                    level = "error" if strict_lines else "warn"
                    issues.append(
                        ValidationIssue(
                            level,
                            f"lines mismatch id={eid}: catalog={entry.lines} disk={actual}",
                        )
                    )

        disk_files = _disk_files(root_path)
        catalog_files = set(self._entries_by_path.keys())
        missing = sorted(disk_files - catalog_files)
        extra = sorted(catalog_files - disk_files)

        if missing:
            issues.append(
                ValidationIssue(
                    "error",
                    f"{len(missing)} file(s) on disk not in catalog "
                    f"(first: {missing[0]})",
                )
            )
        if extra:
            issues.append(
                ValidationIssue(
                    "error",
                    f"{len(extra)} catalog path(s) missing on disk (first: {extra[0]})",
                )
            )

        for sid, spec in self._selectors.items():
            if not spec.entry_ids:
                issues.append(
                    ValidationIssue("error", f"selector {sid!r} has no entry_ids")
                )
            for eid in spec.entry_ids:
                if eid not in self._entries_by_id:
                    issues.append(
                        ValidationIssue(
                            "error",
                            f"selector {sid!r} references unknown id: {eid}",
                        )
                    )
            for label, target in (("default", spec.default), ("recommended", spec.recommended)):
                if target and target not in spec.entry_ids:
                    issues.append(
                        ValidationIssue(
                            "error",
                            f"selector {sid!r} {label}={target!r} not in entry_ids",
                        )
                    )

        return issues


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _count_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            count += chunk.count(b"\n")
    if path.stat().st_size > 0:
        with path.open("rb") as f:
            f.seek(-1, 2)
            if f.read(1) != b"\n":
                count += 1
    return count


def _disk_files(root: Path) -> set[str]:
    out: set[str] = set()
    for path in root.rglob("*"):
        if path.is_file():
            out.add(path.relative_to(root).as_posix())
    return out


def format_lines(n: Optional[int]) -> str:
    if n is None:
        return "?"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)
