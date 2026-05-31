from __future__ import annotations

import hashlib
import os
import string
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
MIN_REASONABLE = datetime(2007, 1, 1, tzinfo=timezone.utc)
MAX_REASONABLE = datetime(datetime.now(timezone.utc).year + 1, 12, 31, tzinfo=timezone.utc)
SECRET_RE = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|authorization|bearer|cookie|password|secret|session|jwt|token)\b"
    r"(\s*[:=]\s*|[\"']\s*:\s*[\"']?)([^,\s\"';&}{]{8,})"
)
DIRECTORY_MODE = 0o040000
REGULAR_FILE_MODE = 0o100000
FILE_TYPE_MASK = 0o170000
KNOWN_FILE_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".json",
    ".plist",
    ".txt",
    ".log",
    ".ldb",
    ".sst",
    ".xml",
    ".html",
    ".htm",
}
CONTAINER_PATH_SUFFIXES = {
    "Library/HTTPStorages",
    "Library/WebKit/Databases",
    "Library/WebKit/WebsiteData/IndexedDB",
    "Library/WebKit/WebsiteData/LocalStorage",
    "Library/Application Support",
    "Library/Caches",
    "WebKit",
    "WebsiteData",
}
KNOWN_CONTAINER_NAMES = {
    "httpstorages",
    "indexeddb",
    "localstorage",
    "databases",
    "websitedata",
    "webkit",
    "sitesservicecache",
    "backstageinappnavcache",
    "resourceinfocache",
    "webservicecache",
    "mruservicecache",
    "localcacheroot",
    "sharedlogs",
    "attachmentstorage",
    "streamcache",
    "logs",
}
CONTAINER_PARENT_NAMES = {
    "sitesservicecache",
    "backstageinappnavcache",
    "resourceinfocache",
    "webservicecache",
    "mruservicecache",
}
HEX_BASENAME_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def open_sqlite_ro(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def is_sqlite_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def apple_timestamp_to_utc(value: object) -> str | None:
    if value in (None, ""):
        return None
    try:
        raw = float(value)
    except (TypeError, ValueError):
        return None
    candidates = []
    for scale in (1, 1000, 1_000_000_000):
        try:
            candidates.append(APPLE_EPOCH + timedelta(seconds=raw / scale))
        except OverflowError:
            continue
    if raw > 978307200:
        for scale in (1, 1000):
            try:
                candidates.append(datetime.fromtimestamp(raw / scale, tz=timezone.utc))
            except (OverflowError, OSError, ValueError):
                continue
    for candidate in candidates:
        if MIN_REASONABLE <= candidate <= MAX_REASONABLE:
            return candidate.isoformat()
    return None


def decode_attributed_body(value: object) -> tuple[str, str]:
    if not isinstance(value, (bytes, bytearray)):
        return "", "empty"
    text = bytes(value).decode("utf-8", errors="ignore")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+", " ", text)
    fragments = re.findall(r"[\w@#&$%.,:;!?/+'\"() -]{3,}", text)
    cleaned = " ".join(f.strip() for f in fragments if f.strip())
    return cleaned[:5000], "attributedBody_fragment" if cleaned else "empty"


def redact_secrets(text: str) -> str:
    return SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


def clean_control_text(text: str) -> str:
    cleaned = "".join(ch if ch in "\t\n\r" or ch >= " " else " " for ch in text)
    return re.sub(r"\s+", " ", cleaned).strip()


def snippet_quality_fields(snippet: str, evidence_class: str) -> dict[str, object]:
    raw = "" if snippet is None else str(snippet)
    control_count = sum(1 for ch in raw if ord(ch) < 32 and ch not in "\t\n\r")
    printable_chars = set(string.printable)
    printable_count = sum(1 for ch in raw if ch in printable_chars or ord(ch) >= 0x80)
    printable_ratio = printable_count / len(raw) if raw else 1.0
    clean = redact_secrets(clean_control_text(raw))
    raw_preview = redact_secrets(raw[:500].encode("unicode_escape", errors="backslashreplace").decode("ascii", errors="ignore"))
    binary_fragment = control_count > 0 or printable_ratio < 0.85
    confidence = "low" if printable_ratio < 0.65 else "medium" if binary_fragment else "high"
    return {
        "clean_snippet": clean,
        "raw_snippet_preview": raw_preview,
        "control_char_count": control_count,
        "printable_ratio": round(printable_ratio, 3),
        "binary_fragment": binary_fragment,
        "confidence": confidence,
        "evidence_class": evidence_class,
    }


def _metadata_mode(metadata: dict[str, Any]) -> int | None:
    for key in ("Mode", "mode", "st_mode", "ProtectionClassMode"):
        value = metadata.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                continue
    return None


def metadata_indicates_directory(metadata: dict[str, Any]) -> bool:
    if not metadata:
        return False
    for key in ("file_type", "FileType", "type", "Type", "NSFileType"):
        value = str(metadata.get(key, "")).lower()
        if "directory" in value:
            return True
    mode = _metadata_mode(metadata)
    return bool(mode is not None and (mode & FILE_TYPE_MASK) == DIRECTORY_MODE)


def metadata_indicates_regular_file(metadata: dict[str, Any]) -> bool:
    if not metadata:
        return False
    for key in ("file_type", "FileType", "type", "Type", "NSFileType"):
        value = str(metadata.get(key, "")).lower()
        if "regular" in value or value == "file" or value.endswith("file"):
            return True
    mode = _metadata_mode(metadata)
    return bool(mode is not None and (mode & FILE_TYPE_MASK) == REGULAR_FILE_MODE)


def _has_known_file_extension(path: str) -> bool:
    return Path(path).suffix.lower() in KNOWN_FILE_EXTENSIONS


def is_likely_directory_record(domain: str, relative_path: str, metadata: dict[str, Any] | None = None) -> bool:
    metadata = metadata or {}
    if metadata_indicates_regular_file(metadata):
        return False
    if metadata_indicates_directory(metadata):
        return True
    normalized = str(Path(relative_path).as_posix()).strip("/")
    if not normalized:
        return True
    if _has_known_file_extension(normalized):
        return False
    normalized_lower = normalized.lower()
    for suffix in CONTAINER_PATH_SUFFIXES:
        suffix_lower = suffix.lower()
        if normalized_lower == suffix_lower or normalized_lower.endswith(f"/{suffix_lower}"):
            return True
    parts = [part.lower() for part in Path(normalized).parts]
    leaf = parts[-1] if parts else ""
    if leaf in KNOWN_CONTAINER_NAMES:
        return True
    if any(parent in parts[:-1] for parent in CONTAINER_PARENT_NAMES):
        return True
    if HEX_BASENAME_RE.match(leaf) and any(parent in parts for parent in {"indexeddb", "localstorage"}):
        return True
    return False


def keyword_hits(text: str, keywords: list[str], context: int = 120) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    lowered = text.lower()
    for keyword in keywords:
        if not keyword:
            continue
        start = 0
        needle = keyword.lower()
        while True:
            idx = lowered.find(needle, start)
            if idx < 0:
                break
            left = max(0, idx - context)
            right = min(len(text), idx + len(keyword) + context)
            hits.append((keyword, idx, text[left:right].replace("\n", " ")))
            start = idx + len(keyword)
    return hits


def guess_app_from_record_domain(domain: str) -> str | None:
    for prefix in ("AppDomain-", "AppDomainGroup-", "PluginKitPlugin-", "SysSharedContainerDomain-"):
        if domain.startswith(prefix):
            return domain.removeprefix(prefix)
    return None


def safe_output_path(base: Path, domain: str, relative_path: str) -> Path:
    parts = [p for p in Path(domain, relative_path).parts if p not in ("", ".", "..")]
    return base.joinpath(*parts)


def is_output_inside_source(source: Path, output: Path) -> bool:
    try:
        output.relative_to(source)
        return True
    except ValueError:
        return False


def file_size_mb(path: Path) -> float:
    return path.stat().st_size / (1024 * 1024)


def env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}
