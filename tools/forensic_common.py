from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
MIN_REASONABLE = datetime(2007, 1, 1, tzinfo=timezone.utc)
MAX_REASONABLE = datetime(datetime.now(timezone.utc).year + 1, 12, 31, tzinfo=timezone.utc)
SECRET_RE = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|authorization|bearer|cookie|password|secret|session|jwt|token)\b"
    r"(\s*[:=]\s*|[\"']\s*:\s*[\"']?)([^,\s\"';&}{]{8,})"
)


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
