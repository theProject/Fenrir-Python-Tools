from __future__ import annotations

import json
import plistlib
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from tools.forensic_common import (
    apple_timestamp_to_utc,
    classify_warning_message,
    clean_control_text,
    file_size_mb,
    guess_app_from_record_domain,
    is_likely_directory_record,
    is_sqlite_file,
    keyword_hits,
    open_sqlite_ro,
    redact_secrets,
    safe_output_path,
    sha256_file,
    snippet_quality_fields,
)
from tools.forensic_models import ExtractedArtifact, ManifestRecord
from tools.forensic_reports import write_cards_html, write_csv, write_json, write_table_html
from tools.forensic_teams import sqlite_sidecar_type


SYSTEM_CATEGORIES = ("notification", "mail", "outlook", "chrome", "tesla_app", "keyboard")
CORE_DATA_TABLES = {
    "ZSPPERSON",
    "ZSPACTIVITY",
    "ZSPLISTITEM",
    "ZSPLINK",
    "ZSPLOCALRECENTITEM",
    "ZSPWEB",
    "ZSPGROUP",
    "ZSPACCOUNTCONFIG",
    "ZSPAGGREGATEDNEWSFEEDITEM",
}
MAIL_EXTRA_KEYWORDS = ["sent a message", "sent you a message", "Microsoft Teams", "Teams", "no-reply", "noreply", "missed activity"]
TEXTLIKE_EXTS = {".json", ".plist", ".txt", ".log", ".xml", ".html", ".htm", ".ldb", ".sst", ".realm", ".dat"}
SQLITE_EXTS = {".db", ".sqlite", ".sqlite3"}
RELATION_TERMS = ("PERSON", "AUTHOR", "OWNER", "CREATOR", "ACTOR", "USER", "ITEM", "LINK", "WEB", "GROUP", "ACTIVITY")


def _logical(record: ManifestRecord) -> str:
    return record.logical_path.lower()


def is_notification_candidate(record: ManifestRecord) -> bool:
    logical = _logical(record)
    return (
        record.domain == "HomeDomain"
        and (
            record.relative_path.startswith("Library/UserNotifications/")
            or record.relative_path.startswith("Library/BulletinBoard/")
            or "Library/SpringBoard/PushStore" in record.relative_path
        )
    ) or any(term in logical for term in ("usernotifications", "pushstore", "deliverednotifications", "bulletin", "notification"))


def is_mail_candidate(record: ManifestRecord) -> bool:
    logical = _logical(record)
    return record.domain == "HomeDomain" and (
        record.relative_path.startswith("Library/Mail/")
        or "envelope index" in logical
        or "protected index" in logical
    )


def is_outlook_candidate(record: ManifestRecord) -> bool:
    logical = _logical(record)
    domain = record.domain.lower()
    return (
        "com.microsoft.office.outlook" in domain
        or ("outlook" in domain and (domain.startswith("appdomain") or domain.startswith("appdomaingroup") or domain.startswith("appdomainplugin")))
        or ("outlook" in logical and any(term in logical for term in ("office", "mail", "message", "sync", "offline", "cache", "sqlite", "database")))
    )


def is_chrome_candidate(record: ManifestRecord) -> bool:
    logical = _logical(record)
    domain = record.domain.lower()
    return (
        "com.google.chrome.ios" in domain
        or ("chrome" in domain or "google" in domain)
        and any(term in logical for term in ("webkit", "history", "cookies", "local storage", "indexeddb", "cache", "sqlite", "plist", "json", "text"))
    )


def is_tesla_candidate(record: ManifestRecord) -> bool:
    logical = _logical(record)
    return any(term in logical for term in ("tesla", "teslamotors", "fleet", "energy", "service", "charging", "supercharger"))


def is_keyboard_candidate(record: ManifestRecord) -> bool:
    logical = _logical(record)
    return (
        record.domain == "HomeDomain"
        and record.relative_path.startswith("Library/Keyboard/")
    ) or any(term in logical for term in ("keyboard", "dictionaries", "lexicon", "autocorrect"))


def categories_for_record(record: ManifestRecord, enabled: set[str]) -> list[str]:
    checks = {
        "notification": is_notification_candidate,
        "mail": is_mail_candidate,
        "outlook": is_outlook_candidate,
        "chrome": is_chrome_candidate,
        "tesla_app": is_tesla_candidate,
        "keyboard": is_keyboard_candidate,
    }
    return [name for name, check in checks.items() if name in enabled and check(record)]


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _table_names(conn: sqlite3.Connection) -> list[str]:
    return [row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def _columns(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(f"PRAGMA table_info({_quote_ident(table)})")]


def _row_id(row: sqlite3.Row, fallback: Any) -> str:
    keys = set(row.keys())
    if "Z_PK" in keys:
        return str(row["Z_PK"])
    if "rowid" in keys:
        return str(row["rowid"])
    return str(fallback)


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _read_text_for_scan(path: Path) -> str:
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".plist":
        try:
            return json.dumps(_json_safe(plistlib.loads(raw)), ensure_ascii=False, default=str)
        except Exception:
            pass
    if suffix == ".json":
        try:
            return json.dumps(json.loads(raw.decode("utf-8", errors="ignore")), ensure_ascii=False, default=str)
        except Exception:
            pass
    return raw.decode("utf-8", errors="ignore")


def _make_hit(
    *,
    keyword: str,
    record: ManifestRecord,
    path: Path,
    snippet: str,
    source_type: str,
    evidence_class: str,
    parser_note: str,
    offset: int | None = None,
    table: str | None = None,
    column: str | None = None,
    rowid: str | None = None,
    database: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    quality = snippet_quality_fields(snippet, evidence_class)
    row = {
        "keyword": keyword,
        "source_type": source_type,
        "domain": record.domain,
        "relative_path": record.relative_path,
        "logical_path": record.logical_path,
        "file_id": record.file_id,
        "extracted_path": str(path),
        "file_sha256": sha256_file(path) if path.exists() else None,
        "app_guess": guess_app_from_record_domain(record.domain),
        "database": database,
        "table": table,
        "column": column,
        "rowid": rowid,
        "offset": offset,
        "snippet": redact_secrets(snippet),
        "parser_note": parser_note,
        **quality,
    }
    if extra:
        row.update(extra)
    return row


def scan_text_artifact(path: Path, record: ManifestRecord, keywords: list[str], evidence_class: str, parser_note: str, context: int) -> list[dict[str, Any]]:
    text = _read_text_for_scan(path)
    return [
        _make_hit(keyword=keyword, record=record, path=path, snippet=snippet, source_type="text", evidence_class=evidence_class, parser_note=parser_note, offset=offset)
        for keyword, offset, snippet in keyword_hits(text, keywords, context=context)
    ]


def scan_sqlite_artifact(path: Path, record: ManifestRecord, keywords: list[str], evidence_class: str, parser_note: str, row_limit: int, context: int) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    conn = open_sqlite_ro(path)
    try:
        for table in _table_names(conn):
            cols = _columns(conn, table)
            scan_cols = [
                c["name"]
                for c in cols
                if str(c.get("type") or "").upper() in {"TEXT", "VARCHAR", "CHAR", "CLOB", "BLOB"}
                or any(term in c["name"].lower() for term in ("subject", "from", "to", "cc", "sender", "recipient", "body", "summary", "snippet", "message", "title", "subtitle", "text", "name", "email"))
            ]
            if not scan_cols:
                continue
            limit_sql = "" if row_limit <= 0 else " LIMIT ?"
            args: tuple[Any, ...] = () if row_limit <= 0 else (row_limit,)
            for row in conn.execute(f"SELECT rowid, * FROM {_quote_ident(table)}{limit_sql}", args):
                for column in scan_cols:
                    value = row[column]
                    if value is None:
                        continue
                    value_text = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
                    value_class = "sqlite_blob_fragment" if isinstance(value, bytes) else evidence_class
                    for keyword, offset, snippet in keyword_hits(value_text, keywords, context=context):
                        hits.append(_make_hit(keyword=keyword, record=record, path=path, snippet=snippet, source_type="sqlite", evidence_class=value_class, parser_note=parser_note, offset=offset, table=table, column=column, rowid=_row_id(row, ""), database=str(path)))
    finally:
        conn.close()
    return hits


def scan_artifact_keywords(path: Path, record: ManifestRecord, keywords: list[str], evidence_class: str, parser_note: str, row_limit: int, context: int) -> list[dict[str, Any]]:
    try:
        if is_sqlite_file(path):
            return scan_sqlite_artifact(path, record, keywords, evidence_class, parser_note, row_limit, context)
        return scan_text_artifact(path, record, keywords, evidence_class, parser_note, context)
    except sqlite3.Error:
        raise


def extract_printable_strings(raw: bytes, min_len: int = 4) -> Iterable[tuple[int, str]]:
    start: int | None = None
    buf = bytearray()
    for idx, byte in enumerate(raw):
        if 32 <= byte <= 126:
            if start is None:
                start = idx
            buf.append(byte)
        else:
            if start is not None and len(buf) >= min_len:
                yield start, buf.decode("ascii", errors="ignore")
            start = None
            buf = bytearray()
    if start is not None and len(buf) >= min_len:
        yield start, buf.decode("ascii", errors="ignore")


def raw_string_carve(path: Path, record: ManifestRecord, keywords: list[str], context: int) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    hits: list[dict[str, Any]] = []
    for offset, text in extract_printable_strings(raw):
        for keyword, local_offset, snippet in keyword_hits(text, keywords, context=context):
            evidence_class = "binary_text_fragment" if len(raw) != len(text.encode("utf-8", errors="ignore")) else "raw_string_fragment"
            hits.append(_make_hit(keyword=keyword, record=record, path=path, snippet=snippet, source_type="raw_string", evidence_class=evidence_class, parser_note="raw_string_carve", offset=offset + local_offset))
    return hits


def sqlite_raw_byte_carve(path: Path, record: ManifestRecord, keywords: list[str], context: int) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    lowered = raw.lower()
    hits: list[dict[str, Any]] = []
    for keyword in keywords:
        needle = keyword.encode("utf-8", errors="ignore").lower()
        if not needle:
            continue
        start = 0
        while True:
            idx = lowered.find(needle, start)
            if idx < 0:
                break
            left = max(0, idx - context)
            right = min(len(raw), idx + len(needle) + context)
            snippet = raw[left:right].decode("utf-8", errors="ignore")
            hits.append(_make_hit(keyword=keyword, record=record, path=path, snippet=snippet, source_type="sqlite_raw", evidence_class="sqlite_raw_bytes", parser_note="sqlite_raw_byte_carve; not deleted-row recovery", offset=idx, database=str(path)))
            start = idx + len(needle)
    return hits


def _compound_terms(values: list[str]) -> list[str]:
    terms: list[str] = []
    for value in values:
        for part in value.split(","):
            term = part.strip()
            if term:
                terms.append(term)
    return list(dict.fromkeys(terms))


def compound_keyword_hits(rows: list[dict[str, Any]], compound_keywords: list[str], window: int) -> list[dict[str, Any]]:
    terms = _compound_terms(compound_keywords)
    if len(terms) < 2:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        text = str(row.get("clean_snippet") or row.get("snippet") or "")
        lowered = text.lower()
        positions: list[tuple[str, int]] = []
        for term in terms:
            idx = lowered.find(term.lower())
            if idx >= 0:
                positions.append((term, idx))
        for i, (left_term, left_idx) in enumerate(positions):
            for right_term, right_idx in positions[i + 1 :]:
                if abs(left_idx - right_idx) <= window:
                    out.append({**row, "compound_terms": f"{left_term},{right_term}", "compound_window": window})
                    break
            else:
                continue
            break
    return out


def _is_coredata_table_set(tables: set[str]) -> bool:
    return bool({t.upper() for t in tables}.intersection(CORE_DATA_TABLES))


def inspect_microsoft_coredata(path: Path, record: ManifestRecord, keywords: list[str], context: int = 160) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    person_hits: list[dict[str, Any]] = []
    related_rows: list[dict[str, Any]] = []
    schema_rows: list[dict[str, Any]] = []
    conn = open_sqlite_ro(path)
    try:
        tables = _table_names(conn)
        if not _is_coredata_table_set(set(tables)):
            return [], [], []
        table_lookup = {t.upper(): t for t in tables}
        person_table = table_lookup.get("ZSPPERSON")
        matched_person_ids: set[str] = set()
        if person_table:
            cols = _columns(conn, person_table)
            wanted = [c["name"] for c in cols if any(term in c["name"].upper() for term in ("DISPLAY", "NAME", "EMAIL", "USER", "LOGIN", "PRINCIPAL"))]
            for row in conn.execute(f"SELECT rowid, * FROM {_quote_ident(person_table)}"):
                person_id = _row_id(row, "")
                for column in wanted:
                    value = row[column]
                    if value is None:
                        continue
                    text = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
                    for keyword, offset, snippet in keyword_hits(text, keywords, context=context):
                        matched_person_ids.add(person_id)
                        quality = snippet_quality_fields(snippet, "coredata_entity")
                        person_hits.append(
                            {
                                "keyword": keyword,
                                "app_guess": guess_app_from_record_domain(record.domain),
                                "database": str(path),
                                "table": person_table,
                                "rowid": person_id,
                                "matched_column": column,
                                "field": column,
                                "clean_value": quality["clean_snippet"],
                                "raw_type": type(value).__name__,
                                "sha256": sha256_file(path),
                                "logical_path": record.logical_path,
                                "confidence": quality["confidence"],
                                "evidence_class": "coredata_entity",
                                "offset": offset,
                                "snippet": redact_secrets(snippet),
                                **quality,
                            }
                        )
        for table in tables:
            cols = _columns(conn, table)
            relation_cols = [c["name"] for c in cols if any(term in c["name"].upper() for term in RELATION_TERMS) or (c["name"].upper().startswith("Z") and str(c.get("type") or "").upper() in {"INTEGER", "INT"})]
            for column in relation_cols:
                schema_rows.append({"database": str(path), "table": table, "column": column, "relationship_hint": "coredata_relationship_candidate"})
            if not matched_person_ids or table == person_table:
                continue
            for column in relation_cols:
                try:
                    placeholders = ",".join("?" for _ in matched_person_ids)
                    sql = f"SELECT rowid, * FROM {_quote_ident(table)} WHERE {_quote_ident(column)} IN ({placeholders})"
                    for row in conn.execute(sql, tuple(matched_person_ids)):
                        row_text = json.dumps({k: _json_safe(row[k]) for k in row.keys()}, ensure_ascii=False, default=str)
                        quality = snippet_quality_fields(row_text, "coredata_entity")
                        related_rows.append(
                            {
                                "app_guess": guess_app_from_record_domain(record.domain),
                                "database": str(path),
                                "table": table,
                                "rowid": _row_id(row, ""),
                                "matched_column": column,
                                "matched_person_ids": ",".join(sorted(matched_person_ids)),
                                "clean_value": quality["clean_snippet"],
                                "sha256": sha256_file(path),
                                "logical_path": record.logical_path,
                                "confidence": quality["confidence"],
                                "evidence_class": "coredata_entity",
                                **quality,
                            }
                        )
                except sqlite3.Error:
                    continue
    finally:
        conn.close()
    return person_hits, related_rows, schema_rows


def _write_category(outdir: Path, name: str, rows: list[dict[str, Any]]) -> None:
    write_csv(outdir / f"{name}_keyword_hits.csv", rows)
    write_json(outdir / f"{name}_keyword_hits.json", rows)
    write_cards_html(outdir / f"{name}_keyword_hits.html", f"{name.replace('_', ' ').title()} Keyword Hits", rows)


def _artifact_warning_rows(record: ManifestRecord, artifact: ExtractedArtifact, prefix: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if artifact.skip_reason:
        message = f"{prefix} {record.logical_path}: {artifact.skip_reason}"
        rows.append(
            {
                "file_id": record.file_id,
                "logical_path": record.logical_path,
                "message": message,
                **classify_warning_message(message),
            }
        )
    for part in artifact.notes.split(" | "):
        if not part.startswith("Extractor warning:"):
            continue
        message = part.removeprefix("Extractor warning:").strip()
        rows.append(
            {
                "file_id": record.file_id,
                "logical_path": record.logical_path,
                "message": message,
                **classify_warning_message(message),
            }
        )
    return rows


def sqlite_integrity_check(path: Path, record: ManifestRecord, artifact: ExtractedArtifact | None = None) -> dict[str, Any]:
    row = {
        "file_id": record.file_id,
        "domain": record.domain,
        "relative_path": record.relative_path,
        "logical_path": record.logical_path,
        "database": str(path),
        "sha256": sha256_file(path) if path.exists() else None,
        "integrity_status": "not_sqlite",
        "integrity_result": "",
        "error": "",
        "evidence_note": "SQLite integrity check was not applicable.",
    }
    if sqlite_sidecar_type(path):
        row.update(
            {
                "integrity_status": "sidecar_skipped",
                "evidence_note": "SQLite WAL/SHM sidecar was preserved but not independently integrity-checked.",
            }
        )
        return row
    if not is_sqlite_file(path):
        return row
    try:
        conn = open_sqlite_ro(path)
        try:
            results = [str(check_row[0]) for check_row in conn.execute("PRAGMA integrity_check")]
        finally:
            conn.close()
    except Exception as exc:
        row.update(
            {
                "integrity_status": "error",
                "error": str(exc),
                "evidence_note": "SQLite integrity check could not complete; this does not mutate the evidence file.",
            }
        )
        return row
    result_text = "; ".join(results)
    status = "ok" if results == ["ok"] else "warning"
    row.update(
        {
            "integrity_status": status,
            "integrity_result": result_text,
            "evidence_note": "SQLite integrity_check returned ok." if status == "ok" else "SQLite integrity_check reported issues; review before relying on parser output.",
        }
    )
    if artifact and classify_warning_message(artifact.notes).get("warning_category") == "decrypt_size_mismatch" and status == "ok":
        row["evidence_note"] = "SQLite integrity_check returned ok; any decrypt-size mismatch remains warning-level unless another parser proves failure."
    return row


def _enabled_categories(flags: dict[str, bool]) -> set[str]:
    if flags.get("system_artifacts"):
        return set(SYSTEM_CATEGORIES)
    mapping = {
        "notification": "notification_scan",
        "mail": "mail_scan",
        "keyboard": "keyboard_scan",
        "outlook": "outlook_scan",
        "chrome": "chrome_scan",
        "tesla_app": "tesla_app_scan",
    }
    return {category for category, flag in mapping.items() if flags.get(flag)}


def run_system_artifacts(
    records: list[ManifestRecord],
    extractor: Any,
    output: Path,
    keywords: list[str],
    flags: dict[str, bool],
    max_file_mb: int,
    include_large: bool,
    text_limit_mb: int,
    sqlite_row_limit: int,
    context: int,
    compound_keywords: list[str],
    compound_window: int,
    warnings: list[str],
) -> dict[str, Any]:
    outdir = output / "system_artifacts"
    extracted_dir = outdir / "extracted_files"
    candidate_rows: list[dict[str, Any]] = []
    artifacts: list[ExtractedArtifact] = []
    category_hits: dict[str, list[dict[str, Any]]] = {category: [] for category in SYSTEM_CATEGORIES}
    raw_hits: list[dict[str, Any]] = []
    sqlite_raw_hits: list[dict[str, Any]] = []
    core_person_hits: list[dict[str, Any]] = []
    core_related_rows: list[dict[str, Any]] = []
    core_schema_rows: list[dict[str, Any]] = []
    directory_skipped = 0
    extraction_failures = 0
    extracted_files = 0
    reused_files = 0
    warning_rows: list[dict[str, Any]] = []
    validation_rows: list[dict[str, Any]] = []
    sqlite_integrity_rows: list[dict[str, Any]] = []
    enabled = _enabled_categories(flags)
    raw_enabled = flags.get("system_artifacts") or flags.get("raw_string_carve")
    sqlite_carve_enabled = flags.get("system_artifacts") or flags.get("sqlite_carve")
    coredata_enabled = flags.get("system_artifacts") or flags.get("microsoft_coredata_scan")
    if not (enabled or raw_enabled or sqlite_carve_enabled or coredata_enabled or compound_keywords):
        return {"artifacts": []}
    all_hits_for_compound: list[dict[str, Any]] = []
    for record in records:
        categories = categories_for_record(record, enabled)
        logical = _logical(record)
        microsoft_candidate = "microsoft" in logical or "office" in logical or "sharepoint" in logical or "outlook" in logical
        suffix = Path(record.relative_path).suffix.lower()
        sqlite_candidate = suffix in SQLITE_EXTS or any(term in logical for term in ("sqlite", "database", ".db"))
        raw_standalone = flags.get("raw_string_carve") and not flags.get("system_artifacts") and not enabled
        sqlite_standalone = flags.get("sqlite_carve") and not flags.get("system_artifacts") and not enabled
        carve_candidate = bool(categories) or (raw_standalone and not is_likely_directory_record(record.domain, record.relative_path, record.metadata)) or (sqlite_standalone and sqlite_candidate)
        if coredata_enabled and microsoft_candidate and sqlite_candidate:
            carve_candidate = True
        if not (categories or carve_candidate or (sqlite_carve_enabled and categories)):
            continue
        dest = safe_output_path(extracted_dir, record.domain, record.relative_path)
        if is_likely_directory_record(record.domain, record.relative_path, record.metadata):
            directory_skipped += 1
            candidate_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "categories": ",".join(categories), "extracted": False, "skip_reason": "directory_record_not_extractable", "extracted_path": str(dest), "validation_status": "directory_record_not_extractable"})
            validation_rows.append(
                {
                    "file_id": record.file_id,
                    "logical_path": record.logical_path,
                    "categories": ",".join(categories),
                    "extraction_status": "skipped",
                    "validation_status": "directory_record_not_extractable",
                    "warning_category": "",
                    "warning_severity": "",
                    "integrity_status": "",
                    "evidence_note": "Manifest record appears to describe a directory/container, not an extractable file.",
                }
            )
            artifacts.append(ExtractedArtifact("system_artifact", record.file_id, record.domain, record.relative_path, record.logical_path, None, str(dest), None, None, 0, extractor.is_encrypted(), False, True, "directory_record_not_extractable"))
            continue
        source_obj = extractor.source_object_path(record.file_id)
        size_mb = file_size_mb(source_obj) if source_obj and source_obj.exists() else None
        if size_mb is not None and size_mb > max_file_mb and not include_large:
            reason = f"Skipped by system artifact size limit ({max_file_mb} MB)"
            candidate_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "categories": ",".join(categories), "extracted": False, "skip_reason": reason, "extracted_path": str(dest), "validation_status": "size_skipped"})
            validation_rows.append(
                {
                    "file_id": record.file_id,
                    "logical_path": record.logical_path,
                    "categories": ",".join(categories),
                    "extraction_status": "skipped",
                    "validation_status": "size_skipped",
                    "warning_category": "",
                    "warning_severity": "",
                    "integrity_status": "",
                    "evidence_note": "Artefact was visible in the manifest but skipped by configured size policy.",
                }
            )
            artifacts.append(ExtractedArtifact("system_artifact", record.file_id, record.domain, record.relative_path, record.logical_path, str(source_obj), str(dest), sha256_file(source_obj), None, 0, extractor.is_encrypted(), False, True, reason))
            continue
        artifact = extractor.extract_record(record, dest, "system_artifact")
        artifacts.append(artifact)
        actual_path = Path(artifact.output_path)
        reused = "Reused previously extracted artefact" in artifact.notes
        artifact_warning_rows = _artifact_warning_rows(record, artifact, "Could not extract system artefact")
        warning_rows.extend(artifact_warning_rows)
        warning_category = ",".join(dict.fromkeys(str(row["warning_category"]) for row in artifact_warning_rows))
        warning_severity = ",".join(dict.fromkeys(str(row["warning_severity"]) for row in artifact_warning_rows))
        candidate_row = {
            "file_id": record.file_id,
            "logical_path": record.logical_path,
            "categories": ",".join(categories),
            "extracted": artifact.extracted,
            "skip_reason": artifact.skip_reason,
            "extracted_path": str(actual_path),
            "output_size": artifact.output_size,
            "reused_existing_extraction": reused,
            "warning_category": warning_category,
            "warning_severity": warning_severity,
            "validation_status": "pending",
            "integrity_status": "",
        }
        candidate_rows.append(candidate_row)
        if not artifact.extracted:
            extraction_failures += 1
            warnings.append(f"Could not extract system artefact {record.logical_path}: {artifact.skip_reason}")
            candidate_row["validation_status"] = "extraction_failure"
            validation_rows.append(
                {
                    "file_id": record.file_id,
                    "logical_path": record.logical_path,
                    "categories": ",".join(categories),
                    "extraction_status": "failed",
                    "validation_status": "extraction_failure",
                    "warning_category": warning_category or "extraction_failure",
                    "warning_severity": warning_severity or "error",
                    "integrity_status": "",
                    "evidence_note": "Extraction failed, so this artefact was not parsed in this run.",
                }
            )
            continue
        extracted_files += 1
        if reused:
            reused_files += 1
        if sqlite_sidecar_type(actual_path):
            integrity_row = sqlite_integrity_check(actual_path, record, artifact)
            sqlite_integrity_rows.append(integrity_row)
            candidate_row["validation_status"] = "sidecar_preserved"
            candidate_row["integrity_status"] = integrity_row["integrity_status"]
            validation_rows.append(
                {
                    "file_id": record.file_id,
                    "logical_path": record.logical_path,
                    "categories": ",".join(categories),
                    "extraction_status": "reused" if reused else "extracted",
                    "validation_status": "sidecar_preserved",
                    "warning_category": warning_category,
                    "warning_severity": warning_severity,
                    "integrity_status": integrity_row["integrity_status"],
                    "evidence_note": integrity_row["evidence_note"],
                }
            )
            continue
        if is_sqlite_file(actual_path):
            integrity_row = sqlite_integrity_check(actual_path, record, artifact)
            sqlite_integrity_rows.append(integrity_row)
            candidate_row["integrity_status"] = integrity_row["integrity_status"]
            if integrity_row["integrity_status"] == "error":
                message = f"Could not run SQLite integrity_check for {record.logical_path}: {integrity_row['error']}"
                warning_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "message": message, **classify_warning_message(message)})
        candidate_row["validation_status"] = "reused" if reused else "extracted"
        if warning_category == "decrypt_size_mismatch" and candidate_row["integrity_status"] == "ok":
            candidate_row["validation_status"] = "extracted_with_warning_integrity_ok"
        validation_rows.append(
            {
                "file_id": record.file_id,
                "logical_path": record.logical_path,
                "categories": ",".join(categories),
                "extraction_status": "reused" if reused else "extracted",
                "validation_status": candidate_row["validation_status"],
                "warning_category": warning_category,
                "warning_severity": warning_severity,
                "integrity_status": candidate_row["integrity_status"],
                "evidence_note": "CoreData rows are entity/relationship records, not messages; raw strings are fragment-level evidence; SQLite raw byte hits are not deleted-row recovery unless independently proven.",
            }
        )
        for category in categories:
            scan_keywords = list(dict.fromkeys(keywords + (MAIL_EXTRA_KEYWORDS if category == "mail" else [])))
            evidence_class = {
                "notification": "notification_fragment",
                "mail": "mail_record",
                "keyboard": "keyboard_lexicon",
            }.get(category, "raw_text")
            try:
                hits = scan_artifact_keywords(actual_path, record, scan_keywords, evidence_class, f"{category}_scan", sqlite_row_limit, context)
                category_hits[category].extend(hits)
                all_hits_for_compound.extend(hits)
            except Exception as exc:
                message = f"Could not inspect system artefact {record.logical_path}: {exc}"
                warnings.append(message)
                warning_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "message": message, **classify_warning_message(message)})
        if coredata_enabled and is_sqlite_file(actual_path) and microsoft_candidate:
            try:
                person_hits, related, schema = inspect_microsoft_coredata(actual_path, record, keywords, context)
                core_person_hits.extend(person_hits)
                core_related_rows.extend(related)
                core_schema_rows.extend(schema)
                all_hits_for_compound.extend(person_hits)
            except Exception as exc:
                message = f"Could not inspect Microsoft CoreData database {record.logical_path}: {exc}"
                warnings.append(message)
                warning_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "message": message, **classify_warning_message(message)})
        if raw_enabled:
            try:
                hits = raw_string_carve(actual_path, record, keywords, context)
                raw_hits.extend(hits)
                all_hits_for_compound.extend(hits)
            except Exception as exc:
                message = f"Could not raw-string carve {record.logical_path}: {exc}"
                warnings.append(message)
                warning_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "message": message, **classify_warning_message(message)})
        if sqlite_carve_enabled and is_sqlite_file(actual_path):
            try:
                hits = sqlite_raw_byte_carve(actual_path, record, keywords, context)
                sqlite_raw_hits.extend(hits)
                all_hits_for_compound.extend(hits)
            except Exception as exc:
                message = f"Could not SQLite raw-byte carve {record.logical_path}: {exc}"
                warnings.append(message)
                warning_rows.append({"file_id": record.file_id, "logical_path": record.logical_path, "message": message, **classify_warning_message(message)})
    write_csv(outdir / "system_candidate_files.csv", candidate_rows)
    write_json(outdir / "system_candidate_files.json", candidate_rows)
    write_csv(outdir / "system_validation_report.csv", validation_rows)
    write_json(outdir / "system_validation_report.json", validation_rows)
    write_table_html(outdir / "system_validation_report.html", "System Artifact Validation Report", validation_rows)
    write_csv(outdir / "warning_classification.csv", warning_rows)
    write_json(outdir / "warning_classification.json", warning_rows)
    write_table_html(outdir / "warning_classification.html", "System Artifact Warning Classification", warning_rows)
    write_csv(outdir / "sqlite_integrity_checks.csv", sqlite_integrity_rows)
    write_json(outdir / "sqlite_integrity_checks.json", sqlite_integrity_rows)
    write_table_html(outdir / "sqlite_integrity_checks.html", "SQLite Integrity Checks", sqlite_integrity_rows)
    for category, rows in category_hits.items():
        _write_category(outdir, category, rows)
    write_csv(outdir / "raw_string_hits.csv", raw_hits)
    write_json(outdir / "raw_string_hits.json", raw_hits)
    write_cards_html(outdir / "raw_string_hits.html", "Raw String Hits", raw_hits)
    write_csv(outdir / "sqlite_raw_hits.csv", sqlite_raw_hits)
    write_json(outdir / "sqlite_raw_hits.json", sqlite_raw_hits)
    write_cards_html(outdir / "sqlite_raw_hits.html", "SQLite Raw Byte Hits", sqlite_raw_hits)
    core_dir = output / "microsoft_coredata"
    write_csv(core_dir / "person_hits.csv", core_person_hits)
    write_json(core_dir / "person_hits.json", core_person_hits)
    write_cards_html(core_dir / "person_hits.html", "Microsoft CoreData Person Hits", core_person_hits)
    write_csv(core_dir / "related_rows.csv", core_related_rows)
    write_json(core_dir / "related_rows.json", core_related_rows)
    write_cards_html(core_dir / "related_rows.html", "Microsoft CoreData Related Rows", core_related_rows, text_field="clean_value")
    write_csv(core_dir / "schema_relationships.csv", core_schema_rows)
    write_json(core_dir / "schema_relationships.json", core_schema_rows)
    compound_rows = compound_keyword_hits(all_hits_for_compound, compound_keywords, compound_window)
    review_dir = output / "review"
    write_csv(review_dir / "compound_keyword_hits.csv", compound_rows)
    write_json(review_dir / "compound_keyword_hits.json", compound_rows)
    write_cards_html(review_dir / "compound_keyword_hits.html", "Compound Keyword Hits", compound_rows)
    summary = {
        "candidate_files": len(candidate_rows),
        "extracted_files": extracted_files,
        "reused_files": reused_files,
        "directory_records_skipped": directory_skipped,
        "extraction_failures": extraction_failures,
        "classified_warnings": len(warning_rows),
        "decrypt_size_mismatch_warnings": sum(1 for row in warning_rows if row.get("warning_category") == "decrypt_size_mismatch"),
        "sqlite_integrity_checked": sum(1 for row in sqlite_integrity_rows if row.get("integrity_status") in {"ok", "warning", "error"}),
        "sqlite_integrity_ok": sum(1 for row in sqlite_integrity_rows if row.get("integrity_status") == "ok"),
        "sqlite_integrity_warnings": sum(1 for row in sqlite_integrity_rows if row.get("integrity_status") == "warning"),
        "sqlite_integrity_errors": sum(1 for row in sqlite_integrity_rows if row.get("integrity_status") == "error"),
        "notification_hits": len(category_hits["notification"]),
        "mail_hits": len(category_hits["mail"]),
        "outlook_hits": len(category_hits["outlook"]),
        "chrome_hits": len(category_hits["chrome"]),
        "tesla_app_hits": len(category_hits["tesla_app"]),
        "keyboard_hits": len(category_hits["keyboard"]),
        "microsoft_coredata_person_hits": len(core_person_hits),
        "microsoft_coredata_related_rows": len(core_related_rows),
        "raw_string_hits": len(raw_hits),
        "sqlite_raw_hits": len(sqlite_raw_hits),
        "compound_keyword_hits": len(compound_rows),
        "evidence_language_note": "CoreData rows are entity/relationship records, raw string hits are fragment-level evidence, SQLite raw byte hits are not deleted-row recovery unless independently proven, and decrypt-size mismatch is warning-level until integrity checks or parser failures prove failure.",
    }
    write_json(outdir / "system_artifacts_summary.json", summary)
    write_table_html(outdir / "system_artifacts_summary.html", "System Artifacts Summary", [summary])
    write_json(core_dir / "microsoft_coredata_summary.json", summary)
    write_table_html(core_dir / "microsoft_coredata_summary.html", "Microsoft CoreData Summary", [summary])
    return {**summary, "artifacts": artifacts}
