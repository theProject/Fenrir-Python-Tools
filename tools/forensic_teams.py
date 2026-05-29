from __future__ import annotations

import json
import plistlib
import re
import sqlite3
from pathlib import Path
from typing import Any

from tools.forensic_common import (
    file_size_mb,
    guess_app_from_record_domain,
    is_sqlite_file,
    keyword_hits,
    open_sqlite_ro,
    redact_secrets,
    safe_output_path,
    sha256_file,
)
from tools.forensic_models import DeepKeywordHit, ExtractedArtifact, ManifestRecord
from tools.forensic_reports import write_cards_html, write_csv, write_json, write_table_html


TEAMS_DOMAIN_RE = re.compile(r"(microsoft|teams|skype|office|msteams)", re.I)
TEAMS_PATH_RE = re.compile(r"(chat|message|conversation|thread|cache|database|sqlite|realm|storage|log|leveldb|indexeddb|offline)", re.I)
TEAMS_EXTS = {".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm", ".json", ".plist", ".txt", ".log", ".realm", ".ldb", ".sst", ".xml"}


def is_teams_candidate(record: ManifestRecord) -> bool:
    suffix = Path(record.relative_path).suffix.lower()
    logical = record.logical_path
    return bool(TEAMS_DOMAIN_RE.search(logical) and (TEAMS_PATH_RE.search(logical) or suffix in TEAMS_EXTS))


def _table_names(conn: sqlite3.Connection) -> list[str]:
    return [row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def _columns(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(f"PRAGMA table_info({table})")]


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def inspect_sqlite_keywords(path: Path, keywords: list[str], row_limit: int, sample_dir: Path, source: ManifestRecord, parser_note: str = "") -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[DeepKeywordHit]]:
    tables_report: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    hits: list[DeepKeywordHit] = []
    conn = open_sqlite_ro(path)
    try:
        for table in _table_names(conn):
            cols = _columns(conn, table)
            count = None
            try:
                count = conn.execute(f"SELECT COUNT(*) AS c FROM {_quote_ident(table)}").fetchone()["c"]
            except sqlite3.Error:
                pass
            text_cols = [c["name"] for c in cols if str(c.get("type") or "").upper() in {"TEXT", "VARCHAR", "CHAR", "CLOB"} or "text" in c["name"].lower()]
            tables_report.append({"database": str(path), "table": table, "row_count": count, "columns_json": json.dumps(cols), "text_columns": ",".join(text_cols)})
            try:
                rows = [dict(r) for r in conn.execute(f"SELECT * FROM {_quote_ident(table)} LIMIT ?", (min(row_limit, 25),))]
                if rows:
                    sample_path = sample_dir / f"{path.stem}_{table}.json"
                    write_json(sample_path, rows)
                    samples.append({"database": str(path), "table": table, "sample_path": str(sample_path), "sample_rows": len(rows)})
            except sqlite3.Error:
                continue
            for column in text_cols:
                try:
                    sql = f"SELECT rowid AS _rowid, {_quote_ident(column)} AS value FROM {_quote_ident(table)} LIMIT ?"
                    for row in conn.execute(sql, (row_limit,)):
                        value = row["value"]
                        if value is None:
                            continue
                        for keyword, offset, snippet in keyword_hits(str(value), keywords):
                            hits.append(
                                DeepKeywordHit(
                                    keyword=keyword,
                                    source_type="sqlite",
                                    domain=source.domain,
                                    relative_path=source.relative_path,
                                    logical_path=source.logical_path,
                                    file_id=source.file_id,
                                    extracted_path=str(path),
                                    file_sha256=sha256_file(path),
                                    app_guess=guess_app_from_record_domain(source.domain),
                                    database=str(path),
                                    table=table,
                                    column=column,
                                    rowid=str(row["_rowid"]),
                                    offset=offset,
                                    snippet=redact_secrets(snippet),
                                    parser_note=parser_note,
                                )
                            )
                except sqlite3.Error:
                    continue
    finally:
        conn.close()
    return tables_report, samples, hits


def scan_text_keywords(path: Path, record: ManifestRecord, keywords: list[str], limit_mb: int = 25, parser_note: str = "text") -> list[DeepKeywordHit]:
    max_bytes = limit_mb * 1024 * 1024
    raw = path.read_bytes()[:max_bytes]
    text = raw.decode("utf-8", errors="ignore")
    if path.suffix.lower() == ".json":
        try:
            json.loads(text)
            parser_note = "json_raw_text"
        except Exception:
            parser_note = "json_decode_failed_raw_text"
    elif path.suffix.lower() == ".plist":
        try:
            plistlib.loads(raw)
            parser_note = "plist_raw_text"
        except Exception:
            parser_note = "plist_decode_failed_raw_text"
    elif path.suffix.lower() in {".ldb", ".sst", ".realm"}:
        parser_note = "mixed_binary_text"
    hits: list[DeepKeywordHit] = []
    digest = sha256_file(path)
    for keyword, offset, snippet in keyword_hits(text, keywords):
        hits.append(
            DeepKeywordHit(
                keyword=keyword,
                source_type="text",
                domain=record.domain,
                relative_path=record.relative_path,
                logical_path=record.logical_path,
                file_id=record.file_id,
                extracted_path=str(path),
                file_sha256=digest,
                app_guess=guess_app_from_record_domain(record.domain),
                offset=offset,
                snippet=redact_secrets(snippet),
                parser_note=parser_note,
            )
        )
    return hits


def run_teams_triage(
    records: list[ManifestRecord],
    extractor: Any,
    output: Path,
    keywords: list[str],
    sample_limit: int,
    max_file_mb: int,
    include_large: bool,
    warnings: list[str],
) -> dict[str, Any]:
    outdir = output / "teams"
    sample_dir = outdir / "sqlite_samples"
    sample_dir.mkdir(parents=True, exist_ok=True)
    candidates = [r for r in records if is_teams_candidate(r)]
    if not candidates:
        warnings.append("No Microsoft Teams candidate files were found. This may mean Teams data was not backup-eligible or the app was not installed at backup time.")
    artifacts: list[ExtractedArtifact] = []
    candidate_rows: list[dict[str, Any]] = []
    sqlite_tables: list[dict[str, Any]] = []
    sqlite_hits: list[DeepKeywordHit] = []
    text_hits: list[DeepKeywordHit] = []
    sqlite_db_count = 0
    for record in candidates:
        dest = safe_output_path(output / "extracted_files", record.domain, record.relative_path)
        source_obj = extractor._source_object_path(record.file_id)
        size_mb = file_size_mb(source_obj) if source_obj and source_obj.exists() else None
        if size_mb is not None and size_mb > max_file_mb and not include_large:
            artifact = ExtractedArtifact("teams_candidate", record.file_id, record.domain, record.relative_path, record.logical_path, str(source_obj), str(dest), sha256_file(source_obj), None, 0, extractor.is_encrypted(), False, True, f"Skipped by --max-teams-file-mb ({max_file_mb})")
            artifacts.append(artifact)
            continue
        artifact = extractor.extract_record(record, dest, "teams_candidate")
        artifacts.append(artifact)
        candidate_rows.append({"file_id": record.file_id, "domain": record.domain, "relative_path": record.relative_path, "logical_path": record.logical_path, "extracted_path": str(dest), "extracted": artifact.extracted, "skip_reason": artifact.skip_reason})
        if not artifact.extracted:
            warnings.append(f"Could not extract Teams candidate {record.logical_path}: {artifact.skip_reason}")
            continue
        try:
            if is_sqlite_file(dest):
                sqlite_db_count += 1
                tables, _, hits = inspect_sqlite_keywords(dest, keywords, sample_limit, sample_dir, record, "teams_sqlite")
                sqlite_tables.extend(tables)
                sqlite_hits.extend(hits)
            elif keywords:
                text_hits.extend(scan_text_keywords(dest, record, keywords, parser_note="teams_text"))
        except Exception as exc:
            warnings.append(f"Could not inspect Teams candidate {record.logical_path}: {exc}")
    write_csv(outdir / "teams_candidate_files.csv", candidate_rows)
    write_json(outdir / "teams_candidate_files.json", candidate_rows)
    write_json(outdir / "teams_sqlite_report.json", {"sqlite_databases": sqlite_db_count, "tables": sqlite_tables})
    write_csv(outdir / "teams_sqlite_tables.csv", sqlite_tables)
    sqlite_rows = [h.__dict__ for h in sqlite_hits]
    text_rows = [h.__dict__ for h in text_hits]
    write_csv(outdir / "teams_keyword_hits.csv", sqlite_rows)
    write_json(outdir / "teams_keyword_hits.json", sqlite_rows)
    write_cards_html(outdir / "teams_keyword_hits.html", "Teams SQLite Keyword Hits", sqlite_rows)
    write_csv(outdir / "teams_text_keyword_hits.csv", text_rows)
    write_json(outdir / "teams_text_keyword_hits.json", text_rows)
    write_cards_html(outdir / "teams_text_keyword_hits.html", "Teams Text Keyword Hits", text_rows)
    return {
        "candidate_files": len(candidates),
        "sqlite_databases": sqlite_db_count,
        "keyword_hits": len(sqlite_hits),
        "text_hits": len(text_hits),
        "artifacts": artifacts,
    }
