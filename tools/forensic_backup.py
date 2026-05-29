from __future__ import annotations

import argparse
import csv
import getpass
import os
import plistlib
import shutil
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from utils import log_ok, log_warn

from tools.forensic_common import is_output_inside_source, open_sqlite_ro, safe_output_path, sha256_file
from tools.forensic_deep_scan import DEFAULT_DEEP_KEYWORDS, run_deep_scan
from tools.forensic_models import ExtractedArtifact, ForensicError, ManifestRecord, TriageResult
from tools.forensic_reports import utc_now_iso, write_case_summary, write_csv, write_json, write_table_html
from tools.forensic_sms import extract_sms_artifacts, parse_sms_exports
from tools.forensic_teams import run_teams_triage


TABLE_CANDIDATES = ("Files", "files", "file", "FILE")


def add_forensic_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("forensics", help="Forensic-safe MobileSync backup triage")
    p.add_argument("--source", required=True, help="MobileSync Backup UUID folder")
    p.add_argument("--output", "-o", default="./rescue/forensics")
    p.add_argument("--targets", nargs="+", default=["sms", "teams"], choices=["sms", "messages", "imessage", "teams", "microsoft_teams"])
    p.add_argument("--password-env")
    p.add_argument("--prompt-password", action="store_true")
    p.add_argument("--password", help="Convenience only; shell history may retain this value")
    p.add_argument("--keyword", action="append", default=[])
    p.add_argument("--sample-limit", type=int, default=500)
    p.add_argument("--no-attachments", action="store_true")
    p.add_argument("--max-teams-file-mb", type=int, default=250)
    p.add_argument("--include-large-teams-files", action="store_true")
    p.add_argument("--deep-app-cache-scan", action="store_true")
    p.add_argument("--deep-keyword", action="append", default=[])
    p.add_argument("--max-deep-file-mb", type=int, default=250)
    p.add_argument("--include-large-deep-files", action="store_true")
    p.add_argument("--deep-scan-text-limit-mb", type=int, default=25)
    p.add_argument("--deep-scan-sqlite-row-limit", type=int, default=5000)
    p.add_argument("--deep-scan-export-context", action="store_true")
    p.add_argument("--write-timeline", action="store_true")


def get_password(args: argparse.Namespace) -> str | None:
    if args.password_env:
        value = os.environ.get(args.password_env)
        if not value:
            raise ForensicError(f"Environment variable not set or empty: {args.password_env}")
        return value
    if args.password:
        return args.password
    if args.prompt_password:
        return getpass.getpass("iOS encrypted backup password: ")
    return None


def _read_plist(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        value = plistlib.load(f)
    return value if isinstance(value, dict) else {}


def validate_backup_source(source: Path, output: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not (source / "Manifest.plist").exists():
        raise ForensicError("Manifest.plist not found. Point --source at the MobileSync Backup UUID folder, not the parent Backup directory.")
    if not (source / "Manifest.db").exists():
        raise ForensicError("Manifest.db not found. Point --source at a complete MobileSync backup UUID folder.")
    if is_output_inside_source(source, output):
        raise ForensicError("Refusing to write output inside the source backup folder.")
    return _read_plist(source / "Manifest.plist"), _read_plist(source / "Info.plist")


class BackupExtractor:
    def __init__(self, source: Path, output: Path, password: str | None):
        self.source = source
        self.output = output
        self.workspace = output / "_workspace"
        self.extracted_root = output / "extracted_files"
        self.password = password
        self.manifest_plist = _read_plist(source / "Manifest.plist")
        self.encrypted = bool(self.manifest_plist.get("IsEncrypted", False))
        self._encrypted_backup: Any | None = None
        if self.encrypted:
            if not password:
                raise ForensicError("This backup is encrypted. Use --password-env IOS_BACKUP_PASSWORD, --prompt-password, or --password.")
            try:
                from iphone_backup_decrypt import EncryptedBackup
                self._encrypted_backup = EncryptedBackup(backup_directory=str(source), passphrase=password)
            except Exception as exc:
                raise ForensicError("Could not unlock encrypted backup. The backup password may be incorrect.") from exc

    def is_encrypted(self) -> bool:
        return self.encrypted

    def save_manifest_db(self) -> Path:
        self.workspace.mkdir(parents=True, exist_ok=True)
        dest = self.workspace / "Manifest.db"
        if self.encrypted:
            try:
                self._encrypted_backup.save_manifest_file(str(dest))
            except Exception as exc:
                raise ForensicError("Could not save decrypted Manifest.db from encrypted backup.") from exc
        else:
            shutil.copy2(self.source / "Manifest.db", dest)
        return dest

    def _source_object_path(self, file_id: str) -> Path | None:
        for candidate in (self.source / file_id[:2] / file_id, self.source / file_id):
            if candidate.exists():
                return candidate
        return None

    def extract_record(self, record: ManifestRecord, output_path: Path, label: str = "artifact") -> ExtractedArtifact:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        source_obj = self._source_object_path(record.file_id)
        source_hash = sha256_file(source_obj) if source_obj and source_obj.exists() else None
        try:
            if self.encrypted:
                encrypted_extract_file(self._encrypted_backup, record, output_path)
            else:
                if not source_obj:
                    raise FileNotFoundError(record.file_id)
                shutil.copy2(source_obj, output_path)
            output_hash = sha256_file(output_path)
            return ExtractedArtifact(
                label=label,
                file_id=record.file_id,
                domain=record.domain,
                relative_path=record.relative_path,
                logical_path=record.logical_path,
                source_path=str(source_obj) if source_obj else None,
                output_path=str(output_path),
                source_sha256=source_hash,
                output_sha256=output_hash,
                output_size=output_path.stat().st_size,
                encrypted=self.encrypted,
                extracted=True,
            )
        except Exception as exc:
            return ExtractedArtifact(
                label=label,
                file_id=record.file_id,
                domain=record.domain,
                relative_path=record.relative_path,
                logical_path=record.logical_path,
                source_path=str(source_obj) if source_obj else None,
                output_path=str(output_path),
                source_sha256=source_hash,
                output_sha256=None,
                output_size=0,
                encrypted=self.encrypted,
                extracted=False,
                skipped=True,
                skip_reason=str(exc),
            )


def encrypted_extract_file(backup: Any, record: ManifestRecord, output_path: Path) -> None:
    attempts = [
        lambda: backup.extract_file(relative_path=record.relative_path, domain_like=record.domain, output_filename=str(output_path)),
        lambda: backup.extract_file(relative_path=record.relative_path, domain=record.domain, output_filename=str(output_path)),
        lambda: backup.extract_file(relative_path=record.relative_path, output_filename=str(output_path)),
        lambda: backup.extract_file(record.relative_path, str(output_path)),
    ]
    errors: list[str] = []
    for attempt in attempts:
        try:
            attempt()
            if output_path.exists():
                return
        except TypeError as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(str(exc))
    raise ForensicError(f"Encrypted extraction failed for {record.logical_path}: {'; '.join(errors[-3:])}")


def load_manifest_records(manifest_db: Path) -> list[ManifestRecord]:
    conn = open_sqlite_ro(manifest_db)
    try:
        cur = conn.cursor()
        table = None
        for candidate in TABLE_CANDIDATES:
            try:
                cur.execute(f"SELECT count(*) FROM {candidate}")
                cur.fetchone()
                table = candidate
                break
            except sqlite3.Error:
                continue
        if not table:
            raise ForensicError("Unrecognized Manifest.db schema (no Files/files/file table).")
        columns = [row["name"] for row in cur.execute(f"PRAGMA table_info({table})")]
        required = {"fileID", "domain", "relativePath"}
        if not required.issubset(set(columns)):
            raise ForensicError("Manifest.db Files table lacks fileID/domain/relativePath columns.")
        selected = [c for c in ("fileID", "domain", "relativePath", "flags", "file") if c in columns]
        records: list[ManifestRecord] = []
        for row in cur.execute(f"SELECT {', '.join(selected)} FROM {table}"):
            blob = row["file"] if "file" in selected else None
            metadata: dict[str, Any] = {}
            if blob:
                try:
                    metadata = plistlib.loads(blob)
                except Exception:
                    metadata = {"_plist_parse_error": True}
            records.append(
                ManifestRecord(
                    file_id=row["fileID"] or "",
                    domain=row["domain"] or "",
                    relative_path=row["relativePath"] or "",
                    flags=row["flags"] if "flags" in selected else None,
                    file_blob=blob,
                    metadata=metadata,
                )
            )
        return records
    finally:
        conn.close()


def export_manifest_index(records: list[ManifestRecord], output: Path) -> None:
    rows = [
        {
            "file_id": r.file_id,
            "domain": r.domain,
            "relative_path": r.relative_path,
            "flags": r.flags,
            "has_metadata": bool(r.metadata),
            "logical_path": r.logical_path,
        }
        for r in records
    ]
    write_csv(output / "_workspace" / "manifest_index.csv", rows)
    write_json(output / "_workspace" / "manifest_index.json", rows)


def _artifact_rows(artifacts: list[ExtractedArtifact]) -> list[dict[str, Any]]:
    return [asdict(a) for a in artifacts]


def _write_evidence_manifest(output: Path, artifacts: list[ExtractedArtifact]) -> None:
    fields = list(asdict(ExtractedArtifact("", "", "", "", "", None, "", None, None, 0, False, False)).keys())
    rows = _artifact_rows(artifacts)
    write_csv(output / "evidence_manifest.csv", rows, fields)
    write_json(output / "evidence_manifest.json", rows)
    write_table_html(output / "evidence_manifest.html", "Evidence Manifest", rows)


def _write_log(output: Path, lines: list[str]) -> None:
    (output / "extraction_log.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_timeline(output: Path) -> None:
    rows: list[dict[str, Any]] = []
    sms_timeline = output / "sms" / "sms_timeline.csv"
    if sms_timeline.exists():
        with sms_timeline.open("r", newline="", encoding="utf-8") as f:
            rows.extend(dict(row) for row in csv.DictReader(f))
    for hit_file in (output / "teams" / "teams_keyword_hits.json", output / "teams" / "teams_text_keyword_hits.json", output / "deep_scan" / "deep_keyword_hits.json"):
        if not hit_file.exists():
            continue
        for hit in plist_safe_json(hit_file):
            rows.append(
                {
                    "datetime_utc": "",
                    "source": hit.get("source_type", ""),
                    "keyword": hit.get("keyword", ""),
                    "app_guess": hit.get("app_guess", ""),
                    "domain": hit.get("domain", ""),
                    "relative_path": hit.get("relative_path", ""),
                    "table": hit.get("table", ""),
                    "column": hit.get("column", ""),
                    "snippet": hit.get("snippet", ""),
                    "confidence": "none",
                    "parser_note": hit.get("parser_note", "No confident timestamp available"),
                }
            )
    fields = ["datetime_utc", "source", "keyword", "app_guess", "domain", "relative_path", "table", "column", "snippet", "confidence", "parser_note"]
    rows.sort(key=lambda r: r.get("datetime_utc") or "9999")
    write_csv(output / "timeline.csv", rows, fields)
    write_json(output / "timeline.json", rows)
    write_table_html(output / "timeline.html", "Forensic Timeline", rows)


def plist_safe_json(path: Path) -> list[dict[str, Any]]:
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def run_forensic_triage(args: argparse.Namespace) -> TriageResult:
    source = Path(args.source).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    log_lines: list[str] = []
    manifest_plist, info_plist = validate_backup_source(source, output)
    log_lines.append("Loaded Manifest.plist")
    backup_encrypted = bool(manifest_plist.get("IsEncrypted", False))
    log_lines.append(f"Backup encrypted: {str(backup_encrypted).lower()}")
    password = get_password(args)
    extractor = BackupExtractor(source, output, password)
    manifest_db = extractor.save_manifest_db()
    log_lines.append("Saved decrypted Manifest.db" if backup_encrypted else "Copied Manifest.db to workspace")
    records = load_manifest_records(manifest_db)
    export_manifest_index(records, output)
    log_lines.append("Loaded manifest records")
    index = {(r.domain, r.relative_path): r for r in records}
    artifacts: list[ExtractedArtifact] = []
    sms_count = 0
    teams_result: dict[str, Any] = {"candidate_files": 0, "sqlite_databases": 0, "keyword_hits": 0, "text_hits": 0}
    deep_result: dict[str, Any] = {"candidate_files": 0, "extracted_files": 0, "keyword_hits": 0, "skipped_files": 0, "sqlite_databases": 0, "text_files": 0}
    targets = set(args.targets)
    if targets.intersection({"sms", "messages", "imessage"}):
        sms_artifacts, sms_warnings = extract_sms_artifacts(records, index, extractor, output, include_attachments=not args.no_attachments)
        artifacts.extend(sms_artifacts)
        warnings.extend(sms_warnings)
        sms_db = output / "extracted_files" / "HomeDomain" / "Library" / "SMS" / "sms.db"
        sms_parse = parse_sms_exports(sms_db, output / "sms", warnings)
        sms_count = sms_parse.get("messages", 0)
        log_lines.append("Extracted SMS database")
        log_lines.append("Parsed SMS messages")
    if targets.intersection({"teams", "microsoft_teams"}):
        teams_result = run_teams_triage(records, extractor, output, args.keyword, args.sample_limit, args.max_teams_file_mb, args.include_large_teams_files, warnings)
        artifacts.extend(teams_result.pop("artifacts"))
        log_lines.append("Found Teams candidates")
    if args.deep_app_cache_scan:
        deep_keywords = list(dict.fromkeys(DEFAULT_DEEP_KEYWORDS + args.deep_keyword))
        deep_result = run_deep_scan(records, extractor, output, deep_keywords, args.max_deep_file_mb, args.include_large_deep_files, args.deep_scan_text_limit_mb, args.deep_scan_sqlite_row_limit, warnings)
        artifacts.extend(deep_result.pop("artifacts"))
        log_lines.append("Ran deep app cache scan")
    if args.write_timeline:
        _write_timeline(output)
    _write_evidence_manifest(output, artifacts)
    log_lines.append("Wrote evidence manifest")
    write_json(output / "warnings.json", warnings)
    summary = {
        "generated_utc": utc_now_iso(),
        "source_backup": str(source),
        "output": str(output),
        "backup_encrypted": backup_encrypted,
        "device": {
            "display_name": info_plist.get("Display Name"),
            "product_type": info_plist.get("Product Type"),
            "product_version": info_plist.get("Product Version"),
            "last_backup_date": str(info_plist.get("Last Backup Date") or ""),
        },
        "manifest": {
            "date": str(manifest_plist.get("Date") or ""),
            "version": manifest_plist.get("Version"),
            "system_domains_version": manifest_plist.get("SystemDomainsVersion"),
            "records": len(records),
        },
        "results": {
            "extracted_artifacts": sum(1 for a in artifacts if a.extracted),
            "sms_messages_parsed": sms_count,
            "sms_attachments_extracted": sum(1 for a in artifacts if a.label == "sms_attachment" and a.extracted),
            "teams_candidate_files": teams_result.get("candidate_files", 0),
            "teams_sqlite_databases_inspected": teams_result.get("sqlite_databases", 0),
            "teams_sqlite_keyword_hits": teams_result.get("keyword_hits", 0),
            "teams_text_keyword_hits": teams_result.get("text_hits", 0),
            "deep_scan_candidate_files": deep_result.get("candidate_files", 0),
            "deep_scan_extracted_files": deep_result.get("extracted_files", 0),
            "deep_scan_skipped_files": deep_result.get("skipped_files", 0),
            "deep_scan_sqlite_databases_scanned": deep_result.get("sqlite_databases", 0),
            "deep_scan_text_files_scanned": deep_result.get("text_files", 0),
            "deep_scan_keyword_hits": deep_result.get("keyword_hits", 0),
        },
        "warnings": warnings,
        "notes": [
            "Original backup was not modified.",
            "Encrypted artefacts were decrypted into the output folder only.",
            "Microsoft Teams is cloud-backed; absence of local message bodies does not prove messages never existed server-side.",
        ],
    }
    write_case_summary(output / "case_summary.json", output / "case_summary.html", summary)
    log_lines.append("Wrote case summary")
    _write_log(output, log_lines)
    log_ok(f"Forensic triage complete: {output}")
    return TriageResult(
        output=str(output),
        backup_encrypted=backup_encrypted,
        manifest_records=len(records),
        extracted_artifacts=sum(1 for a in artifacts if a.extracted),
        sms_messages=sms_count,
        teams_candidate_files=teams_result.get("candidate_files", 0),
        teams_sqlite_dbs=teams_result.get("sqlite_databases", 0),
        teams_keyword_hits=teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0),
        deep_scan_candidate_files=deep_result.get("candidate_files", 0),
        deep_scan_extracted_files=deep_result.get("extracted_files", 0),
        deep_scan_keyword_hits=deep_result.get("keyword_hits", 0),
        warnings=warnings,
    )
