from __future__ import annotations

import argparse
import csv
import inspect
from collections import Counter
import getpass
import os
import plistlib
import re
import shutil
import sqlite3
import warnings as py_warnings
from dataclasses import asdict
from pathlib import Path
from typing import Any

from utils import log_ok, log_warn

from tools.forensic_common import is_output_inside_source, open_sqlite_ro, safe_output_path, sha256_file
from tools.forensic_case_focus import add_case_target_args, build_case_targets, write_case_focus_exports, write_photo_candidate_exports
from tools.forensic_deep_scan import DEFAULT_DEEP_KEYWORDS, run_deep_scan
from tools.forensic_models import ExtractedArtifact, ForensicError, ManifestRecord, TriageResult
from tools.forensic_reports import set_report_options, utc_now_iso, write_case_summary, write_csv, write_json, write_table_html
from tools.forensic_reports import write_cards_html
from tools.forensic_run_control import STAGES, RunControl
from tools.forensic_sms import extract_sms_artifacts, parse_sms_exports
from tools.forensic_system_artifacts import compound_keyword_hits, run_system_artifacts
from tools.forensic_teams import run_teams_triage


TABLE_CANDIDATES = ("Files", "files", "file", "FILE")
HIGH_SIGNAL_KEYWORDS = {"tesla", "adhd", "julio", "bikrom", "accommodation", "jake", "kelly"}
NOISY_STANDALONE_KEYWORDS = {"monitor", "focus", "coding", "widescreen"}


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
    p.add_argument("--deep-scan-sqlite-row-limit", type=int, default=0, help="Rows per SQLite text column to scan; 0 means no row limit")
    p.add_argument("--deep-scan-export-context", type=int, default=240, help="Characters of context on each side of a deep-scan keyword hit")
    p.add_argument("--write-timeline", action="store_true")
    p.add_argument("--system-artifacts", action="store_true")
    p.add_argument("--notification-scan", action="store_true")
    p.add_argument("--mail-scan", action="store_true")
    p.add_argument("--keyboard-scan", action="store_true")
    p.add_argument("--outlook-scan", action="store_true")
    p.add_argument("--chrome-scan", action="store_true")
    p.add_argument("--tesla-app-scan", action="store_true")
    p.add_argument("--microsoft-coredata-scan", action="store_true")
    p.add_argument("--raw-string-carve", action="store_true")
    p.add_argument("--sqlite-carve", action="store_true")
    p.add_argument("--compound-keyword", action="append", default=[])
    p.add_argument("--compound-window", type=int, default=500)
    p.add_argument("--disable-compound-review", action="store_true")
    p.add_argument("--only-stage", choices=[*STAGES, "summary"])
    p.add_argument("--skip-stage", action="append", choices=STAGES, default=[])
    p.add_argument("--stop-after-stage", choices=STAGES)
    p.add_argument("--case-focus-only", action="store_true")
    p.add_argument("--review-only", action="store_true")
    p.add_argument("--summary-only", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--skip-existing-extractions", action="store_true")
    p.add_argument("--csv-only", action="store_true")
    p.add_argument("--no-html", action="store_true")
    p.add_argument("--no-large-html", action="store_true")
    p.add_argument("--max-report-rows", type=int, default=1000)
    p.add_argument("--max-case-review-rows", type=int, default=250)
    p.add_argument("--progress-every", type=int, default=500)
    add_case_target_args(p)


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
    def __init__(self, source: Path, output: Path, password: str | None, skip_existing: bool = False):
        self.source = source
        self.output = output
        self.workspace = output / "_workspace"
        self.extracted_root = output / "extracted_files"
        self.password = password
        self.skip_existing = skip_existing
        self.manifest_plist = _read_plist(source / "Manifest.plist")
        self.encrypted = bool(self.manifest_plist.get("IsEncrypted", False))
        self._encrypted_backup: Any | None = None
        self._extraction_cache: dict[str, ExtractedArtifact] = {}
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

    def source_object_path(self, file_id: str) -> Path | None:
        for candidate in (self.source / file_id[:2] / file_id, self.source / file_id):
            if candidate.exists():
                return candidate
        return None

    def _collision_safe_path(self, record: ManifestRecord, requested_path: Path, label: str) -> Path:
        basename = requested_path.name or Path(record.relative_path).name or "artifact"
        safe_basename = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._") or "artifact"
        prefix = record.file_id[:2] or "unknown"
        return self.output / "_path_collisions" / label / prefix / f"{record.file_id}__{safe_basename}"

    def _prepare_output_path(self, record: ManifestRecord, requested_path: Path, label: str) -> tuple[Path, str]:
        note = ""
        try:
            requested_path.parent.mkdir(parents=True, exist_ok=True)
            if requested_path.is_dir():
                raise IsADirectoryError(requested_path)
            return requested_path, note
        except (FileExistsError, NotADirectoryError, IsADirectoryError):
            fallback = self._collision_safe_path(record, requested_path, label)
            fallback.parent.mkdir(parents=True, exist_ok=True)
            note = "Preferred output path collided with an existing file/directory; artefact relocated to collision-safe path."
            return fallback, note

    def extract_record(self, record: ManifestRecord, output_path: Path, label: str = "artifact") -> ExtractedArtifact:
        cache_key = record.file_id or record.logical_path
        cached = self._extraction_cache.get(cache_key)
        if cached and cached.extracted and Path(cached.output_path).exists():
            return ExtractedArtifact(
                label=label,
                file_id=record.file_id,
                domain=record.domain,
                relative_path=record.relative_path,
                logical_path=record.logical_path,
                source_path=cached.source_path,
                output_path=cached.output_path,
                source_sha256=cached.source_sha256,
                output_sha256=cached.output_sha256,
                output_size=cached.output_size,
                encrypted=self.encrypted,
                extracted=True,
                notes=f"Reused previously extracted artefact from {cached.label}; no duplicate copy made.",
            )
        requested_path = output_path
        output_path, collision_note = self._prepare_output_path(record, requested_path, label)
        source_obj = self.source_object_path(record.file_id)
        source_hash = sha256_file(source_obj) if source_obj and source_obj.exists() else None
        if self.skip_existing and output_path.exists() and output_path.is_file():
            output_hash = sha256_file(output_path)
            artifact = ExtractedArtifact(
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
                notes="Reused existing extracted artefact because --skip-existing-extractions was set.",
            )
            self._extraction_cache[cache_key] = artifact
            return artifact
        try:
            with py_warnings.catch_warnings(record=True) as caught_warnings:
                py_warnings.simplefilter("always")
                if self.encrypted:
                    encrypted_extract_file(self._encrypted_backup, record, output_path)
                else:
                    if not source_obj:
                        raise FileNotFoundError(record.file_id)
                    shutil.copy2(source_obj, output_path)
            output_hash = sha256_file(output_path)
            warning_notes = [f"Extractor warning: {str(item.message)}" for item in caught_warnings]
            notes = " | ".join(part for part in [collision_note, *warning_notes] if part)
            artifact = ExtractedArtifact(
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
                notes=notes,
            )
            self._extraction_cache[cache_key] = artifact
            return artifact
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
                notes=collision_note,
            )


def encrypted_extract_file(backup: Any, record: ManifestRecord, output_path: Path) -> None:
    extract = getattr(backup, "extract_file", None)
    if not callable(extract):
        raise ForensicError("Encrypted extraction failed: backup adapter has no callable extract_file method.")
    try:
        signature = inspect.signature(extract)
    except (TypeError, ValueError):
        signature = None
    errors: list[str] = []

    def finish(result: Any) -> bool:
        if isinstance(result, (bytes, bytearray)):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(bytes(result))
        elif isinstance(result, str | Path) and Path(result).exists() and not output_path.exists():
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(result), output_path)
        return output_path.exists()

    if signature is not None:
        params = list(signature.parameters.values())
        names = {param.name for param in params}
        has_var_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in params)
        has_var_args = any(param.kind == inspect.Parameter.VAR_POSITIONAL for param in params)
        positional_only = {param.name for param in params if param.kind == inspect.Parameter.POSITIONAL_ONLY}
        required_positional = [
            param
            for param in params
            if param.default is inspect.Parameter.empty
            and param.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
        ]
        accepts_keywords = has_var_kwargs or (
            {"relative_path", "output_filename"}.issubset(names)
            and not {"relative_path", "output_filename"}.intersection(positional_only)
        )
        if accepts_keywords:
            kwargs = {"relative_path": record.relative_path, "output_filename": str(output_path)}
            if has_var_kwargs or "domain_like" in names:
                kwargs["domain_like"] = record.domain
            try:
                if finish(extract(**kwargs)):
                    return
            except Exception as exc:
                errors.append(str(exc))
        elif has_var_args or len(required_positional) in {2, 3}:
            args = (record.relative_path, str(output_path)) if len(required_positional) <= 2 else (record.relative_path, record.domain, str(output_path))
            try:
                if finish(extract(*args)):
                    return
            except Exception as exc:
                errors.append(str(exc))
        else:
            errors.append(f"Unsupported EncryptedBackup.extract_file signature: {signature}")
    else:
        try:
            if finish(extract(relative_path=record.relative_path, domain_like=record.domain, output_filename=str(output_path))):
                return
        except Exception as exc:
            errors.append(str(exc))

    detail = "; ".join(error for error in errors if error) or "extract_file returned without creating output"
    raise ForensicError(f"Encrypted extraction failed for {record.logical_path}: {detail}")


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


def _hit_sources(output: Path) -> list[Path]:
    return [
        output / "teams" / "teams_keyword_hits.json",
        output / "teams" / "teams_text_keyword_hits.json",
        output / "deep_scan" / "deep_keyword_hits.json",
        output / "system_artifacts" / "notification_keyword_hits.json",
        output / "system_artifacts" / "mail_keyword_hits.json",
        output / "system_artifacts" / "outlook_keyword_hits.json",
        output / "system_artifacts" / "chrome_keyword_hits.json",
        output / "system_artifacts" / "tesla_app_keyword_hits.json",
        output / "system_artifacts" / "keyboard_keyword_hits.json",
        output / "system_artifacts" / "raw_string_hits.json",
        output / "system_artifacts" / "sqlite_raw_hits.json",
        output / "microsoft_coredata" / "person_hits.json",
        output / "microsoft_coredata" / "related_rows.json",
    ]


FOCUSED_REVIEW_SOURCES = {
    "microsoft_coredata_person_hits": ("Microsoft CoreData person rows are entity records, not messages.", ("microsoft_coredata", "person_hits.json")),
    "microsoft_coredata_related_rows": ("Microsoft CoreData related rows are entity/relationship records, not messages.", ("microsoft_coredata", "related_rows.json")),
    "notifications": ("Notification hits are notification fragments, not full app message recovery.", ("system_artifacts", "notification_keyword_hits.json")),
    "outlook": ("Outlook hits are local cache artefacts unless a table/column proves message content.", ("system_artifacts", "outlook_keyword_hits.json")),
    "tesla_app_traces": ("Tesla app traces are local app artefacts and should be interpreted by source path, table, and snippet quality.", ("system_artifacts", "tesla_app_keyword_hits.json")),
}


def _with_focus(rows: list[dict[str, Any]], focus: str, note: str) -> list[dict[str, Any]]:
    return [{**row, "focused_export": focus, "professional_evidence_note": note} for row in rows]


def _summary_key(row: dict[str, Any], summary_name: str) -> str:
    if summary_name == "app_domain":
        return str(row.get("app_guess") or row.get("app_or_domain") or row.get("domain") or "unknown")
    return str(row.get(summary_name) or "unknown")


def _write_summary_table(review_dir: Path, stem: str, rows: list[dict[str, Any]], summary_name: str, title: str) -> None:
    counts: Counter[str] = Counter(_summary_key(row, summary_name) for row in rows)
    data = [{"value": key, "hits": count} for key, count in counts.most_common()]
    write_csv(review_dir / f"{stem}_by_{summary_name}.csv", data)
    write_json(review_dir / f"{stem}_by_{summary_name}.json", data)
    write_table_html(review_dir / f"{stem}_by_{summary_name}.html", title, data)


def write_review_exports(output: Path, compound_keywords: list[str] | None = None, compound_window: int = 500) -> dict[str, int]:
    hits: list[dict[str, Any]] = []
    for path in _hit_sources(output):
        hits.extend(plist_safe_json(path))
    review_dir = output / "review"
    high_signal: list[dict[str, Any]] = []
    keyword_counts: Counter[str] = Counter()
    app_counts: Counter[str] = Counter()
    for hit in hits:
        keyword = str(hit.get("keyword") or "")
        keyword_lower = keyword.lower()
        keyword_counts[keyword] += 1
        app_key = str(hit.get("app_guess") or hit.get("domain") or "unknown")
        app_counts[app_key] += 1
        if keyword_lower in HIGH_SIGNAL_KEYWORDS:
            row = dict(hit)
            row["review_signal"] = "high"
            high_signal.append(row)
        elif keyword_lower in NOISY_STANDALONE_KEYWORDS:
            row = dict(hit)
            row["review_signal"] = "noisy_standalone"
    keyword_rows = [{"keyword": key, "hits": count, "signal": "high" if key.lower() in HIGH_SIGNAL_KEYWORDS else "noisy_standalone" if key.lower() in NOISY_STANDALONE_KEYWORDS else "standard"} for key, count in keyword_counts.most_common()]
    app_rows = [{"app_or_domain": key, "hits": count} for key, count in app_counts.most_common()]
    write_csv(review_dir / "high_signal_hits.csv", high_signal)
    write_json(review_dir / "high_signal_hits.json", high_signal)
    write_cards_html(review_dir / "high_signal_hits.html", "High Signal Hits", high_signal)
    write_csv(review_dir / "keyword_summary.csv", keyword_rows)
    write_json(review_dir / "keyword_summary.json", keyword_rows)
    write_table_html(review_dir / "keyword_summary.html", "Keyword Summary", keyword_rows)
    write_csv(review_dir / "app_domain_summary.csv", app_rows)
    write_json(review_dir / "app_domain_summary.json", app_rows)
    write_table_html(review_dir / "app_domain_summary.html", "App / Domain Summary", app_rows)
    compound_rows = compound_keyword_hits(hits, compound_keywords or [], compound_window)
    write_csv(review_dir / "compound_keyword_hits.csv", compound_rows)
    write_json(review_dir / "compound_keyword_hits.json", compound_rows)
    write_cards_html(review_dir / "compound_keyword_hits.html", "Compound Keyword Hits", compound_rows)
    focused_rows = _with_focus(
        compound_rows,
        "compound_keyword_hits",
        "Compound keyword hits show multiple configured terms within the review window; inspect source path and evidence class before drawing conclusions.",
    )
    write_csv(review_dir / "focused_compound_keyword_hits.csv", focused_rows)
    write_json(review_dir / "focused_compound_keyword_hits.json", focused_rows)
    write_cards_html(review_dir / "focused_compound_keyword_hits.html", "Focused Compound Keyword Hits", focused_rows)
    for focus, (note, path_parts) in FOCUSED_REVIEW_SOURCES.items():
        rows = _with_focus(plist_safe_json(output.joinpath(*path_parts)), focus, note)
        focused_rows.extend(rows)
        write_csv(review_dir / f"focused_{focus}.csv", rows)
        write_json(review_dir / f"focused_{focus}.json", rows)
        write_cards_html(review_dir / f"focused_{focus}.html", f"Focused {focus.replace('_', ' ').title()}", rows)
    write_csv(review_dir / "focused_review_hits.csv", focused_rows)
    write_json(review_dir / "focused_review_hits.json", focused_rows)
    write_cards_html(review_dir / "focused_review_hits.html", "Focused Review Hits", focused_rows)
    for summary_name, title in (
        ("keyword", "Focused Review Summary By Keyword"),
        ("app_domain", "Focused Review Summary By App / Domain"),
        ("evidence_class", "Focused Review Summary By Evidence Class"),
        ("table", "Focused Review Summary By Table"),
        ("logical_path", "Focused Review Summary By Logical Path"),
    ):
        _write_summary_table(review_dir, "focused_summary", focused_rows, summary_name, title)
    return {
        "high_signal_hits": len(high_signal),
        "reviewed_hits": len(hits),
        "focused_review_hits": len(focused_rows),
        "compound_keyword_hits": len(compound_rows),
    }


def run_forensic_triage(args: argparse.Namespace) -> TriageResult:
    source = Path(args.source).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    set_report_options(
        no_html=bool(getattr(args, "no_html", False)),
        csv_only=bool(getattr(args, "csv_only", False)),
        no_large_html=bool(getattr(args, "no_large_html", True)),
        max_report_rows=int(getattr(args, "max_report_rows", 1000) or 1000),
    )
    only_stage = getattr(args, "only_stage", None)
    if getattr(args, "case_focus_only", False):
        only_stage = "case_focus"
    if getattr(args, "review_only", False):
        only_stage = "review"
    if getattr(args, "summary_only", False):
        only_stage = "summary"
    normalized_only_stage = "case_summary" if only_stage == "summary" else only_stage
    skip_stages = list(getattr(args, "skip_stage", []) or [])
    run_control = RunControl(output, normalized_only_stage, skip_stages, getattr(args, "stop_after_stage", None))

    def stage_enabled(stage: str) -> bool:
        return run_control.enabled(stage)

    def stop_if_requested(stage: str) -> bool:
        return run_control.should_stop_after(stage)

    warnings: list[str] = []
    log_lines: list[str] = []
    manifest_plist: dict[str, Any] = {}
    info_plist: dict[str, Any] = {}
    backup_encrypted = False
    extractor: BackupExtractor | None = None
    records: list[ManifestRecord] = []
    manifest_db = output / "_workspace" / "Manifest.db"

    run_control.start("workspace")
    try:
        manifest_plist, info_plist = validate_backup_source(source, output)
        log_lines.append("Loaded Manifest.plist")
        backup_encrypted = bool(manifest_plist.get("IsEncrypted", False))
        log_lines.append(f"Backup encrypted: {str(backup_encrypted).lower()}")
        password = get_password(args)
        extractor = BackupExtractor(source, output, password, skip_existing=bool(getattr(args, "skip_existing_extractions", False)))
        if not (getattr(args, "resume", False) and manifest_db.exists()):
            manifest_db = extractor.save_manifest_db()
            log_lines.append("Saved decrypted Manifest.db" if backup_encrypted else "Copied Manifest.db to workspace")
        records = load_manifest_records(manifest_db)
        export_manifest_index(records, output)
        log_lines.append("Loaded manifest records")
        run_control.complete("workspace", {"manifest_records": len(records), "backup_encrypted": backup_encrypted})
    except Exception as exc:
        run_control.fail("workspace", exc)
        raise
    if stop_if_requested("workspace"):
        return TriageResult(str(output), backup_encrypted, len(records), 0, 0, 0, 0, 0, warnings=warnings)

    index = {(r.domain, r.relative_path): r for r in records}
    case_targets = build_case_targets(args)
    case_terms = case_targets.search_terms
    artifacts: list[ExtractedArtifact] = []
    sms_count = 0
    teams_result: dict[str, Any] = {"candidate_files": 0, "sqlite_databases": 0, "keyword_hits": 0, "text_hits": 0}
    deep_result: dict[str, Any] = {"candidate_files": 0, "extracted_files": 0, "keyword_hits": 0, "skipped_files": 0, "sqlite_databases": 0, "text_files": 0}
    system_result: dict[str, Any] = {}
    photo_result: dict[str, Any] = {"photo_candidates": 0, "screenshot_candidates": 0}
    review_result: dict[str, Any] = {"high_signal_hits": 0, "focused_review_hits": 0, "compound_keyword_hits": 0}
    case_result: dict[str, Any] = {"case_hits": 0, "case_review_queue": 0}
    targets = set(args.targets)

    if stage_enabled("sms") and targets.intersection({"sms", "messages", "imessage"}):
        if getattr(args, "resume", False) and (output / "sms" / "sms_messages.csv").exists():
            run_control.skip("sms", "resume_existing_sms_outputs")
        else:
            run_control.start("sms")
            try:
                assert extractor is not None
                sms_artifacts, sms_warnings = extract_sms_artifacts(records, index, extractor, output, include_attachments=not args.no_attachments)
                artifacts.extend(sms_artifacts)
                warnings.extend(sms_warnings)
                sms_db = output / "extracted_files" / "HomeDomain" / "Library" / "SMS" / "sms.db"
                sms_parse = parse_sms_exports(sms_db, output / "sms", warnings)
                sms_count = sms_parse.get("messages", 0)
                log_lines.append("Extracted SMS database")
                log_lines.append("Parsed SMS messages")
                run_control.complete("sms", {"messages": sms_count, "artifacts": len(sms_artifacts)})
            except Exception as exc:
                run_control.fail("sms", exc)
                raise
        if stop_if_requested("sms"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, 0, 0, 0, warnings=warnings)
    elif "sms" not in skip_stages:
        run_control.skip("sms", "stage_not_selected")

    if stage_enabled("teams") and targets.intersection({"teams", "microsoft_teams"}):
        if getattr(args, "resume", False) and (output / "teams" / "teams_candidate_files.csv").exists():
            run_control.skip("teams", "resume_existing_teams_outputs")
        else:
            run_control.start("teams")
            try:
                assert extractor is not None
                teams_result = run_teams_triage(records, extractor, output, list(dict.fromkeys(args.keyword + case_terms)), args.sample_limit, args.max_teams_file_mb, args.include_large_teams_files, warnings)
                artifacts.extend(teams_result.pop("artifacts"))
                log_lines.append("Found Teams candidates")
                run_control.complete("teams", teams_result)
            except Exception as exc:
                run_control.fail("teams", exc)
                raise
        if stop_if_requested("teams"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, teams_result.get("candidate_files", 0), teams_result.get("sqlite_databases", 0), teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0), warnings=warnings)
    elif "teams" not in skip_stages:
        run_control.skip("teams", "stage_not_selected")

    if stage_enabled("deep_scan") and args.deep_app_cache_scan:
        run_control.start("deep_scan")
        try:
            assert extractor is not None
            deep_keywords = list(dict.fromkeys(DEFAULT_DEEP_KEYWORDS + args.deep_keyword + case_terms))
            deep_result = run_deep_scan(
                records,
                extractor,
                output,
                deep_keywords,
                args.max_deep_file_mb,
                args.include_large_deep_files,
                args.deep_scan_text_limit_mb,
                args.deep_scan_sqlite_row_limit,
                args.deep_scan_export_context,
                warnings,
            )
            artifacts.extend(deep_result.pop("artifacts"))
            log_lines.append("Ran deep app cache scan")
            run_control.complete("deep_scan", deep_result)
        except Exception as exc:
            run_control.fail("deep_scan", exc)
            raise
        if stop_if_requested("deep_scan"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, teams_result.get("candidate_files", 0), teams_result.get("sqlite_databases", 0), teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0), deep_result.get("candidate_files", 0), deep_result.get("extracted_files", 0), deep_result.get("keyword_hits", 0), warnings)
    elif "deep_scan" not in skip_stages:
        run_control.skip("deep_scan", "stage_not_selected")

    system_flags = {
        "system_artifacts": bool(getattr(args, "system_artifacts", False)),
        "notification_scan": bool(getattr(args, "notification_scan", False)),
        "mail_scan": bool(getattr(args, "mail_scan", False)),
        "keyboard_scan": bool(getattr(args, "keyboard_scan", False)),
        "outlook_scan": bool(getattr(args, "outlook_scan", False)),
        "chrome_scan": bool(getattr(args, "chrome_scan", False)),
        "tesla_app_scan": bool(getattr(args, "tesla_app_scan", False)),
        "microsoft_coredata_scan": bool(getattr(args, "microsoft_coredata_scan", False)),
        "raw_string_carve": bool(getattr(args, "raw_string_carve", False)),
        "sqlite_carve": bool(getattr(args, "sqlite_carve", False)),
    }
    if case_targets.enabled:
        focus_sources = set(case_targets.focus_sources)
        system_flags["notification_scan"] = system_flags["notification_scan"] or "notifications" in focus_sources
        system_flags["mail_scan"] = system_flags["mail_scan"] or "mail" in focus_sources
        system_flags["outlook_scan"] = system_flags["outlook_scan"] or "outlook" in focus_sources
        system_flags["chrome_scan"] = system_flags["chrome_scan"] or "chrome" in focus_sources
        system_flags["tesla_app_scan"] = system_flags["tesla_app_scan"] or not focus_sources or "tesla" in " ".join(case_terms).lower()
        system_flags["microsoft_coredata_scan"] = system_flags["microsoft_coredata_scan"] or "microsoft-coredata" in focus_sources
        system_flags["raw_string_carve"] = system_flags["raw_string_carve"] or "raw" in focus_sources
        system_flags["sqlite_carve"] = system_flags["sqlite_carve"] or "sqlite-raw" in focus_sources

    if stage_enabled("system_artifacts") and (any(system_flags.values()) or getattr(args, "compound_keyword", [])):
        run_control.start("system_artifacts")
        try:
            assert extractor is not None
            system_keywords = list(dict.fromkeys(DEFAULT_DEEP_KEYWORDS + args.deep_keyword + args.keyword + case_terms))
            compound_terms = [] if getattr(args, "disable_compound_review", False) else list(getattr(args, "compound_keyword", []))
            if not getattr(args, "disable_compound_review", False):
                compound_terms.extend(f"{left},{right}" for left, right in case_targets.near_terms)
            system_result = run_system_artifacts(
                records,
                extractor,
                output,
                system_keywords,
                system_flags,
                args.max_deep_file_mb,
                args.include_large_deep_files,
                args.deep_scan_text_limit_mb,
                args.deep_scan_sqlite_row_limit,
                args.deep_scan_export_context,
                compound_terms,
                getattr(args, "compound_window", 500),
                warnings,
                getattr(args, "progress_every", 500),
            )
            artifacts.extend(system_result.pop("artifacts", []))
            log_lines.append("Ran system artefact scan")
            run_control.complete("system_artifacts", system_result)
        except Exception as exc:
            run_control.fail("system_artifacts", exc)
            raise
        if stop_if_requested("system_artifacts"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, teams_result.get("candidate_files", 0), teams_result.get("sqlite_databases", 0), teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0), deep_result.get("candidate_files", 0), deep_result.get("extracted_files", 0), deep_result.get("keyword_hits", 0), warnings)
    elif "system_artifacts" not in skip_stages:
        run_control.skip("system_artifacts", "stage_not_selected")

    include_photos = bool(getattr(args, "photo_candidate_scan", False) or "photos" in case_targets.focus_sources)
    include_screenshots = bool(getattr(args, "screenshot_candidate_scan", False) or "screenshots" in case_targets.focus_sources)
    if stage_enabled("photos") and (include_photos or include_screenshots):
        run_control.start("photos")
        try:
            photo_result = write_photo_candidate_exports(output, records, include_photos, include_screenshots)
            log_lines.append("Wrote photo/screenshot candidate reports")
            run_control.complete("photos", photo_result)
        except Exception as exc:
            run_control.fail("photos", exc)
            raise
        if stop_if_requested("photos"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, teams_result.get("candidate_files", 0), teams_result.get("sqlite_databases", 0), teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0), deep_result.get("candidate_files", 0), deep_result.get("extracted_files", 0), deep_result.get("keyword_hits", 0), warnings)
    elif "photos" not in skip_stages:
        run_control.skip("photos", "stage_not_selected")

    if stage_enabled("timeline") and args.write_timeline:
        run_control.start("timeline")
        try:
            _write_timeline(output)
            run_control.complete("timeline", {"written": True})
        except Exception as exc:
            run_control.fail("timeline", exc)
            raise
    elif "timeline" not in skip_stages:
        run_control.skip("timeline", "stage_not_selected")

    if stage_enabled("review"):
        run_control.start("review")
        try:
            review_result = write_review_exports(output, getattr(args, "compound_keyword", []), getattr(args, "compound_window", 500))
            run_control.complete("review", review_result)
        except Exception as exc:
            run_control.fail("review", exc)
            raise
        if stop_if_requested("review"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, teams_result.get("candidate_files", 0), teams_result.get("sqlite_databases", 0), teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0), deep_result.get("candidate_files", 0), deep_result.get("extracted_files", 0), deep_result.get("keyword_hits", 0), warnings)

    if stage_enabled("case_focus"):
        run_control.start("case_focus")
        try:
            case_result = write_case_focus_exports(output, case_targets, getattr(args, "max_case_review_rows", 250))
            run_control.complete("case_focus", case_result)
        except Exception as exc:
            run_control.fail("case_focus", exc)
            raise
        if stop_if_requested("case_focus"):
            return TriageResult(str(output), backup_encrypted, len(records), sum(1 for a in artifacts if a.extracted), sms_count, teams_result.get("candidate_files", 0), teams_result.get("sqlite_databases", 0), teams_result.get("keyword_hits", 0) + teams_result.get("text_hits", 0), deep_result.get("candidate_files", 0), deep_result.get("extracted_files", 0), deep_result.get("keyword_hits", 0), warnings)

    if stage_enabled("evidence_manifest"):
        run_control.start("evidence_manifest")
        try:
            _write_evidence_manifest(output, artifacts)
            log_lines.append("Wrote evidence manifest")
            run_control.complete("evidence_manifest", {"artifacts": len(artifacts), "extracted": sum(1 for a in artifacts if a.extracted)})
        except Exception as exc:
            run_control.fail("evidence_manifest", exc)
            raise
    elif "evidence_manifest" not in skip_stages:
        run_control.skip("evidence_manifest", "stage_not_selected")

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
            "extracted_files": teams_result.get("extracted_files", 0) + deep_result.get("extracted_files", 0),
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
            "deep_scan_sqlite_row_limit": deep_result.get("sqlite_row_limit", args.deep_scan_sqlite_row_limit),
            "deep_scan_export_context": deep_result.get("export_context", args.deep_scan_export_context),
            "high_signal_hits": review_result.get("high_signal_hits", 0),
            "focused_review_hits": review_result.get("focused_review_hits", 0),
            "case_focus_hits": case_result.get("case_hits", 0),
            "case_review_queue": case_result.get("case_review_queue", 0),
            "photo_candidates": photo_result.get("photo_candidates", 0),
            "screenshot_candidates": photo_result.get("screenshot_candidates", 0),
            "notification_hits": system_result.get("notification_hits", 0),
            "mail_hits": system_result.get("mail_hits", 0),
            "outlook_hits": system_result.get("outlook_hits", 0),
            "chrome_hits": system_result.get("chrome_hits", 0),
            "tesla_app_hits": system_result.get("tesla_app_hits", 0),
            "keyboard_hits": system_result.get("keyboard_hits", 0),
            "microsoft_coredata_person_hits": system_result.get("microsoft_coredata_person_hits", 0),
            "microsoft_coredata_related_rows": system_result.get("microsoft_coredata_related_rows", 0),
            "raw_string_hits": system_result.get("raw_string_hits", 0),
            "sqlite_raw_hits": system_result.get("sqlite_raw_hits", 0),
            "compound_keyword_hits": review_result.get("compound_keyword_hits", system_result.get("compound_keyword_hits", 0)),
            "system_reused_files": system_result.get("reused_files", 0),
            "system_classified_warnings": system_result.get("classified_warnings", 0),
            "decrypt_size_mismatch_warnings": system_result.get("decrypt_size_mismatch_warnings", 0),
            "system_sqlite_integrity_checked": system_result.get("sqlite_integrity_checked", 0),
            "system_sqlite_integrity_ok": system_result.get("sqlite_integrity_ok", 0),
            "system_sqlite_integrity_warnings": system_result.get("sqlite_integrity_warnings", 0),
            "system_sqlite_integrity_errors": system_result.get("sqlite_integrity_errors", 0),
            "directory_records_skipped": teams_result.get("directory_records_skipped", 0) + deep_result.get("directory_records_skipped", 0) + system_result.get("directory_records_skipped", 0),
            "extraction_failures": teams_result.get("extraction_failures", 0) + deep_result.get("extraction_failures", 0) + system_result.get("extraction_failures", 0),
        },
        "warnings": warnings,
        "notes": [
            "Original backup was not modified.",
            "Encrypted artefacts were decrypted into the output folder only.",
            "Microsoft Teams is cloud-backed; absence of local message bodies does not prove messages never existed server-side.",
            "Microsoft CoreData rows are entity/relationship records, not messages unless a source schema clearly proves message content.",
            "Raw string hits are fragment-level evidence; SQLite raw byte hits are not deleted-row recovery unless independently proven.",
            "Decrypt-size mismatch is warning-level until SQLite integrity checks or parser failures prove an extraction failure.",
        ],
    }
    if stage_enabled("case_summary"):
        run_control.start("case_summary")
        try:
            write_case_summary(output / "case_summary.json", output / "case_summary.html", summary)
            log_lines.append("Wrote case summary")
            run_control.complete("case_summary", summary["results"])
        except Exception as exc:
            run_control.fail("case_summary", exc)
            raise
    elif "case_summary" not in skip_stages:
        run_control.skip("case_summary", "stage_not_selected")
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
