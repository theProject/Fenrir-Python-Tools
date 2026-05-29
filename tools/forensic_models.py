from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ForensicError(RuntimeError):
    pass


@dataclass
class ManifestRecord:
    file_id: str
    domain: str
    relative_path: str
    flags: int | None = None
    file_blob: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def logical_path(self) -> str:
        return f"{self.domain}/{self.relative_path}".strip("/")


@dataclass
class ExtractedArtifact:
    label: str
    file_id: str
    domain: str
    relative_path: str
    logical_path: str
    source_path: str | None
    output_path: str
    source_sha256: str | None
    output_sha256: str | None
    output_size: int
    encrypted: bool
    extracted: bool
    skipped: bool = False
    skip_reason: str = ""
    notes: str = ""


@dataclass
class DeepKeywordHit:
    keyword: str
    source_type: str
    domain: str
    relative_path: str
    logical_path: str
    file_id: str
    extracted_path: str
    file_sha256: str | None
    app_guess: str | None
    database: str | None = None
    table: str | None = None
    column: str | None = None
    rowid: str | None = None
    offset: int | None = None
    snippet: str = ""
    parser_note: str = ""


@dataclass
class TriageResult:
    output: str
    backup_encrypted: bool
    manifest_records: int
    extracted_artifacts: int
    sms_messages: int
    teams_candidate_files: int
    teams_sqlite_dbs: int
    teams_keyword_hits: int
    deep_scan_candidate_files: int = 0
    deep_scan_extracted_files: int = 0
    deep_scan_keyword_hits: int = 0
    warnings: list[str] = field(default_factory=list)
