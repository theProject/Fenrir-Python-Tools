from pathlib import Path

import pytest

from tools.forensic_backup import encrypted_extract_file
from tools.forensic_common import classify_warning_message
from tools.forensic_models import ForensicError, ManifestRecord
from tools.forensic_system_artifacts import run_system_artifacts


def _record(relative_path: str = "Library/Caches/cache.sqlite") -> ManifestRecord:
    return ManifestRecord("aa000001", "AppDomain-com.example.app", relative_path, metadata={"Mode": 0o100644})


class ModernEncryptedBackup:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, str]] = []

    def extract_file(self, *, relative_path, domain_like=None, output_filename):
        self.calls.append((relative_path, domain_like, output_filename))
        Path(output_filename).write_text("modern encrypted extract", encoding="utf-8")


class PositionalEncryptedBackup:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def extract_file(self, relative_path, output_filename, /):
        self.calls.append((relative_path, output_filename))
        Path(output_filename).write_text("positional encrypted extract", encoding="utf-8")


class FailingEncryptedBackup:
    def extract_file(self, *, relative_path, domain_like=None, output_filename):
        raise RuntimeError("decrypt-size mismatch while extracting")


class NoExtractDirectoryExtractor:
    def __init__(self) -> None:
        self.extract_calls = 0

    def is_encrypted(self) -> bool:
        return True

    def source_object_path(self, file_id: str):
        return None

    def extract_record(self, record, output_path, label="artifact"):
        self.extract_calls += 1
        raise AssertionError("directory records must be skipped before encrypted extraction")


def test_encrypted_extract_file_modern_keyword_only_signature(tmp_path):
    backup = ModernEncryptedBackup()
    output = tmp_path / "cache.sqlite"
    record = _record()

    encrypted_extract_file(backup, record, output)

    assert output.read_text(encoding="utf-8") == "modern encrypted extract"
    assert backup.calls == [(record.relative_path, record.domain, str(output))]


def test_encrypted_extract_file_positional_only_signature(tmp_path):
    backup = PositionalEncryptedBackup()
    output = tmp_path / "cache.sqlite"
    record = _record()

    encrypted_extract_file(backup, record, output)

    assert output.read_text(encoding="utf-8") == "positional encrypted extract"
    assert backup.calls == [(record.relative_path, str(output))]


def test_encrypted_extract_file_failure_classification(tmp_path):
    with pytest.raises(ForensicError) as exc:
        encrypted_extract_file(FailingEncryptedBackup(), _record(), tmp_path / "out.sqlite")

    message = str(exc.value)
    classified = classify_warning_message(message)
    assert "Encrypted extraction failed" in message
    assert "unexpected keyword argument 'domain'" not in message
    assert classified["warning_category"] == "decrypt_size_mismatch"
    assert classified["warning_severity"] == "warning"


def test_directory_record_skipped_before_encrypted_extract_attempt(tmp_path):
    extractor = NoExtractDirectoryExtractor()
    record = ManifestRecord("aa000002", "AppDomain-com.microsoft.Office.Outlook", "Library/HTTPStorages")
    warnings: list[str] = []

    result = run_system_artifacts(
        [record],
        extractor,
        tmp_path / "case",
        ["Tesla"],
        {"outlook_scan": True},
        20,
        False,
        20,
        0,
        120,
        [],
        500,
        warnings,
    )

    assert extractor.extract_calls == 0
    assert result["directory_records_skipped"] == 1
    assert warnings == []
