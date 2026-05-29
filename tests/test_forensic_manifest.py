import plistlib
import sqlite3
from pathlib import Path

from tools.forensic_backup import BackupExtractor, export_manifest_index, load_manifest_records, run_forensic_triage


def make_backup(root: Path) -> Path:
    backup = root / "BACKUP_UUID"
    backup.mkdir()
    (backup / "ab").mkdir()
    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)
    db = backup / "Manifest.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    conn.execute("INSERT INTO Files VALUES ('abcdef', 'HomeDomain', 'Library/SMS/sms.db', 1, ?)", (plistlib.dumps({"Size": 10}),))
    conn.commit()
    conn.close()
    (backup / "ab" / "abcdef").write_bytes(b"SQLite format 3\x00fake")
    return backup


def test_manifest_loading_and_index_export(tmp_path):
    backup = make_backup(tmp_path)
    records = load_manifest_records(backup / "Manifest.db")
    assert records[0].logical_path == "HomeDomain/Library/SMS/sms.db"
    assert records[0].metadata["Size"] == 10
    export_manifest_index(records, tmp_path / "out")
    assert (tmp_path / "out" / "_workspace" / "manifest_index.csv").exists()


def test_unencrypted_extractor_preserves_source_and_hashes(tmp_path):
    backup = make_backup(tmp_path)
    out = tmp_path / "out"
    extractor = BackupExtractor(backup, out, None)
    record = load_manifest_records(backup / "Manifest.db")[0]
    artifact = extractor.extract_record(record, out / "extracted_files" / "HomeDomain" / "Library" / "SMS" / "sms.db")
    assert artifact.extracted is True
    assert artifact.source_sha256 == artifact.output_sha256


def test_missing_sms_warns_not_crashes(tmp_path):
    backup = tmp_path / "BACKUP_UUID"
    backup.mkdir()
    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)
    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
    conn.commit()
    conn.close()
    args = type("Args", (), {
        "source": str(backup),
        "output": str(tmp_path / "case"),
        "targets": ["sms"],
        "password_env": None,
        "password": None,
        "prompt_password": False,
        "no_attachments": False,
        "keyword": [],
        "sample_limit": 10,
        "max_teams_file_mb": 1,
        "include_large_teams_files": False,
        "deep_app_cache_scan": False,
        "deep_keyword": [],
        "max_deep_file_mb": 1,
        "include_large_deep_files": False,
        "deep_scan_text_limit_mb": 1,
        "deep_scan_sqlite_row_limit": 10,
        "deep_scan_export_context": False,
        "write_timeline": False,
    })()
    result = run_forensic_triage(args)
    assert result.sms_messages == 0
    assert result.warnings
