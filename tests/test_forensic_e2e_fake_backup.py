import plistlib
import sqlite3
from pathlib import Path

from tools.forensic_backup import run_forensic_triage


def _write_sms_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
    conn.execute(
        "CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, date INTEGER, is_from_me INTEGER, handle_id INTEGER, text TEXT, service TEXT)"
    )
    conn.execute("INSERT INTO handle VALUES (1, '+15551234567')")
    conn.execute("INSERT INTO message VALUES (1, 'sms-guid', 700000000, 0, 1, 'Forensic SMS fixture', 'iMessage')")
    conn.commit()
    conn.close()


def _write_app_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cache_items (body TEXT)")
    conn.execute("INSERT INTO cache_items VALUES ('Tesla keyword appears in app cache')")
    conn.commit()
    conn.close()


def test_forensics_e2e_fake_mobilesync_backup(tmp_path):
    backup = tmp_path / "BACKUP_UUID"
    backup.mkdir()
    (backup / "aa").mkdir()
    (backup / "bb").mkdir()

    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False, "Version": "fixture"}, f)
    with (backup / "Info.plist").open("wb") as f:
        plistlib.dump({"Display Name": "Fixture iPhone", "Product Type": "iPhone", "Product Version": "17.0"}, f)

    _write_sms_db(backup / "aa" / "aaaaaaaa")
    _write_app_db(backup / "bb" / "bbbbbbbb")

    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    conn.execute("INSERT INTO Files VALUES (?, ?, ?, 0, NULL)", ("aaaaaaaa", "HomeDomain", "Library/SMS/sms.db"))
    conn.execute(
        "INSERT INTO Files VALUES (?, ?, ?, 0, NULL)",
        ("bbbbbbbb", "AppDomain-com.teslamotors.TeslaApp", "Library/Caches/cache.sqlite"),
    )
    conn.commit()
    conn.close()

    output = tmp_path / "case-output"
    args = type(
        "Args",
        (),
        {
            "source": str(backup),
            "output": str(output),
            "targets": ["sms", "teams"],
            "password_env": None,
            "password": None,
            "prompt_password": False,
            "no_attachments": False,
            "keyword": ["Tesla"],
            "sample_limit": 50,
            "max_teams_file_mb": 5,
            "include_large_teams_files": False,
            "deep_app_cache_scan": True,
            "deep_keyword": [],
            "max_deep_file_mb": 5,
            "include_large_deep_files": False,
            "deep_scan_text_limit_mb": 5,
            "deep_scan_sqlite_row_limit": 100,
            "deep_scan_export_context": False,
            "write_timeline": True,
        },
    )()

    run_forensic_triage(args)

    assert (output / "case_summary.json").exists()
    assert (output / "evidence_manifest.csv").exists()
    assert (output / "sms" / "sms_messages.csv").exists()
    deep_hits = output / "deep_scan" / "deep_keyword_hits.csv"
    assert deep_hits.exists()
    assert "Tesla" in deep_hits.read_text(encoding="utf-8")
