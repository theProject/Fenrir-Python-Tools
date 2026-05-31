import csv
import json
import plistlib
import sqlite3
from pathlib import Path

from tools.forensic_backup import BackupExtractor, add_forensic_parser, run_forensic_triage, write_review_exports
from tools.forensic_common import classify_warning_message
from tools.forensic_models import ManifestRecord
from tools.forensic_sms import extract_sms_artifacts
from tools.forensic_system_artifacts import compound_keyword_hits, run_system_artifacts, sqlite_integrity_check


def _backup(tmp_path: Path) -> Path:
    backup = tmp_path / "BACKUP_UUID"
    backup.mkdir()
    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)
    return backup


def _object(backup: Path, file_id: str, data: bytes) -> None:
    folder = backup / file_id[:2]
    folder.mkdir(exist_ok=True)
    (folder / file_id).write_bytes(data)


def _record(file_id: str, domain: str, relative_path: str) -> ManifestRecord:
    return ManifestRecord(file_id, domain, relative_path)


def _run(tmp_path, records, keywords, flags):
    backup = records.pop("_backup")
    output = tmp_path / "case-output"
    warnings: list[str] = []
    result = run_system_artifacts(
        list(records.values()),
        BackupExtractor(backup, output, None),
        output,
        keywords,
        flags,
        20,
        False,
        20,
        0,
        120,
        [],
        500,
        warnings,
    )
    return output, warnings, result


def test_system_artifacts_notification_plist_and_keyboard_hits(tmp_path):
    backup = _backup(tmp_path)
    _object(backup, "aa000001", plistlib.dumps({"body": "Tesla notification body"}))
    _object(backup, "aa000002", b"\x00ADHD learned keyboard term\x00")
    records = {
        "_backup": backup,
        "notification": _record("aa000001", "HomeDomain", "Library/UserNotifications/DeliveredNotifications.plist"),
        "keyboard": _record("aa000002", "HomeDomain", "Library/Keyboard/DynamicLexicon.dat"),
    }

    output, warnings, result = _run(tmp_path, records, ["Tesla", "ADHD"], {"notification_scan": True, "keyboard_scan": True})

    assert warnings == []
    assert result["notification_hits"] == 1
    assert result["keyboard_hits"] == 1
    assert "notification_fragment" in (output / "system_artifacts" / "notification_keyword_hits.csv").read_text(encoding="utf-8")
    assert "keyboard_lexicon" in (output / "system_artifacts" / "keyboard_keyword_hits.csv").read_text(encoding="utf-8")


def test_system_artifacts_mail_outlook_chrome_and_tesla_hits(tmp_path):
    backup = _backup(tmp_path)
    mail_db = tmp_path / "mail.sqlite"
    conn = sqlite3.connect(mail_db)
    conn.execute("CREATE TABLE messages (subject TEXT, sender TEXT, body TEXT)")
    conn.execute("INSERT INTO messages VALUES ('Teams alert', 'noreply@example.com', 'Microsoft Teams sent a message about Julio')")
    conn.commit()
    conn.close()
    _object(backup, "bb000001", mail_db.read_bytes())
    _object(backup, "bb000002", b"Outlook offline cache mentions Jake")
    _object(backup, "bb000003", b'{"url":"https://example.test","title":"Chrome history ADHD"}')
    _object(backup, "bb000004", b'{"vehicle":"Tesla charging event"}')
    records = {
        "_backup": backup,
        "mail": _record("bb000001", "HomeDomain", "Library/Mail/Envelope Index"),
        "outlook": _record("bb000002", "AppDomain-com.microsoft.Office.Outlook", "Library/Caches/offline.txt"),
        "chrome": _record("bb000003", "AppDomain-com.google.chrome.ios", "Library/WebKit/History.json"),
        "tesla": _record("bb000004", "AppDomain-com.teslamotors.TeslaApp", "Library/Caches/state.json"),
    }

    output, warnings, result = _run(tmp_path, records, ["Julio", "Jake", "ADHD", "Tesla"], {"mail_scan": True, "outlook_scan": True, "chrome_scan": True, "tesla_app_scan": True})

    assert warnings == []
    assert result["mail_hits"] >= 1
    assert result["outlook_hits"] == 1
    assert result["chrome_hits"] == 1
    assert result["tesla_app_hits"] == 1
    assert "mail_record" in (output / "system_artifacts" / "mail_keyword_hits.csv").read_text(encoding="utf-8")
    assert "Jake" in (output / "system_artifacts" / "outlook_keyword_hits.csv").read_text(encoding="utf-8")
    assert "ADHD" in (output / "system_artifacts" / "chrome_keyword_hits.csv").read_text(encoding="utf-8")
    assert "Tesla" in (output / "system_artifacts" / "tesla_app_keyword_hits.csv").read_text(encoding="utf-8")


def test_microsoft_coredata_person_hit_and_related_activity(tmp_path):
    backup = _backup(tmp_path)
    db = tmp_path / "coredata.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE ZSPPERSON (Z_PK INTEGER PRIMARY KEY, ZDISPLAYNAME TEXT, ZEMAIL TEXT)")
    conn.execute("CREATE TABLE ZSPACTIVITY (Z_PK INTEGER PRIMARY KEY, ZPERSON INTEGER, ZTITLE TEXT)")
    conn.execute("INSERT INTO ZSPPERSON VALUES (7, 'Bikrom Example', 'person@example.test')")
    conn.execute("INSERT INTO ZSPACTIVITY VALUES (9, 7, 'Opened SharePoint list item')")
    conn.commit()
    conn.close()
    _object(backup, "cc000001", db.read_bytes())
    records = {
        "_backup": backup,
        "core": _record("cc000001", "AppDomain-com.microsoft.sharepoint", "Library/Caches/coredata.sqlite"),
    }

    output, warnings, result = _run(tmp_path, records, ["Bikrom"], {"microsoft_coredata_scan": True})

    assert warnings == []
    assert result["microsoft_coredata_person_hits"] == 1
    assert result["microsoft_coredata_related_rows"] == 1
    person_hits = (output / "microsoft_coredata" / "person_hits.csv").read_text(encoding="utf-8")
    related = (output / "microsoft_coredata" / "related_rows.csv").read_text(encoding="utf-8")
    schema = (output / "microsoft_coredata" / "schema_relationships.csv").read_text(encoding="utf-8")
    assert "coredata_entity" in person_hits
    assert "ZSPACTIVITY" in related
    assert "coredata_relationship_candidate" in schema


def test_raw_string_and_sqlite_raw_byte_carves(tmp_path):
    backup = _backup(tmp_path)
    raw_db = tmp_path / "raw.sqlite"
    conn = sqlite3.connect(raw_db)
    conn.execute("CREATE TABLE live (body TEXT)")
    conn.execute("INSERT INTO live VALUES ('no live keyword here')")
    conn.commit()
    conn.close()
    _object(backup, "dd000001", b"\x00\x01prefix Tesla raw binary string\x02")
    _object(backup, "dd000002", raw_db.read_bytes() + b"\x00freepage ADHD sqlite bytes\x00")
    records = {
        "_backup": backup,
        "raw": _record("dd000001", "AppDomain-com.google.chrome.ios", "Library/Caches/blob.bin"),
        "sqlite": _record("dd000002", "AppDomain-com.example.app", "Library/Caches/cache.sqlite"),
    }

    output, warnings, result = _run(tmp_path, records, ["Tesla", "ADHD"], {"raw_string_carve": True, "sqlite_carve": True})

    assert warnings == []
    assert result["raw_string_hits"] >= 1
    assert result["sqlite_raw_hits"] >= 1
    assert "binary_text_fragment" in (output / "system_artifacts" / "raw_string_hits.csv").read_text(encoding="utf-8")
    assert "sqlite_raw_bytes" in (output / "system_artifacts" / "sqlite_raw_hits.csv").read_text(encoding="utf-8")


def test_compound_keyword_matching_rules():
    rows = [{"clean_snippet": "Monitor context followed by ADHD in the same window"}]
    assert compound_keyword_hits(rows, ["Monitor", "ADHD"], 500)
    assert compound_keyword_hits(rows, ["Monitor,ADHD"], 500)
    assert compound_keyword_hits(rows, ["Monitor"], 500) == []
    assert compound_keyword_hits([{"clean_snippet": "Monitor" + ("x" * 600) + "ADHD"}], ["Monitor", "ADHD"], 100) == []


def test_system_artifacts_missing_file_warns_and_continues(tmp_path):
    backup = _backup(tmp_path)
    records = {
        "_backup": backup,
        "missing": _record("ee000001", "HomeDomain", "Library/UserNotifications/missing.plist"),
    }

    output, warnings, result = _run(tmp_path, records, ["Tesla"], {"notification_scan": True})

    assert result["extraction_failures"] == 1
    assert warnings
    assert (output / "system_artifacts" / "system_candidate_files.csv").exists()


def test_system_artifacts_corrupt_sqlite_warns_and_continues(tmp_path):
    backup = _backup(tmp_path)
    _object(backup, "ee000002", b"SQLite format 3\x00not really a database")
    records = {
        "_backup": backup,
        "corrupt": _record("ee000002", "HomeDomain", "Library/Mail/Envelope Index"),
    }

    output, warnings, result = _run(tmp_path, records, ["Teams"], {"mail_scan": True})

    assert result["extracted_files"] == 1
    assert warnings
    assert (output / "system_artifacts" / "mail_keyword_hits.csv").exists()


def test_forensics_cli_system_artifact_flags_parse():
    import argparse

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    add_forensic_parser(sub)
    args = parser.parse_args([
        "forensics",
        "--source",
        "/tmp/backup",
        "--system-artifacts",
        "--compound-keyword",
        "monitor,ADHD",
        "--compound-window",
        "250",
    ])

    assert args.system_artifacts is True
    assert args.compound_keyword == ["monitor,ADHD"]
    assert args.compound_window == 250


def test_forensics_e2e_writes_system_counts_to_case_summary(tmp_path):
    backup = _backup(tmp_path)
    _object(backup, "ff000001", plistlib.dumps({"body": "Tesla notification body"}))
    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
    conn.execute("INSERT INTO Files VALUES (?, ?, ?)", ("ff000001", "HomeDomain", "Library/UserNotifications/DeliveredNotifications.plist"))
    conn.commit()
    conn.close()
    output = tmp_path / "case"
    args = type(
        "Args",
        (),
        {
            "source": str(backup),
            "output": str(output),
            "targets": ["teams"],
            "password_env": None,
            "password": None,
            "prompt_password": False,
            "no_attachments": False,
            "keyword": ["Tesla"],
            "sample_limit": 50,
            "max_teams_file_mb": 20,
            "include_large_teams_files": False,
            "deep_app_cache_scan": False,
            "deep_keyword": [],
            "max_deep_file_mb": 20,
            "include_large_deep_files": False,
            "deep_scan_text_limit_mb": 20,
            "deep_scan_sqlite_row_limit": 0,
            "deep_scan_export_context": 120,
            "write_timeline": False,
            "system_artifacts": False,
            "notification_scan": True,
            "mail_scan": False,
            "keyboard_scan": False,
            "outlook_scan": False,
            "chrome_scan": False,
            "tesla_app_scan": False,
            "microsoft_coredata_scan": False,
            "raw_string_carve": False,
            "sqlite_carve": False,
            "compound_keyword": ["Tesla,notification"],
            "compound_window": 500,
        },
    )()

    run_forensic_triage(args)

    summary = json.loads((output / "case_summary.json").read_text(encoding="utf-8"))
    assert summary["results"]["notification_hits"] == 1
    assert summary["results"]["compound_keyword_hits"] == 1


def test_milestone_2_1_warning_classification_distinguishes_decrypt_size_mismatch():
    mismatch = classify_warning_message("Size of decrypted file does not match expected size")
    failure = classify_warning_message("Could not extract system artefact HomeDomain/file.db: no such file")

    assert mismatch["warning_category"] == "decrypt_size_mismatch"
    assert mismatch["warning_severity"] == "warning"
    assert "warning-level" in mismatch["professional_note"]
    assert failure["warning_category"] == "extraction_failure"
    assert failure["warning_severity"] == "error"


def test_milestone_2_1_system_sqlite_integrity_report_generation(tmp_path):
    backup = _backup(tmp_path)
    db = tmp_path / "notification.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE notifications (body TEXT)")
    conn.execute("INSERT INTO notifications VALUES ('Tesla notification row')")
    conn.commit()
    conn.close()
    _object(backup, "99000001", db.read_bytes())
    record = _record("99000001", "HomeDomain", "Library/UserNotifications/notifications.sqlite")
    direct = sqlite_integrity_check(db, record)
    records = {"_backup": backup, "notification": record}

    output, warnings, result = _run(tmp_path, records, ["Tesla"], {"notification_scan": True})

    assert direct["integrity_status"] == "ok"
    assert warnings == []
    assert result["sqlite_integrity_checked"] == 1
    assert result["sqlite_integrity_ok"] == 1
    integrity_csv = (output / "system_artifacts" / "sqlite_integrity_checks.csv").read_text(encoding="utf-8")
    assert "integrity_status" in integrity_csv
    assert "ok" in integrity_csv


def test_milestone_2_1_focused_review_exports_and_summary_tables(tmp_path):
    output = tmp_path / "case"
    (output / "system_artifacts").mkdir(parents=True)
    (output / "microsoft_coredata").mkdir(parents=True)
    (output / "system_artifacts" / "notification_keyword_hits.json").write_text(
        json.dumps([
            {
                "keyword": "Tesla",
                "clean_snippet": "Tesla and ADHD notification fragment",
                "app_guess": "com.apple.usernotifications",
                "evidence_class": "notification_fragment",
                "table": "",
                "logical_path": "HomeDomain/Library/UserNotifications/db.sqlite",
            }
        ]),
        encoding="utf-8",
    )
    (output / "system_artifacts" / "outlook_keyword_hits.json").write_text(
        json.dumps([
            {
                "keyword": "Bikrom",
                "clean_snippet": "Outlook cache row for Bikrom",
                "app_guess": "com.microsoft.Office.Outlook",
                "evidence_class": "raw_text",
                "table": "messages",
                "logical_path": "AppDomain-com.microsoft.Office.Outlook/Library/Caches/message.sqlite",
            }
        ]),
        encoding="utf-8",
    )
    (output / "system_artifacts" / "tesla_app_keyword_hits.json").write_text(
        json.dumps([
            {
                "keyword": "Tesla",
                "clean_snippet": "Tesla app trace",
                "app_guess": "com.teslamotors.TeslaApp",
                "evidence_class": "raw_text",
                "table": "",
                "logical_path": "AppDomain-com.teslamotors.TeslaApp/Library/Caches/state.json",
            }
        ]),
        encoding="utf-8",
    )
    (output / "microsoft_coredata" / "person_hits.json").write_text(
        json.dumps([
            {
                "keyword": "Bikrom",
                "clean_snippet": "Bikrom Example",
                "app_guess": "com.microsoft.sharepoint",
                "evidence_class": "coredata_entity",
                "table": "ZSPPERSON",
                "logical_path": "AppDomain-com.microsoft.sharepoint/Library/Caches/coredata.sqlite",
            }
        ]),
        encoding="utf-8",
    )
    (output / "microsoft_coredata" / "related_rows.json").write_text(
        json.dumps([
            {
                "clean_snippet": "Related SharePoint activity row",
                "app_guess": "com.microsoft.sharepoint",
                "evidence_class": "coredata_entity",
                "table": "ZSPACTIVITY",
                "logical_path": "AppDomain-com.microsoft.sharepoint/Library/Caches/coredata.sqlite",
            }
        ]),
        encoding="utf-8",
    )

    result = write_review_exports(output, ["Tesla", "ADHD"], 500)

    assert result["focused_review_hits"] >= 5
    focused = (output / "review" / "focused_review_hits.csv").read_text(encoding="utf-8")
    assert "microsoft_coredata_person_hits" in focused
    assert "microsoft_coredata_related_rows" in focused
    assert "notifications" in focused
    assert "outlook" in focused
    assert "tesla_app_traces" in focused
    assert (output / "review" / "focused_summary_by_keyword.csv").exists()
    assert (output / "review" / "focused_summary_by_app_domain.csv").exists()
    assert (output / "review" / "focused_summary_by_evidence_class.csv").exists()
    assert (output / "review" / "focused_summary_by_table.csv").exists()
    assert (output / "review" / "focused_summary_by_logical_path.csv").exists()


def test_milestone_2_1_duplicate_extraction_reuses_existing_artifact(tmp_path):
    backup = _backup(tmp_path)
    db = tmp_path / "message.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE messages (body TEXT)")
    conn.execute("INSERT INTO messages VALUES ('Jake in Outlook cache')")
    conn.commit()
    conn.close()
    _object(backup, "ab900001", db.read_bytes())
    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
    conn.execute(
        "INSERT INTO Files VALUES (?, ?, ?)",
        ("ab900001", "AppDomain-com.microsoft.Office.Outlook", "Library/Caches/message.sqlite"),
    )
    conn.commit()
    conn.close()
    output = tmp_path / "case"
    args = type(
        "Args",
        (),
        {
            "source": str(backup),
            "output": str(output),
            "targets": ["teams"],
            "password_env": None,
            "password": None,
            "prompt_password": False,
            "no_attachments": False,
            "keyword": ["Jake"],
            "sample_limit": 50,
            "max_teams_file_mb": 20,
            "include_large_teams_files": False,
            "deep_app_cache_scan": False,
            "deep_keyword": [],
            "max_deep_file_mb": 20,
            "include_large_deep_files": False,
            "deep_scan_text_limit_mb": 20,
            "deep_scan_sqlite_row_limit": 0,
            "deep_scan_export_context": 120,
            "write_timeline": False,
            "system_artifacts": False,
            "notification_scan": False,
            "mail_scan": False,
            "keyboard_scan": False,
            "outlook_scan": True,
            "chrome_scan": False,
            "tesla_app_scan": False,
            "microsoft_coredata_scan": False,
            "raw_string_carve": False,
            "sqlite_carve": False,
            "compound_keyword": [],
            "compound_window": 500,
        },
    )()

    run_forensic_triage(args)

    manifest_rows = list(csv.DictReader((output / "evidence_manifest.csv").open("r", newline="", encoding="utf-8")))
    same_file_rows = [row for row in manifest_rows if row["file_id"] == "ab900001"]
    assert len(same_file_rows) == 2
    assert same_file_rows[0]["output_path"] == same_file_rows[1]["output_path"]
    assert "Reused previously extracted artefact" in same_file_rows[1]["notes"]
    assert not (output / "system_artifacts" / "extracted_files" / "AppDomain-com.microsoft.Office.Outlook" / "Library" / "Caches" / "message.sqlite").exists()
    summary = json.loads((output / "case_summary.json").read_text(encoding="utf-8"))
    assert summary["results"]["system_reused_files"] == 1


def test_milestone_2_1_sms_exact_path_extraction_still_extracts_db_wal_and_shm(tmp_path):
    backup = _backup(tmp_path)
    _object(backup, "ac000001", b"SQLite format 3\x00sms")
    _object(backup, "ac000002", b"wal")
    _object(backup, "ac000003", b"shm")
    records = [
        _record("ac000001", "HomeDomain", "Library/SMS/sms.db"),
        _record("ac000002", "HomeDomain", "Library/SMS/sms.db-wal"),
        _record("ac000003", "HomeDomain", "Library/SMS/sms.db-shm"),
    ]
    index = {(record.domain, record.relative_path): record for record in records}
    output = tmp_path / "case"
    extractor = BackupExtractor(backup, output, None)

    artifacts, warnings = extract_sms_artifacts(records, index, extractor, output, include_attachments=False)

    assert warnings == []
    assert len(artifacts) == 3
    assert (output / "extracted_files" / "HomeDomain" / "Library" / "SMS" / "sms.db").exists()
    assert (output / "extracted_files" / "HomeDomain" / "Library" / "SMS" / "sms.db-wal").exists()
    assert (output / "extracted_files" / "HomeDomain" / "Library" / "SMS" / "sms.db-shm").exists()
    assert all("_path_collisions" not in artifact.output_path for artifact in artifacts)
