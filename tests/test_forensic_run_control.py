import json
import plistlib
import sqlite3
import sys
from pathlib import Path

from tools.forensic_backup import run_forensic_triage
from tools.forensic_case_focus import discover_photo_candidates, write_case_focus_exports, build_case_targets
from tools.forensic_models import ManifestRecord
from tools.forensic_reports import set_report_options, write_cards_html


def _backup(tmp_path: Path) -> Path:
    backup = tmp_path / "BACKUP_UUID"
    backup.mkdir()
    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)
    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
    conn.commit()
    conn.close()
    return backup


def _object(backup: Path, file_id: str, data: bytes) -> None:
    (backup / file_id[:2]).mkdir(exist_ok=True)
    (backup / file_id[:2] / file_id).write_bytes(data)


def _insert_record(backup: Path, file_id: str, domain: str, relative_path: str) -> None:
    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("INSERT INTO Files VALUES (?, ?, ?)", (file_id, domain, relative_path))
    conn.commit()
    conn.close()


def _args(backup: Path, output: Path, **overrides):
    values = {
        "source": str(backup),
        "output": str(output),
        "targets": ["sms", "teams"],
        "password_env": None,
        "password": None,
        "prompt_password": False,
        "no_attachments": False,
        "keyword": [],
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
        "outlook_scan": False,
        "chrome_scan": False,
        "tesla_app_scan": False,
        "microsoft_coredata_scan": False,
        "raw_string_carve": False,
        "sqlite_carve": False,
        "compound_keyword": [],
        "compound_window": 500,
        "disable_compound_review": False,
        "only_stage": None,
        "skip_stage": [],
        "stop_after_stage": None,
        "case_focus_only": False,
        "review_only": False,
        "summary_only": False,
        "resume": False,
        "skip_existing_extractions": False,
        "csv_only": False,
        "no_html": False,
        "no_large_html": True,
        "max_report_rows": 1000,
        "max_case_review_rows": 250,
        "progress_every": 500,
        "case_profile": None,
        "target_pack": None,
        "target_email": [],
        "target_domain": [],
        "target_person": [],
        "target_phrase": [],
        "from_date": None,
        "to_date": None,
        "near_term": [],
        "near_window": 500,
        "focus_source": [],
        "photo_candidate_scan": False,
        "screenshot_candidate_scan": False,
    }
    values.update(overrides)
    return type("Args", (), values)()


def test_partial_run_status_writes_stage_start_and_completion(tmp_path):
    backup = _backup(tmp_path)
    output = tmp_path / "case"

    run_forensic_triage(_args(backup, output, targets=["teams"]))

    status = json.loads((output / "partial_run_status.json").read_text(encoding="utf-8"))
    assert status["stages"]["workspace"]["status"] == "completed"
    assert status["stages"]["teams"]["status"] == "completed"
    assert status["stages"]["case_summary"]["status"] == "completed"
    assert (output / "run_log.txt").exists()


def test_stop_after_stage_teams_stops_cleanly_after_teams(tmp_path):
    backup = _backup(tmp_path)
    output = tmp_path / "case"

    run_forensic_triage(_args(backup, output, targets=["teams"], stop_after_stage="teams"))

    status = json.loads((output / "partial_run_status.json").read_text(encoding="utf-8"))
    assert status["stages"]["teams"]["status"] == "completed"
    assert "case_summary" not in status["stages"]
    assert not (output / "case_summary.json").exists()


def test_only_stage_system_artifacts_runs_only_that_stage_with_workspace(tmp_path):
    backup = _backup(tmp_path)
    _object(backup, "aa000001", plistlib.dumps({"body": "Tesla notification"}))
    _insert_record(backup, "aa000001", "HomeDomain", "Library/UserNotifications/DeliveredNotifications.plist")
    output = tmp_path / "case"

    run_forensic_triage(_args(backup, output, targets=["teams"], only_stage="system_artifacts", notification_scan=True, keyword=["Tesla"]))

    status = json.loads((output / "partial_run_status.json").read_text(encoding="utf-8"))
    assert status["stages"]["workspace"]["status"] == "completed"
    assert status["stages"]["system_artifacts"]["status"] == "completed"
    assert status["stages"]["teams"]["status"] == "skipped"
    assert not (output / "teams" / "teams_candidate_files.csv").exists()
    assert (output / "system_artifacts" / "notification_keyword_hits.csv").exists()


def test_case_focus_only_works_from_preexisting_outputs(tmp_path):
    backup = _backup(tmp_path)
    output = tmp_path / "case"
    (output / "system_artifacts").mkdir(parents=True)
    (output / "system_artifacts" / "outlook_keyword_hits.csv").write_text(
        "clean_snippet,evidence_class,datetime_utc\nTesla approved ADHD monitor accommodation,raw_text,2024-01-02T00:00:00+00:00\n",
        encoding="utf-8",
    )

    run_forensic_triage(
        _args(
            backup,
            output,
            targets=["teams"],
            case_focus_only=True,
            target_phrase=["ADHD"],
            near_term=["ADHD,monitor"],
            focus_source=["outlook"],
        )
    )

    assert "ADHD" in (output / "case_focus" / "case_hits.csv").read_text(encoding="utf-8")
    status = json.loads((output / "partial_run_status.json").read_text(encoding="utf-8"))
    assert status["stages"]["case_focus"]["status"] == "completed"
    assert status["stages"]["teams"]["status"] == "skipped"


def test_no_html_prevents_html_generation(tmp_path):
    backup = _backup(tmp_path)
    _object(backup, "bb000001", plistlib.dumps({"body": "Tesla notification"}))
    _insert_record(backup, "bb000001", "HomeDomain", "Library/UserNotifications/DeliveredNotifications.plist")
    output = tmp_path / "case"

    run_forensic_triage(_args(backup, output, targets=["teams"], notification_scan=True, keyword=["Tesla"], no_html=True))

    assert (output / "system_artifacts" / "notification_keyword_hits.csv").exists()
    assert not (output / "system_artifacts" / "notification_keyword_hits.html").exists()
    assert not (output / "case_summary.html").exists()


def test_max_report_rows_caps_html_rows(tmp_path):
    set_report_options(max_report_rows=2)
    path = tmp_path / "cards.html"
    rows = [{"snippet": f"row {idx}"} for idx in range(5)]

    write_cards_html(path, "Cards", rows)

    text = path.read_text(encoding="utf-8")
    assert "row 0" in text
    assert "row 1" in text
    assert "row 2" not in text
    assert "HTML truncated to 2 rows" in text
    set_report_options()


def test_case_focus_streaming_outputs_csv_jsonl_and_bounded_review_queue(tmp_path):
    set_report_options(max_report_rows=1)
    output = tmp_path / "case"
    (output / "system_artifacts").mkdir(parents=True)
    (output / "system_artifacts" / "outlook_keyword_hits.csv").write_text(
        "clean_snippet,evidence_class,datetime_utc\n"
        "Tesla ADHD monitor one,raw_text,2024-01-01T00:00:00+00:00\n"
        "Tesla ADHD monitor two,raw_text,2024-01-02T00:00:00+00:00\n"
        "Tesla ADHD monitor three,raw_text,2024-01-03T00:00:00+00:00\n",
        encoding="utf-8",
    )
    targets = build_case_targets(_args(_backup(tmp_path), output, target_phrase=["ADHD"], near_term=["ADHD,monitor"], focus_source=["outlook"]))

    result = write_case_focus_exports(output, targets, max_review_rows=2)

    assert result["case_hits"] == 3
    assert (output / "case_focus" / "case_hits.csv").exists()
    assert (output / "case_focus" / "case_hits.jsonl").exists()
    assert not (output / "case_focus" / "case_hits.json").exists()
    assert len((output / "case_focus" / "review_queue.csv").read_text(encoding="utf-8").splitlines()) == 3
    set_report_options()


def test_media_candidate_discovery_does_not_import_pil():
    sys.modules.pop("PIL", None)
    records = [ManifestRecord("aa", "MediaDomain", "DCIM/100APPLE/Screenshot.PNG")]

    discover_photo_candidates(records)

    assert "PIL" not in sys.modules


def test_resume_skips_existing_sms_and_teams_outputs(tmp_path):
    backup = _backup(tmp_path)
    output = tmp_path / "case"
    (output / "sms").mkdir(parents=True)
    (output / "teams").mkdir(parents=True)
    (output / "sms" / "sms_messages.csv").write_text("message_id,text\n", encoding="utf-8")
    (output / "teams" / "teams_candidate_files.csv").write_text("file_id\n", encoding="utf-8")

    run_forensic_triage(_args(backup, output, resume=True))

    status = json.loads((output / "partial_run_status.json").read_text(encoding="utf-8"))
    assert status["stages"]["sms"]["status"] == "skipped"
    assert status["stages"]["sms"]["error"] == "resume_existing_sms_outputs"
    assert status["stages"]["teams"]["status"] == "skipped"
    assert status["stages"]["teams"]["error"] == "resume_existing_teams_outputs"
