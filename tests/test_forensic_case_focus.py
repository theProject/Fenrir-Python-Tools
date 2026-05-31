import argparse
import json
from pathlib import Path

from tools.forensic_case_focus import (
    build_case_targets,
    build_investigate_command,
    collect_case_hits,
    command_text,
    discover_photo_candidates,
    load_case_target_pack,
    score_case_hit,
    write_case_focus_exports,
)
from tools.forensic_models import ManifestRecord


def test_target_pack_parsing(tmp_path):
    pack = tmp_path / "case_targets.json"
    pack.write_text(
        json.dumps(
            {
                "case_name": "tesla_accommodation_monitor",
                "date_range": {"from": "2024-01-01", "to": "2024-12-31"},
                "emails": ["hr@tesla.com"],
                "domains": ["tesla.com"],
                "people": ["Alex Example"],
                "phrases": ["reasonable accommodation", "external monitor"],
                "near_terms": [["ADHD", "monitor"]],
            }
        ),
        encoding="utf-8",
    )

    targets = load_case_target_pack(pack)

    assert targets.case_name == "tesla_accommodation_monitor"
    assert targets.from_date == "2024-01-01"
    assert targets.to_date == "2024-12-31"
    assert targets.emails == ["hr@tesla.com"]
    assert targets.near_terms == [("ADHD", "monitor")]


def test_exact_email_domain_person_phrase_matching_and_scoring():
    targets = build_case_targets(
        argparse.Namespace(
            case_profile=None,
            target_pack=None,
            target_email=["hr@tesla.com"],
            target_domain=["tesla.com"],
            target_person=["Kelly"],
            target_phrase=["reasonable accommodation"],
            near_term=[],
            near_window=500,
            focus_source=[],
            from_date=None,
            to_date=None,
        )
    )
    row = {
        "clean_snippet": "Kelly at hr@tesla.com approved a reasonable accommodation.",
        "evidence_class": "mail_record",
        "datetime_utc": "2024-03-10T12:00:00+00:00",
    }

    scored = score_case_hit(row, targets, "outlook")

    assert scored is not None
    assert scored["matched_emails"] == "hr@tesla.com"
    assert scored["matched_domains"] == "tesla.com"
    assert scored["matched_people"] == "Kelly"
    assert scored["matched_phrases"] == "reasonable accommodation"
    assert scored["case_confidence"] == "high"


def test_near_term_matching_and_date_range_filtering():
    targets = build_case_targets(
        argparse.Namespace(
            case_profile=None,
            target_pack=None,
            target_email=[],
            target_domain=[],
            target_person=[],
            target_phrase=[],
            near_term=["ADHD,monitor"],
            near_window=50,
            focus_source=[],
            from_date="2024-01-01",
            to_date="2024-12-31",
        )
    )
    inside = {"clean_snippet": "ADHD accommodation monitor", "evidence_class": "notification_fragment", "datetime_utc": "2024-05-01T00:00:00+00:00"}
    outside = {"clean_snippet": "ADHD accommodation monitor", "evidence_class": "notification_fragment", "datetime_utc": "2023-05-01T00:00:00+00:00"}

    scored = score_case_hit(inside, targets, "notifications")

    assert scored is not None
    assert scored["matched_near_terms"] == "ADHD,monitor"
    assert scored["date_status"] == "inside_range"
    assert score_case_hit(outside, targets, "notifications") is None


def test_fragment_evidence_scores_fragment_only_when_weak():
    targets = build_case_targets(
        argparse.Namespace(
            case_profile=None,
            target_pack=None,
            target_email=[],
            target_domain=[],
            target_person=[],
            target_phrase=["monitor"],
            near_term=[],
            near_window=500,
            focus_source=[],
            from_date=None,
            to_date=None,
        )
    )
    row = {"clean_snippet": "monitor", "evidence_class": "sqlite_raw_bytes"}

    scored = score_case_hit(row, targets, "sqlite-raw")

    assert scored is not None
    assert scored["case_confidence"] == "fragment_only"


def test_focused_case_exports(tmp_path):
    output = tmp_path / "case"
    source_dir = output / "system_artifacts"
    source_dir.mkdir(parents=True)
    (source_dir / "outlook_keyword_hits.json").write_text(
        json.dumps(
            [
                {
                    "keyword": "ADHD",
                    "clean_snippet": "Tesla reasonable accommodation for ADHD and external monitor",
                    "evidence_class": "raw_text",
                    "datetime_utc": "2024-02-01T10:00:00+00:00",
                    "logical_path": "AppDomain-com.microsoft.Office.Outlook/Library/Caches/mail.sqlite",
                }
            ]
        ),
        encoding="utf-8",
    )
    targets = build_case_targets(
        argparse.Namespace(
            case_profile="tesla-accommodation-monitor",
            target_pack=None,
            target_email=[],
            target_domain=[],
            target_person=[],
            target_phrase=[],
            near_term=[],
            near_window=500,
            focus_source=["outlook"],
            from_date="2024-01-01",
            to_date="2024-12-31",
        )
    )

    result = write_case_focus_exports(output, targets)

    assert result["case_hits"] == 1
    assert "external monitor" in (output / "case_focus" / "case_hits.csv").read_text(encoding="utf-8")
    assert (output / "case_focus" / "case_hits_by_source.csv").exists()
    assert (output / "case_focus" / "case_hits_by_term.csv").exists()
    assert (output / "case_focus" / "case_hits_by_person.csv").exists()
    assert (output / "case_focus" / "case_hits_by_email.csv").exists()
    assert (output / "case_focus" / "case_hits_by_date.csv").exists()
    assert (output / "case_focus" / "case_timeline.csv").exists()
    assert (output / "case_focus" / "review_queue.csv").exists()


def test_collect_case_hits_respects_focus_source(tmp_path):
    output = tmp_path / "case"
    (output / "system_artifacts").mkdir(parents=True)
    (output / "system_artifacts" / "chrome_keyword_hits.json").write_text(json.dumps([{"clean_snippet": "Tesla ADHD monitor", "evidence_class": "raw_text"}]), encoding="utf-8")
    (output / "system_artifacts" / "outlook_keyword_hits.json").write_text(json.dumps([{"clean_snippet": "Tesla ADHD monitor", "evidence_class": "raw_text"}]), encoding="utf-8")
    targets = build_case_targets(
        argparse.Namespace(
            case_profile=None,
            target_pack=None,
            target_email=[],
            target_domain=["tesla.com"],
            target_person=[],
            target_phrase=["ADHD"],
            near_term=["ADHD,monitor"],
            near_window=500,
            focus_source=["outlook"],
            from_date=None,
            to_date=None,
        )
    )

    hits = collect_case_hits(output, targets)

    assert len(hits) == 1
    assert hits[0]["case_source"] == "outlook"


def test_wizard_dry_run_command_generation():
    args = argparse.Namespace(
        source="/tmp/BACKUP",
        output="./rescue/focus",
        case_profile="tesla-accommodation-monitor",
        target_pack="case_targets.json",
        target_email=["hr@tesla.com"],
        target_domain=["tesla.com"],
        target_person=["Kelly"],
        target_phrase=["external monitor"],
        near_term=["ADHD,monitor"],
        near_window=300,
        focus_source=["outlook"],
        from_date="2024-01-01",
        to_date="2024-12-31",
        password_env=None,
        prompt_password=True,
        photo_candidate_scan=False,
        screenshot_candidate_scan=True,
    )

    command = build_investigate_command(args)
    text = command_text(command)

    assert command[:3] == [".venv/bin/python", "rescue.py", "forensics"]
    assert "--case-profile tesla-accommodation-monitor" in text
    assert "--target-pack case_targets.json" in text
    assert "--target-email hr@tesla.com" in text
    assert "--prompt-password" in command
    assert "--screenshot-candidate-scan" in command


def test_photo_and_screenshot_candidate_discovery():
    records = [
        ManifestRecord("aa", "MediaDomain", "DCIM/100APPLE/IMG_0001.JPG"),
        ManifestRecord("bb", "MediaDomain", "DCIM/100APPLE/Screenshot 2024-01-01.PNG"),
        ManifestRecord("cc", "HomeDomain", "Library/Notes/note.txt"),
    ]

    photos, screenshots = discover_photo_candidates(records)

    assert len(photos) == 2
    assert len(screenshots) == 1
    assert screenshots[0]["file_id"] == "bb"
