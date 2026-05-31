from __future__ import annotations

import argparse
import csv
import json
import shlex
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.forensic_common import guess_app_from_record_domain
from tools.forensic_models import ManifestRecord
from tools.forensic_reports import get_max_report_rows, write_cards_html, write_csv, write_json, write_table_html


SUPPORTED_FOCUS_SOURCES = {
    "outlook",
    "notifications",
    "microsoft-coredata",
    "screenshots",
    "photos",
    "chrome",
    "teams",
    "mail",
    "raw",
    "sqlite-raw",
}
FRAGMENT_CLASSES = {"binary_text_fragment", "raw_string_fragment", "sqlite_raw_bytes", "sqlite_blob_fragment"}
STRONG_SOURCES = {"outlook", "notifications", "microsoft-coredata", "teams", "mail", "screenshots"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".tif", ".tiff", ".gif", ".bmp", ".webp"}
CASE_PROFILES: dict[str, dict[str, Any]] = {
    "tesla-accommodation-monitor": {
        "case_name": "tesla_accommodation_monitor",
        "domains": ["tesla.com"],
        "phrases": [
            "ADHD",
            "accommodation",
            "reasonable accommodation",
            "monitor",
            "external monitor",
            "widescreen",
            "display",
            "ergonomic",
            "IT request",
            "approved",
            "granted",
        ],
        "near_terms": [
            ["ADHD", "monitor"],
            ["accommodation", "monitor"],
            ["reasonable accommodation", "display"],
            ["Tesla", "ADHD"],
            ["IT", "monitor"],
        ],
        "focus_sources": ["outlook", "notifications", "microsoft-coredata", "teams", "mail", "screenshots"],
    }
}


@dataclass
class CaseTargets:
    case_name: str = "case_focus"
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    people: list[str] = field(default_factory=list)
    phrases: list[str] = field(default_factory=list)
    near_terms: list[tuple[str, str]] = field(default_factory=list)
    focus_sources: list[str] = field(default_factory=list)
    from_date: str | None = None
    to_date: str | None = None
    near_window: int = 500

    @property
    def enabled(self) -> bool:
        return bool(self.case_name != "case_focus" or self.search_terms or self.focus_sources or self.from_date or self.to_date)

    @property
    def search_terms(self) -> list[str]:
        terms: list[str] = []
        terms.extend(self.emails)
        terms.extend(self.domains)
        terms.extend(self.people)
        terms.extend(self.phrases)
        for left, right in self.near_terms:
            terms.extend([left, right])
        return list(dict.fromkeys(term for term in terms if term))


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def _near_pair(value: str) -> tuple[str, str] | None:
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for candidate in (value, value.replace("Z", "+00:00")):
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_date_pack(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, dict):
        return None, None
    return value.get("from"), value.get("to")


def load_case_target_pack(path: Path) -> CaseTargets:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Target pack must contain a JSON object.")
    from_date, to_date = _parse_date_pack(data.get("date_range"))
    near_terms: list[tuple[str, str]] = []
    for pair in data.get("near_terms", []) or []:
        if isinstance(pair, list) and len(pair) >= 2:
            near_terms.append((str(pair[0]), str(pair[1])))
        elif isinstance(pair, str):
            parsed = _near_pair(pair)
            if parsed:
                near_terms.append(parsed)
    return CaseTargets(
        case_name=str(data.get("case_name") or "case_focus"),
        emails=_dedupe([str(v) for v in data.get("emails", []) or []]),
        domains=_dedupe([str(v) for v in data.get("domains", []) or []]),
        people=_dedupe([str(v) for v in data.get("people", []) or []]),
        phrases=_dedupe([str(v) for v in data.get("phrases", []) or []]),
        near_terms=near_terms,
        focus_sources=_dedupe([str(v) for v in data.get("focus_sources", []) or []]),
        from_date=from_date,
        to_date=to_date,
        near_window=int(data.get("near_window") or 500),
    )


def build_case_targets(args: argparse.Namespace) -> CaseTargets:
    targets = CaseTargets()
    profile_name = getattr(args, "case_profile", None)
    if profile_name:
        profile = CASE_PROFILES.get(profile_name)
        if not profile:
            raise ValueError(f"Unsupported case profile: {profile_name}")
        targets = CaseTargets(
            case_name=str(profile["case_name"]),
            domains=list(profile.get("domains", [])),
            phrases=list(profile.get("phrases", [])),
            near_terms=[tuple(pair) for pair in profile.get("near_terms", [])],
            focus_sources=list(profile.get("focus_sources", [])),
        )
    pack_path = getattr(args, "target_pack", None)
    if pack_path:
        pack = load_case_target_pack(Path(pack_path).expanduser())
        targets.case_name = pack.case_name or targets.case_name
        targets.emails.extend(pack.emails)
        targets.domains.extend(pack.domains)
        targets.people.extend(pack.people)
        targets.phrases.extend(pack.phrases)
        targets.near_terms.extend(pack.near_terms)
        targets.focus_sources.extend(pack.focus_sources)
        targets.from_date = pack.from_date or targets.from_date
        targets.to_date = pack.to_date or targets.to_date
        targets.near_window = pack.near_window or targets.near_window
    targets.emails.extend(getattr(args, "target_email", []) or [])
    targets.domains.extend(getattr(args, "target_domain", []) or [])
    targets.people.extend(getattr(args, "target_person", []) or [])
    targets.phrases.extend(getattr(args, "target_phrase", []) or [])
    for value in getattr(args, "near_term", []) or []:
        parsed = _near_pair(value)
        if parsed:
            targets.near_terms.append(parsed)
    targets.focus_sources.extend(getattr(args, "focus_source", []) or [])
    targets.from_date = getattr(args, "from_date", None) or targets.from_date
    targets.to_date = getattr(args, "to_date", None) or targets.to_date
    targets.near_window = int(getattr(args, "near_window", targets.near_window) or targets.near_window)
    targets.emails = _dedupe(targets.emails)
    targets.domains = _dedupe(targets.domains)
    targets.people = _dedupe(targets.people)
    targets.phrases = _dedupe(targets.phrases)
    targets.focus_sources = _dedupe([source for source in targets.focus_sources if source in SUPPORTED_FOCUS_SOURCES])
    targets.near_terms = list(dict.fromkeys(targets.near_terms))
    return targets


def source_files(output: Path) -> list[tuple[str, Path]]:
    return [
        ("teams", output / "teams" / "teams_keyword_hits.json"),
        ("teams", output / "teams" / "teams_text_keyword_hits.json"),
        ("mail", output / "system_artifacts" / "mail_keyword_hits.json"),
        ("notifications", output / "system_artifacts" / "notification_keyword_hits.json"),
        ("outlook", output / "system_artifacts" / "outlook_keyword_hits.json"),
        ("chrome", output / "system_artifacts" / "chrome_keyword_hits.json"),
        ("raw", output / "system_artifacts" / "raw_string_hits.json"),
        ("sqlite-raw", output / "system_artifacts" / "sqlite_raw_hits.json"),
        ("microsoft-coredata", output / "microsoft_coredata" / "person_hits.json"),
        ("microsoft-coredata", output / "microsoft_coredata" / "related_rows.json"),
        ("deep", output / "deep_scan" / "deep_keyword_hits.json"),
    ]


def _csv_source_for_json(path: Path) -> Path:
    return path.with_suffix(".csv")


def _load_rows(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def iter_source_rows(path: Path) -> Any:
    csv_path = _csv_source_for_json(path)
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as f:
            yield from csv.DictReader(f)
        return
    for row in _load_rows(path):
        yield row


def _search_blob(row: dict[str, Any]) -> str:
    values = [
        row.get("clean_snippet"),
        row.get("snippet"),
        row.get("raw_snippet_preview"),
        row.get("clean_value"),
        row.get("title"),
        row.get("subtitle"),
        row.get("body"),
        row.get("logical_path"),
        row.get("domain"),
        row.get("relative_path"),
        row.get("app_guess"),
        row.get("table"),
        row.get("column"),
        row.get("keyword"),
    ]
    return " ".join(str(value) for value in values if value is not None)


def _find_terms(text: str, terms: list[str]) -> list[str]:
    lowered = text.lower()
    return [term for term in terms if term.lower() in lowered]


def _near_matches(text: str, pairs: list[tuple[str, str]], window: int) -> list[str]:
    lowered = text.lower()
    matches: list[str] = []
    for left, right in pairs:
        left_idx = lowered.find(left.lower())
        right_idx = lowered.find(right.lower())
        if left_idx >= 0 and right_idx >= 0 and abs(left_idx - right_idx) <= window:
            matches.append(f"{left},{right}")
    return matches


def _row_datetime(row: dict[str, Any]) -> datetime | None:
    for key in ("datetime_utc", "timestamp_utc", "date_utc", "created_utc", "modified_utc"):
        parsed = _parse_date(str(row.get(key) or ""))
        if parsed:
            return parsed
    return None


def score_case_hit(row: dict[str, Any], targets: CaseTargets, source: str) -> dict[str, Any] | None:
    text = _search_blob(row)
    emails = _find_terms(text, targets.emails)
    domains = _find_terms(text, targets.domains)
    people = _find_terms(text, targets.people)
    phrases = _find_terms(text, targets.phrases)
    near = _near_matches(text, targets.near_terms, targets.near_window)
    if not any([emails, domains, people, phrases, near]):
        return None
    hit_date = _row_datetime(row)
    from_dt = _parse_date(targets.from_date)
    to_dt = _parse_date(targets.to_date)
    date_status = "undated"
    if hit_date and from_dt and hit_date < from_dt:
        return None
    if hit_date and to_dt and hit_date.date() > to_dt.date():
        return None
    if hit_date and (from_dt or to_dt):
        date_status = "inside_range"
    evidence_class = str(row.get("evidence_class") or "")
    score = 0
    score += 40 if emails else 0
    score += 25 if domains else 0
    score += 20 * min(len(phrases), 3)
    score += 35 if near else 0
    score += 20 if people else 0
    score += 10 if date_status == "inside_range" else 0
    score += 15 if source in STRONG_SOURCES else 0
    score += 10 if evidence_class not in FRAGMENT_CLASSES else 0
    if evidence_class in FRAGMENT_CLASSES and score < 60:
        confidence = "fragment_only"
    elif score >= 80:
        confidence = "high"
    elif score >= 45:
        confidence = "medium"
    else:
        confidence = "low"
    matched_terms = list(dict.fromkeys([*emails, *domains, *people, *phrases, *near]))
    return {
        **row,
        "case_name": targets.case_name,
        "case_source": source,
        "score": score,
        "case_confidence": confidence,
        "matched_emails": ";".join(emails),
        "matched_domains": ";".join(domains),
        "matched_people": ";".join(people),
        "matched_phrases": ";".join(phrases),
        "matched_near_terms": ";".join(near),
        "matched_terms": ";".join(matched_terms),
        "date_status": date_status,
        "case_datetime_utc": hit_date.isoformat() if hit_date else "",
    }


def collect_case_hits(output: Path, targets: CaseTargets) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    focus = set(targets.focus_sources)
    for source, path in source_files(output):
        if focus and source not in focus and not (source == "deep" and "raw" in focus):
            continue
        for row in iter_source_rows(path):
            scored = score_case_hit(row, targets, source)
            if scored:
                hits.append(scored)
    hits.sort(key=lambda row: (-int(row.get("score") or 0), row.get("case_datetime_utc") or "9999"))
    return hits


def _summary(rows: list[dict[str, Any]], key: str, value_name: str) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for row in rows:
        value = str(row.get(key) or "unknown")
        if ";" in value:
            for part in [p for p in value.split(";") if p]:
                counts[part] += 1
        else:
            counts[value] += 1
    return [{value_name: value, "hits": count} for value, count in counts.most_common()]


def _bump_counter(counter: Counter[str], value: str) -> None:
    if ";" in value:
        for part in [p for p in value.split(";") if p]:
            counter[part] += 1
    else:
        counter[value or "unknown"] += 1


def _summary_from_counter(counter: Counter[str], value_name: str) -> list[dict[str, Any]]:
    return [{value_name: value, "hits": count} for value, count in counter.most_common()]


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def _insert_review_candidate(queue: list[dict[str, Any]], row: dict[str, Any], limit: int) -> None:
    if limit <= 0:
        return
    queue.append(dict(row))
    queue.sort(key=lambda item: (-int(item.get("score") or 0), item.get("case_datetime_utc") or "9999"))
    del queue[limit:]


def write_case_focus_exports(output: Path, targets: CaseTargets, max_review_rows: int = 250) -> dict[str, int]:
    if not targets.enabled:
        return {"case_hits": 0}
    outdir = output / "case_focus"
    outdir.mkdir(parents=True, exist_ok=True)
    case_hits_path = outdir / "case_hits.csv"
    jsonl_path = outdir / "case_hits.jsonl"
    source_counter: Counter[str] = Counter()
    term_counter: Counter[str] = Counter()
    person_counter: Counter[str] = Counter()
    email_counter: Counter[str] = Counter()
    date_counter: Counter[str] = Counter()
    review_queue: list[dict[str, Any]] = []
    json_rows: list[dict[str, Any]] = []
    html_rows: list[dict[str, Any]] = []
    timeline_rows: list[dict[str, Any]] = []
    max_report_rows = get_max_report_rows()
    writer: csv.DictWriter[str] | None = None
    count = 0
    focus = set(targets.focus_sources)
    with case_hits_path.open("w", newline="", encoding="utf-8") as csv_file, jsonl_path.open("w", encoding="utf-8") as jsonl_file:
        for source, path in source_files(output):
            if focus and source not in focus and not (source == "deep" and "raw" in focus):
                continue
            for row in iter_source_rows(path):
                scored = score_case_hit(row, targets, source)
                if not scored:
                    continue
                if writer is None:
                    writer = csv.DictWriter(csv_file, fieldnames=list(scored.keys()), extrasaction="ignore")
                    writer.writeheader()
                writer.writerow(scored)
                jsonl_file.write(json.dumps(scored, ensure_ascii=False, default=str) + "\n")
                count += 1
                source_counter[scored.get("case_source") or "unknown"] += 1
                _bump_counter(term_counter, str(scored.get("matched_terms") or "unknown"))
                _bump_counter(person_counter, str(scored.get("matched_people") or "unknown"))
                _bump_counter(email_counter, str(scored.get("matched_emails") or "unknown"))
                date_counter[(scored.get("case_datetime_utc") or "undated")[:10] if scored.get("case_datetime_utc") else "undated"] += 1
                _insert_review_candidate(review_queue, scored, max_review_rows)
                if len(json_rows) <= max_report_rows:
                    json_rows.append(dict(scored))
                if len(html_rows) < max_report_rows:
                    html_rows.append(dict(scored))
                if scored.get("case_datetime_utc") and len(timeline_rows) < max_report_rows:
                    timeline_rows.append(dict(scored))
        if writer is None:
            csv_file.write("")
    if count <= max_report_rows:
        write_json(outdir / "case_hits.json", json_rows)
    else:
        (outdir / "case_hits.json").unlink(missing_ok=True)
    write_cards_html(outdir / "case_hits.html", "Case Focus Hits", html_rows, text_field="clean_snippet")
    summaries = {
        "case_hits_by_source": _summary_from_counter(source_counter, "source"),
        "case_hits_by_term": _summary_from_counter(term_counter, "term"),
        "case_hits_by_person": _summary_from_counter(person_counter, "person"),
        "case_hits_by_email": _summary_from_counter(email_counter, "email"),
        "case_hits_by_date": _summary_from_counter(date_counter, "date"),
    }
    for stem, summary_rows in summaries.items():
        write_csv(outdir / f"{stem}.csv", summary_rows)
        write_json(outdir / f"{stem}.json", summary_rows)
        write_table_html(outdir / f"{stem}.html", stem.replace("_", " ").title(), summary_rows)
    timeline_rows.sort(key=lambda row: row["case_datetime_utc"])
    write_csv(outdir / "case_timeline.csv", timeline_rows)
    write_table_html(outdir / "case_timeline.html", "Case Timeline", timeline_rows)
    write_csv(outdir / "review_queue.csv", review_queue)
    write_table_html(outdir / "review_queue.html", "Case Review Queue", review_queue)
    return {"case_hits": count, "case_review_queue": len(review_queue)}


def _photo_reason(record: ManifestRecord) -> str | None:
    logical = record.logical_path.lower()
    suffix = Path(record.relative_path).suffix.lower()
    if record.domain == "MediaDomain" or "dcim/" in logical or "photodata/" in logical:
        return "photo_library_path"
    if suffix in IMAGE_EXTS:
        return "image_extension"
    return None


def _screenshot_reason(record: ManifestRecord) -> str | None:
    logical = record.logical_path.lower()
    metadata_text = json.dumps(record.metadata, default=str).lower() if record.metadata else ""
    if "screenshot" in logical or "screen shot" in logical or "screenshot" in metadata_text:
        return "screenshot_name_or_metadata"
    return None


def discover_photo_candidates(records: list[ManifestRecord]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    photo_rows: list[dict[str, Any]] = []
    screenshot_rows: list[dict[str, Any]] = []
    for record in records:
        photo_reason = _photo_reason(record)
        screenshot_reason = _screenshot_reason(record)
        if photo_reason:
            photo_rows.append(
                {
                    "file_id": record.file_id,
                    "domain": record.domain,
                    "relative_path": record.relative_path,
                    "logical_path": record.logical_path,
                    "app_guess": guess_app_from_record_domain(record.domain),
                    "candidate_reason": photo_reason,
                    "evidence_note": "Photo candidate only; file was not altered.",
                }
            )
        if screenshot_reason or (photo_reason and "screenshot" in record.relative_path.lower()):
            screenshot_rows.append(
                {
                    "file_id": record.file_id,
                    "domain": record.domain,
                    "relative_path": record.relative_path,
                    "logical_path": record.logical_path,
                    "app_guess": guess_app_from_record_domain(record.domain),
                    "candidate_reason": screenshot_reason or "photo_path_screenshot_name",
                    "evidence_note": "Screenshot candidate only; OCR is not performed in this milestone.",
                }
            )
    return photo_rows, screenshot_rows


def write_photo_candidate_exports(output: Path, records: list[ManifestRecord], include_photos: bool, include_screenshots: bool) -> dict[str, int]:
    if not include_photos and not include_screenshots:
        return {"photo_candidates": 0, "screenshot_candidates": 0}
    photo_rows, screenshot_rows = discover_photo_candidates(records)
    outdir = output / "photos"
    if include_photos:
        write_csv(outdir / "photo_candidates.csv", photo_rows)
        write_json(outdir / "photo_candidates.json", photo_rows)
        write_table_html(outdir / "photo_candidates.html", "Photo Candidates", photo_rows)
    if include_screenshots:
        write_csv(outdir / "screenshot_candidates.csv", screenshot_rows)
        write_json(outdir / "screenshot_candidates.json", screenshot_rows)
        write_table_html(outdir / "screenshot_candidates.html", "Screenshot Candidates", screenshot_rows)
    return {"photo_candidates": len(photo_rows) if include_photos else 0, "screenshot_candidates": len(screenshot_rows) if include_screenshots else 0}


def add_case_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--case-profile", choices=sorted(CASE_PROFILES))
    parser.add_argument("--target-pack", help="JSON target pack for focused case investigation")
    parser.add_argument("--target-email", action="append", default=[])
    parser.add_argument("--target-domain", action="append", default=[])
    parser.add_argument("--target-person", action="append", default=[])
    parser.add_argument("--target-phrase", action="append", default=[])
    parser.add_argument("--from-date")
    parser.add_argument("--to-date")
    parser.add_argument("--near-term", action="append", default=[])
    parser.add_argument("--near-window", type=int, default=500)
    parser.add_argument("--focus-source", action="append", choices=sorted(SUPPORTED_FOCUS_SOURCES), default=[])
    parser.add_argument("--photo-candidate-scan", action="store_true")
    parser.add_argument("--screenshot-candidate-scan", action="store_true")


def build_investigate_command(args: argparse.Namespace) -> list[str]:
    command = [".venv/bin/python", "rescue.py", "forensics"]
    if getattr(args, "source", None):
        command.extend(["--source", str(args.source)])
    output = getattr(args, "output", None) or "./rescue/case-focus"
    command.extend(["--output", str(output)])
    profile = getattr(args, "case_profile", None) or "tesla-accommodation-monitor"
    command.extend(["--case-profile", profile])
    for attr, flag in (
        ("target_pack", "--target-pack"),
        ("password_env", "--password-env"),
        ("from_date", "--from-date"),
        ("to_date", "--to-date"),
    ):
        value = getattr(args, attr, None)
        if value:
            command.extend([flag, str(value)])
    for attr, flag in (
        ("target_email", "--target-email"),
        ("target_domain", "--target-domain"),
        ("target_person", "--target-person"),
        ("target_phrase", "--target-phrase"),
        ("near_term", "--near-term"),
        ("focus_source", "--focus-source"),
    ):
        for value in getattr(args, attr, []) or []:
            command.extend([flag, str(value)])
    command.extend(["--near-window", str(getattr(args, "near_window", 500) or 500)])
    if getattr(args, "prompt_password", False):
        command.append("--prompt-password")
    if getattr(args, "photo_candidate_scan", False):
        command.append("--photo-candidate-scan")
    if getattr(args, "screenshot_candidate_scan", False):
        command.append("--screenshot-candidate-scan")
    return command


def command_text(command: list[str]) -> str:
    return shlex.join(command)


def add_investigate_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("investigate", help="Guided local case investigation command builder")
    p.add_argument("--source", help="MobileSync Backup UUID folder")
    p.add_argument("--output", "-o", default="./rescue/case-focus")
    p.add_argument("--password-env")
    p.add_argument("--prompt-password", action="store_true", help="Use the existing secure iOS backup password prompt when the generated command runs")
    p.add_argument("--dry-run", action="store_true", help="Print the equivalent forensics command without running it")
    p.add_argument("--run", action="store_true", help="Run the generated forensics command after printing it")
    add_case_target_args(p)


def _ask(prompt: str, default: str = "") -> str:
    value = input(f"{prompt} " + (f"[{default}] " if default else ""))
    return value.strip() or default


def run_investigate(args: argparse.Namespace) -> list[str]:
    if not getattr(args, "source", None) and not getattr(args, "dry_run", False):
        print("This wizard never asks for live Microsoft, Tesla, Apple, or Google passwords.")
        print("Use --prompt-password only for the local encrypted iOS backup password.")
        args.source = _ask("MobileSync backup UUID folder:")
        args.output = _ask("Output folder:", getattr(args, "output", "./rescue/case-focus"))
        args.case_profile = _ask("What are you trying to find?", "tesla-accommodation-monitor")
        emails = _ask("Known email addresses? Comma-separated:", "")
        domains = _ask("Known domains? Comma-separated:", "tesla.com")
        people = _ask("Known people? Comma-separated:", "")
        date_range = _ask("Date range? Use YYYY-MM-DD..YYYY-MM-DD or blank:", "")
        phrases = _ask("Exact phrases? Comma-separated:", "")
        include_media = _ask("Should screenshots/photos be included? yes/no:", "yes").lower().startswith("y")
        broad = _ask("Run high-signal only or broad scan?", "high-signal")
        args.target_email = [v.strip() for v in emails.split(",") if v.strip()]
        args.target_domain = [v.strip() for v in domains.split(",") if v.strip()]
        args.target_person = [v.strip() for v in people.split(",") if v.strip()]
        args.target_phrase = [v.strip() for v in phrases.split(",") if v.strip()]
        if ".." in date_range:
            args.from_date, args.to_date = [part.strip() for part in date_range.split("..", 1)]
        args.photo_candidate_scan = include_media
        args.screenshot_candidate_scan = include_media
        if broad == "broad":
            args.focus_source = []
    command = build_investigate_command(args)
    print("Equivalent command:")
    print(command_text(command))
    if getattr(args, "run", False):
        from tools.forensic_backup import run_forensic_triage

        forensic_args = argparse.Namespace(**vars(args))
        forensic_args.cmd = "forensics"
        defaults = {
            "targets": ["sms", "teams"],
            "password": None,
            "keyword": [],
            "sample_limit": 500,
            "no_attachments": False,
            "max_teams_file_mb": 250,
            "include_large_teams_files": False,
            "deep_app_cache_scan": False,
            "deep_keyword": [],
            "max_deep_file_mb": 250,
            "include_large_deep_files": False,
            "deep_scan_text_limit_mb": 25,
            "deep_scan_sqlite_row_limit": 0,
            "deep_scan_export_context": 240,
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
        }
        for key, value in defaults.items():
            if not hasattr(forensic_args, key):
                setattr(forensic_args, key, value)
        run_forensic_triage(forensic_args)
    return command
