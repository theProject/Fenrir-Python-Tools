from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CSS = """
body{background:#050505;color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:24px}
h1,h2{margin:0 0 12px}.card{background:#09090b;border:1px solid #27272a;border-radius:18px;padding:16px;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #27272a;padding:8px;text-align:left;vertical-align:top}
th{background:#18181b}.keyword{color:#05f2af;font-weight:700}.warn{color:#fbbf24}.muted{color:#a1a1aa}.mag{color:#e20074}
"""
MAX_HTML_BYTES = 25 * 1024 * 1024
HTML_ENABLED = True
MAX_REPORT_ROWS = 1000
NO_LARGE_HTML = True


def set_report_options(*, no_html: bool = False, csv_only: bool = False, no_large_html: bool = True, max_report_rows: int = 1000) -> None:
    global HTML_ENABLED, MAX_REPORT_ROWS, NO_LARGE_HTML
    HTML_ENABLED = not (no_html or csv_only)
    MAX_REPORT_ROWS = max(0, int(max_report_rows))
    NO_LARGE_HTML = bool(no_large_html)


def get_max_report_rows() -> int:
    return MAX_REPORT_ROWS


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [to_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_plain(value), ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [to_plain(r) for r in rows]
    fields = fieldnames or (list(data[0].keys()) if data else [])
    with path.open("w", newline="", encoding="utf-8") as f:
        if not fields:
            return
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)


def write_table_html(path: Path, title: str, rows: Iterable[dict[str, Any]], intro: str = "") -> None:
    if not HTML_ENABLED:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    iterator = iter(rows)
    first = next(iterator, None)
    data: list[dict[str, Any]] = []
    truncated = False
    if first is not None:
        data.append(to_plain(first))
        for idx, row in enumerate(iterator, start=1):
            if idx >= MAX_REPORT_ROWS:
                truncated = True
                break
            data.append(to_plain(row))
    fields = list(data[0].keys()) if data else []
    parts = ["<!doctype html><meta charset='utf-8'>", f"<title>{html.escape(title)}</title>", f"<style>{CSS}</style>"]
    parts.append(f"<h1>{html.escape(title)}</h1>")
    if intro:
        parts.append(f"<div class='card'>{html.escape(intro)}</div>")
    if truncated:
        parts.append(f"<div class='card warn'>HTML truncated to {MAX_REPORT_ROWS} rows. Use CSV/JSON for the complete output.</div>")
    if not data:
        parts.append("<div class='card muted'>No records.</div>")
    else:
        parts.append("<div class='card'><table><thead><tr>")
        parts.extend(f"<th>{html.escape(k)}</th>" for k in fields)
        parts.append("</tr></thead><tbody>")
        for row in data:
            parts.append("<tr>")
            for key in fields:
                value = "" if row.get(key) is None else str(row.get(key))
                parts.append(f"<td>{html.escape(value)}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table></div>")
    path.write_text("".join(parts), encoding="utf-8")


def _cards_html(title: str, cards: list[dict[str, Any]], text_field: str, truncated: bool = False) -> str:
    display_field = text_field
    if cards and any("clean_snippet" in card for card in cards):
        display_field = "clean_snippet"
    parts = ["<!doctype html><meta charset='utf-8'>", f"<title>{html.escape(title)}</title>", f"<style>{CSS}</style>"]
    parts.append(f"<h1>{html.escape(title)}</h1>")
    if truncated:
        parts.append(f"<div class='card warn'>HTML truncated to {MAX_REPORT_ROWS} rows. Use CSV/JSON for the complete output.</div>")
    for card in cards:
        parts.append("<div class='card'>")
        for key, value in to_plain(card).items():
            if key == "snippet" and display_field == "clean_snippet":
                continue
            safe = html.escape("" if value is None else str(value))
            if key == display_field:
                parts.append(f"<p>{safe}</p>")
            else:
                parts.append(f"<div><span class='muted'>{html.escape(key)}:</span> {safe}</div>")
        parts.append("</div>")
    if not cards:
        parts.append("<div class='card muted'>No records.</div>")
    return "".join(parts)


def write_cards_html(path: Path, title: str, cards: Iterable[dict[str, Any]], text_field: str = "snippet") -> None:
    if not HTML_ENABLED:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    data: list[dict[str, Any]] = []
    truncated = False
    for idx, card in enumerate(cards):
        if idx >= MAX_REPORT_ROWS:
            truncated = True
            break
        data.append(to_plain(card))
    html_text = _cards_html(title, data, text_field, truncated=truncated)
    if len(html_text.encode("utf-8")) <= MAX_HTML_BYTES:
        path.write_text(html_text, encoding="utf-8")
        return

    stem_dir = path.with_suffix("")
    stem_dir.mkdir(parents=True, exist_ok=True)
    part_paths: list[Path] = []
    part: list[dict[str, Any]] = []
    part_number = 1
    for card in data:
        trial = _cards_html(f"{title} Part {part_number:03d}", part + [card], text_field)
        if part and len(trial.encode("utf-8")) > MAX_HTML_BYTES:
            part_path = stem_dir / f"report_part_{part_number:03d}.html"
            part_path.write_text(_cards_html(f"{title} Part {part_number:03d}", part, text_field), encoding="utf-8")
            part_paths.append(part_path)
            part_number += 1
            part = [card]
        else:
            part.append(card)
    if part:
        part_path = stem_dir / f"report_part_{part_number:03d}.html"
        part_path.write_text(_cards_html(f"{title} Part {part_number:03d}", part, text_field), encoding="utf-8")
        part_paths.append(part_path)
    index = ["<!doctype html><meta charset='utf-8'>", f"<title>{html.escape(title)}</title>", f"<style>{CSS}</style>", f"<h1>{html.escape(title)}</h1>"]
    index.append("<div class='card'><p>Report split because the full HTML exceeded 25 MB.</p>")
    for part_path in part_paths:
        index.append(f"<div><a href='{html.escape(str(part_path.name))}'>{html.escape(part_path.name)}</a></div>")
    index.append("</div>")
    (stem_dir / "report_index.html").write_text("".join(index), encoding="utf-8")
    path.write_text("".join(index), encoding="utf-8")


def write_case_summary(path_json: Path, path_html: Path, summary: dict[str, Any]) -> None:
    write_json(path_json, summary)
    if not HTML_ENABLED:
        return
    parts = ["<!doctype html><meta charset='utf-8'>", "<title>Case Summary</title>", f"<style>{CSS}</style>", "<h1>Case Summary</h1>"]
    for section in ("device", "manifest", "results"):
        parts.append(f"<div class='card'><h2>{section.title()}</h2>")
        for key, value in summary.get(section, {}).items():
            parts.append(f"<div><span class='muted'>{html.escape(str(key))}:</span> {html.escape(str(value))}</div>")
        parts.append("</div>")
    if summary.get("warnings"):
        parts.append("<div class='card'><h2>Warnings</h2>")
        for warning in summary["warnings"]:
            parts.append(f"<p class='warn'>{html.escape(str(warning))}</p>")
        parts.append("</div>")
    if summary.get("notes"):
        parts.append("<div class='card'><h2>Notes</h2>")
        for note in summary["notes"]:
            parts.append(f"<p>{html.escape(str(note))}</p>")
        parts.append("</div>")
    path_html.write_text("".join(parts), encoding="utf-8")
