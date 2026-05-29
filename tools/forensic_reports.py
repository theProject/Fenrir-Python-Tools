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
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [to_plain(r) for r in rows]
    fields = list(data[0].keys()) if data else []
    parts = ["<!doctype html><meta charset='utf-8'>", f"<title>{html.escape(title)}</title>", f"<style>{CSS}</style>"]
    parts.append(f"<h1>{html.escape(title)}</h1>")
    if intro:
        parts.append(f"<div class='card'>{html.escape(intro)}</div>")
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


def write_cards_html(path: Path, title: str, cards: Iterable[dict[str, Any]], text_field: str = "snippet") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parts = ["<!doctype html><meta charset='utf-8'>", f"<title>{html.escape(title)}</title>", f"<style>{CSS}</style>"]
    parts.append(f"<h1>{html.escape(title)}</h1>")
    count = 0
    for card in cards:
        count += 1
        parts.append("<div class='card'>")
        for key, value in to_plain(card).items():
            safe = html.escape("" if value is None else str(value))
            if key == text_field:
                parts.append(f"<p>{safe}</p>")
            else:
                parts.append(f"<div><span class='muted'>{html.escape(key)}:</span> {safe}</div>")
        parts.append("</div>")
    if count == 0:
        parts.append("<div class='card muted'>No records.</div>")
    path.write_text("".join(parts), encoding="utf-8")


def write_case_summary(path_json: Path, path_html: Path, summary: dict[str, Any]) -> None:
    write_json(path_json, summary)
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
