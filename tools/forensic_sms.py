from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from tools.forensic_common import apple_timestamp_to_utc, decode_attributed_body, open_sqlite_ro, safe_output_path
from tools.forensic_models import ExtractedArtifact, ManifestRecord
from tools.forensic_reports import write_csv, write_json, write_table_html


SMS_TARGETS = [
    ("HomeDomain", "Library/SMS/sms.db"),
    ("HomeDomain", "Library/SMS/sms.db-wal"),
    ("HomeDomain", "Library/SMS/sms.db-shm"),
]


def extract_sms_artifacts(
    records: list[ManifestRecord],
    index: dict[tuple[str, str], ManifestRecord],
    extractor: Any,
    output: Path,
    include_attachments: bool,
) -> tuple[list[ExtractedArtifact], list[str]]:
    artifacts: list[ExtractedArtifact] = []
    warnings: list[str] = []
    for domain, rel in SMS_TARGETS:
        record = index.get((domain, rel))
        if not record:
            if rel.endswith("sms.db"):
                warnings.append("sms.db was not found in the manifest. This backup may not contain Messages data, or Messages may not have been included.")
            continue
        artifacts.append(extractor.extract_record(record, safe_output_path(output / "extracted_files", domain, rel), "sms"))
    if include_attachments:
        for record in records:
            if record.domain == "HomeDomain" and record.relative_path.startswith("Library/SMS/Attachments/"):
                artifacts.append(extractor.extract_record(record, safe_output_path(output / "extracted_files", record.domain, record.relative_path), "sms_attachment"))
    return artifacts, warnings


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return bool(row)


def _read_handles(conn: sqlite3.Connection) -> dict[int, str]:
    if not _table_exists(conn, "handle"):
        return {}
    return {row["ROWID"]: row["id"] for row in conn.execute("SELECT ROWID, id FROM handle")}


def _read_chat_maps(conn: sqlite3.Connection) -> tuple[dict[int, list[int]], dict[int, dict[str, Any]]]:
    msg_to_chats: dict[int, list[int]] = {}
    chats: dict[int, dict[str, Any]] = {}
    if _table_exists(conn, "chat_message_join"):
        for row in conn.execute("SELECT chat_id, message_id FROM chat_message_join"):
            msg_to_chats.setdefault(row["message_id"], []).append(row["chat_id"])
    if _table_exists(conn, "chat"):
        cols = _columns(conn, "chat")
        select = ["ROWID"]
        for col in ("guid", "chat_identifier", "display_name", "service_name"):
            if col in cols:
                select.append(col)
        for row in conn.execute(f"SELECT {', '.join(select)} FROM chat"):
            chats[row["ROWID"]] = dict(row)
    return msg_to_chats, chats


def _read_attachments(conn: sqlite3.Connection) -> tuple[dict[int, list[dict[str, Any]]], list[dict[str, Any]]]:
    if not (_table_exists(conn, "attachment") and _table_exists(conn, "message_attachment_join")):
        return {}, []
    cols = _columns(conn, "attachment")
    select = ["a.ROWID"]
    for col in ("guid", "filename", "transfer_name", "mime_type", "total_bytes", "created_date"):
        if col in cols:
            select.append(f"a.{col}")
    sql = f"SELECT maj.message_id, {', '.join(select)} FROM message_attachment_join maj JOIN attachment a ON a.ROWID=maj.attachment_id"
    by_msg: dict[int, list[dict[str, Any]]] = {}
    all_rows: list[dict[str, Any]] = []
    for row in conn.execute(sql):
        data = dict(row)
        all_rows.append(data)
        by_msg.setdefault(row["message_id"], []).append(data)
    return by_msg, all_rows


def parse_sms_exports(sms_db: Path, output: Path, warnings: list[str]) -> dict[str, int]:
    output.mkdir(parents=True, exist_ok=True)
    if not sms_db.exists():
        write_csv(output / "sms_messages.csv", [])
        write_json(output / "sms_messages.json", [])
        write_table_html(output / "sms_messages.html", "SMS / iMessage Messages", [])
        return {"messages": 0}
    try:
        conn = open_sqlite_ro(sms_db)
    except sqlite3.Error:
        warnings.append("Could not open SQLite database read-only. File may be corrupt, encrypted internally, or not actually SQLite.")
        return {"messages": 0}
    try:
        handles = _read_handles(conn)
        msg_to_chats, chats = _read_chat_maps(conn)
        attachments_by_msg, attachments = _read_attachments(conn)
        msg_cols = _columns(conn, "message")
        if not msg_cols:
            warnings.append("SMS database did not contain a message table.")
            return {"messages": 0}
        select = ["ROWID"]
        wanted = [
            "guid", "date", "date_read", "date_delivered", "is_from_me", "handle_id", "service", "account", "text",
            "attributedBody", "subject", "country", "error", "associated_message_guid", "associated_message_type",
            "message_action_type", "cache_has_attachments",
        ]
        select.extend([c for c in wanted if c in msg_cols])
        messages: list[dict[str, Any]] = []
        for row in conn.execute(f"SELECT {', '.join(select)} FROM message ORDER BY date ASC"):
            data = dict(row)
            text = data.get("text") or ""
            text_source = "text" if text else "empty"
            if not text and "attributedBody" in data:
                text, text_source = decode_attributed_body(data.get("attributedBody"))
            chat_ids = msg_to_chats.get(data["ROWID"], [])
            chat_rows = [chats.get(cid, {}) for cid in chat_ids]
            msg_attachments = attachments_by_msg.get(data["ROWID"], [])
            messages.append(
                {
                    "message_id": data["ROWID"],
                    "guid": data.get("guid"),
                    "datetime_utc": apple_timestamp_to_utc(data.get("date")),
                    "date_read_utc": apple_timestamp_to_utc(data.get("date_read")),
                    "date_delivered_utc": apple_timestamp_to_utc(data.get("date_delivered")),
                    "direction": "outgoing" if data.get("is_from_me") == 1 else "incoming",
                    "is_from_me": data.get("is_from_me"),
                    "handle_id": data.get("handle_id"),
                    "handle": handles.get(data.get("handle_id")),
                    "service": data.get("service"),
                    "account": data.get("account"),
                    "text": text,
                    "text_source": text_source,
                    "subject": data.get("subject"),
                    "country": data.get("country"),
                    "error": data.get("error"),
                    "chat_ids": ",".join(str(c) for c in chat_ids),
                    "chat_identifiers": ",".join(str(c.get("chat_identifier") or c.get("guid") or "") for c in chat_rows),
                    "chat_display_names": ",".join(str(c.get("display_name") or "") for c in chat_rows),
                    "attachments_json": json.dumps(msg_attachments, ensure_ascii=False, default=str),
                    "associated_message_guid": data.get("associated_message_guid"),
                    "associated_message_type": data.get("associated_message_type"),
                    "message_action_type": data.get("message_action_type"),
                    "cache_has_attachments": data.get("cache_has_attachments"),
                    "raw_date": data.get("date"),
                }
            )
        handle_rows = [{"handle_id": k, "handle": v} for k, v in handles.items()]
        chat_rows = [dict(v) for v in chats.values()]
        write_csv(output / "sms_messages.csv", messages)
        write_json(output / "sms_messages.json", messages)

        # === okayhacker wins ===
        write_table_html(output / "sms_messages.html", "Apple iMessage History Decrypted", messages)

        # === Quick & Dirty Signature Injection With Love from okayhacker ===
        html_path = output / "sms_messages.html"
        content = html_path.read_text(encoding="utf-8")
        styled = 'Apple iMessage History Decrypted <span style="color:#000000; -webkit-text-stroke: 3px #05f2af;"> ⛓️‍💥 </span> by <span style="color:#e20074; font-weight:bold;">okayhacker</span>'
        content = content.replace("<h1>Apple iMessage History Decrypted</h1>", f"<h1>{styled}</h1>")
        html_path.write_text(content, encoding="utf-8")
        
        write_csv(output / "sms_chats.csv", chat_rows)
        write_csv(output / "sms_handles.csv", handle_rows)
        write_csv(output / "sms_attachments.csv", attachments)
        timeline = [
            {
                "datetime_utc": m["datetime_utc"],
                "source": "sms",
                "keyword": "",
                "app_guess": "Messages",
                "domain": "HomeDomain",
                "relative_path": "Library/SMS/sms.db",
                "table": "message",
                "column": "text",
                "snippet": m["text"],
                "confidence": "high" if m["datetime_utc"] else "none",
                "parser_note": m["text_source"],
            }
            for m in messages
        ]
        write_csv(output / "sms_timeline.csv", timeline)
        return {"messages": len(messages)}
    finally:
        conn.close()
