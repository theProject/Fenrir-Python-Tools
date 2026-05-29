import sqlite3
from pathlib import Path

from tools.forensic_common import apple_timestamp_to_utc, decode_attributed_body
from tools.forensic_sms import parse_sms_exports


def make_sms_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
    conn.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, date INTEGER, is_from_me INTEGER, handle_id INTEGER, text TEXT, attributedBody BLOB, service TEXT)")
    conn.execute("CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT, chat_identifier TEXT, display_name TEXT)")
    conn.execute("CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER)")
    conn.execute("CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT, transfer_name TEXT)")
    conn.execute("CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER)")
    conn.execute("INSERT INTO handle VALUES (1, '+15551234567')")
    conn.execute("INSERT INTO chat VALUES (1, 'chat-guid', '+15551234567', 'Test Chat')")
    conn.execute("INSERT INTO message VALUES (1, 'msg-guid', 700000000000000000, 0, 1, '', ?, 'iMessage')", (b"\x00Hello from attributed body\x00",))
    conn.execute("INSERT INTO chat_message_join VALUES (1, 1)")
    conn.commit()
    conn.close()


def test_sms_parser_exports_dynamic_schema(tmp_path):
    db = tmp_path / "sms.db"
    make_sms_db(db)
    warnings: list[str] = []
    result = parse_sms_exports(db, tmp_path / "sms", warnings)
    assert result["messages"] == 1
    assert "attributed body" in (tmp_path / "sms" / "sms_messages.json").read_text()
    assert warnings == []


def test_apple_timestamp_conversion_handles_nanoseconds():
    assert apple_timestamp_to_utc(700000000000000000).startswith("2023-03")


def test_attributed_body_fallback():
    text, source = decode_attributed_body(b"\x00Readable fragment here\x00")
    assert "Readable fragment" in text
    assert source == "attributedBody_fragment"
