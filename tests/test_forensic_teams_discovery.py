import sqlite3

from tools.forensic_models import ManifestRecord
from tools.forensic_teams import inspect_sqlite_keywords, is_teams_candidate


def test_teams_candidate_detection():
    record = ManifestRecord("id", "AppDomainGroup-group.com.microsoft.skype.teams", "Library/Caches/chat.sqlite")
    assert is_teams_candidate(record)


def test_keyword_search_in_sqlite(tmp_path):
    db = tmp_path / "chat.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE messages (body TEXT)")
    conn.execute("INSERT INTO messages VALUES ('Chris mentioned Teams')")
    conn.commit()
    conn.close()
    record = ManifestRecord("id", "AppDomain-com.microsoft.skype.teams", "Library/Caches/chat.sqlite")
    _, _, hits = inspect_sqlite_keywords(db, ["Chris"], 100, tmp_path / "samples", record)
    assert len(hits) == 1
    assert hits[0].table == "messages"
