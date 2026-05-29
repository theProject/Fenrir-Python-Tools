from tools.forensic_deep_scan import is_deep_candidate
from tools.forensic_models import ManifestRecord
from tools.forensic_teams import scan_text_keywords


def test_deep_candidate_detection():
    record = ManifestRecord("id", "AppDomain-com.teslamotors.TeslaApp", "Library/Application Support/cache/state.json")
    assert is_deep_candidate(record)


def test_keyword_search_in_raw_text(tmp_path):
    path = tmp_path / "state.log"
    path.write_text("Monitor keyword appears here", encoding="utf-8")
    record = ManifestRecord("id", "AppDomain-com.example.app", "Library/Logs/state.log")
    hits = scan_text_keywords(path, record, ["Monitor"])
    assert hits[0].keyword == "Monitor"
