import argparse
import plistlib
import sqlite3

from tools.forensic_backup import BackupExtractor
from tools.forensic_backup import add_forensic_parser
from tools.forensic_common import is_likely_directory_record
from tools.forensic_deep_scan import DEFAULT_DEEP_KEYWORDS, is_deep_candidate, run_deep_scan
from tools.forensic_models import ManifestRecord
from tools.forensic_teams import inspect_sqlite_keywords, scan_text_keywords


def test_deep_candidate_detection():
    record = ManifestRecord("id", "AppDomain-com.teslamotors.TeslaApp", "Library/Application Support/cache/state.json")
    assert is_deep_candidate(record)


def test_keyword_search_in_raw_text(tmp_path):
    path = tmp_path / "state.log"
    path.write_text("Monitor keyword appears here", encoding="utf-8")
    record = ManifestRecord("id", "AppDomain-com.example.app", "Library/Logs/state.log")
    hits = scan_text_keywords(path, record, ["Monitor"])
    assert hits[0].keyword == "Monitor"


def test_deep_scan_export_context_parses_as_integer():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    add_forensic_parser(sub)
    args = parser.parse_args(["forensics", "--source", "/tmp/backup", "--deep-scan-export-context", "17"])
    assert args.deep_scan_export_context == 17
    assert isinstance(args.deep_scan_export_context, int)


def test_deep_scan_default_cli_values_are_forensic_complete():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    add_forensic_parser(sub)
    args = parser.parse_args(["forensics", "--source", "/tmp/backup"])
    assert args.deep_scan_export_context == 240
    assert args.deep_scan_sqlite_row_limit == 0


def test_deep_scan_default_keywords_still_include_required_terms():
    assert {"Tesla", "Julio", "Jake", "Monitor", "ADHD", "Bikrom"}.issubset(set(DEFAULT_DEEP_KEYWORDS))


def _keyword_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cache_items (body TEXT)")
    conn.execute("INSERT INTO cache_items VALUES ('Tesla first row')")
    conn.execute("INSERT INTO cache_items VALUES ('Tesla second row')")
    conn.commit()
    conn.close()


def test_sqlite_row_limit_zero_scans_all_rows(tmp_path):
    db = tmp_path / "cache.sqlite"
    _keyword_db(db)
    record = ManifestRecord("id", "AppDomain-com.example.app", "Library/Caches/cache.sqlite")
    _, _, hits = inspect_sqlite_keywords(db, ["Tesla"], 0, tmp_path / "samples", record)
    assert len(hits) == 2


def test_sqlite_row_limit_one_scans_only_one_row(tmp_path):
    db = tmp_path / "cache.sqlite"
    _keyword_db(db)
    record = ManifestRecord("id", "AppDomain-com.example.app", "Library/Caches/cache.sqlite")
    _, _, hits = inspect_sqlite_keywords(db, ["Tesla"], 1, tmp_path / "samples", record)
    assert len(hits) == 1


def test_deep_scan_hit_snippets_respect_configured_context(tmp_path):
    path = tmp_path / "state.log"
    path.write_text("AAAAATeslaBBBBB", encoding="utf-8")
    record = ManifestRecord("id", "AppDomain-com.example.app", "Library/Logs/state.log")
    hits = scan_text_keywords(path, record, ["Tesla"], context=2)
    assert hits[0].snippet == "AATeslaBB"


def test_deep_scan_skips_outlook_httpstorages_directory_without_warning(tmp_path):
    backup = tmp_path / "BACKUP_UUID"
    backup.mkdir()
    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)
    record = ManifestRecord("id", "AppDomain-com.microsoft.Office.Outlook", "Library/HTTPStorages")
    extractor = BackupExtractor(backup, tmp_path / "case", None)
    warnings: list[str] = []

    result = run_deep_scan([record], extractor, tmp_path / "case", ["Tesla"], 5, False, 5, 0, 120, warnings)

    assert result["directory_records_skipped"] == 1
    assert result["extraction_failures"] == 0
    assert warnings == []
    skipped = (tmp_path / "case" / "deep_scan" / "skipped_files.csv").read_text(encoding="utf-8")
    assert "directory_record_not_extractable" in skipped


def test_deep_scan_extensionless_candidate_still_extracts_and_scans(tmp_path):
    backup = tmp_path / "BACKUP_UUID"
    backup.mkdir()
    (backup / "aa").mkdir()
    with (backup / "Manifest.plist").open("wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)
    (backup / "aa" / "aaaaaaaa").write_text("Tesla in extensionless cache", encoding="utf-8")
    record = ManifestRecord("aaaaaaaa", "AppDomain-com.example.app", "Library/Caches/user")
    extractor = BackupExtractor(backup, tmp_path / "case", None)
    warnings: list[str] = []

    result = run_deep_scan([record], extractor, tmp_path / "case", ["Tesla"], 5, False, 5, 0, 120, warnings)

    assert result["extracted_files"] == 1
    assert result["directory_records_skipped"] == 0
    assert result["keyword_hits"] == 1
    assert warnings == []


def test_milestone_1_1_known_container_warning_paths_are_skipped():
    paths = [
        (
            "AppDomain-com.microsoft.Office.Word",
            "Library/Application Support/Microsoft/Office/16.0/SitesServiceCache",
        ),
        (
            "AppDomain-com.microsoft.Office.Word",
            "Library/Application Support/Microsoft/Office/16.0/MruServiceCache/UnsignedUser",
        ),
        (
            "AppDomain-com.microsoft.Office.Outlook",
            "Library/WebKit/WebsiteData/Default/ABCDEF1234567890/ABCDEF1234567890/LocalStorage",
        ),
        (
            "AppDomain-com.microsoft.sharepoint",
            "Library/WebKit/WebsiteData/Default/ABCDEF1234567890/ABCDEF1234567890/IndexedDB",
        ),
        ("AppDomain-com.microsoft.sharepoint", "Library/localCacheRoot"),
        ("AppDomainGroup-group.com.microsoft.sharepoint", "sharedlogs"),
        ("AppDomain-com.microsoft.copilot", "Library/Application Support/AttachmentStorage"),
        ("AppDomainPlugin-com.microsoft.skydrive.onedrivefileprovider", "Library/StreamCache"),
        ("AppDomainGroup-group.com.microsoft.onenote", "ShareExtension/Logs"),
        (
            "AppDomain-com.microsoft.Office.Word",
            "Library/Application Support/Microsoft/Office/16.0/BackstageInAppNavCache",
        ),
        (
            "AppDomain-com.microsoft.Office.Word",
            "Library/Application Support/Microsoft/Office/16.0/ResourceInfoCache",
        ),
        (
            "AppDomain-com.microsoft.Office.Word",
            "Library/Application Support/Microsoft/Office/16.0/WebServiceCache",
        ),
    ]

    for domain, relative_path in paths:
        assert is_likely_directory_record(domain, relative_path), relative_path


def test_milestone_1_1_clear_files_below_containers_are_not_skipped():
    paths = [
        ("AppDomain-com.example.app", "Library/Caches/user"),
        (
            "AppDomain-com.microsoft.Office.Outlook",
            "Library/WebKit/WebsiteData/Default/foo/LocalStorage/leveldb/000003.log",
        ),
        (
            "AppDomain-com.microsoft.sharepoint",
            "Library/WebKit/WebsiteData/Default/foo/IndexedDB/blob.sqlite",
        ),
        ("AppDomain-com.microsoft.sharepoint", "Library/localCacheRoot/somefile.json"),
    ]

    for domain, relative_path in paths:
        assert not is_likely_directory_record(domain, relative_path), relative_path


def test_milestone_1_1_hash_like_extensionless_indexeddb_child_is_skipped_unless_file_metadata():
    path = "Library/WebKit/WebsiteData/Default/foo/IndexedDB/0123456789abcdef0123456789ABCDEF"

    assert is_likely_directory_record("AppDomain-com.microsoft.sharepoint", path)
    assert not is_likely_directory_record(
        "AppDomain-com.microsoft.sharepoint",
        path,
        {"Mode": 0o100644},
    )


def test_milestone_1_2_microsoft_virtual_storage_warning_paths_are_skipped():
    paths = [
        ("AppDomain-com.microsoft.splists", "Library/WebKit/WebsiteData/IndexedDB/v0"),
        ("AppDomain-com.microsoft.sharepoint", "Library/localCacheRoot/e5abe53d95bcb1c8ecd317956df7510c"),
        ("AppDomain-com.microsoft.sharepoint", "Library/localCacheRoot/e5abe53d95bcb1c8ecd317956df7510c/files"),
        ("AppDomain-com.microsoft.sharepoint", "Documents/RCTAsyncLocalStorage_V1"),
        ("AppDomainPlugin-com.microsoft.skydrive.OneDriveMessageExtension", ""),
        ("AppDomainPlugin-com.microsoft.skydrive.OneDriveMessageExtension", "Library"),
        ("AppDomainPlugin-com.microsoft.skydrive.OneDriveMessageExtension", "Library/Preferences"),
        ("AppDomainPlugin-com.microsoft.skydrive.OneDriveMessageExtension", "Documents"),
        ("AppDomain-com.microsoft.o365shdmobileapp", "Documents/.config/.isolated-storage"),
        ("AppDomain-com.microsoft.skype.teams", "Library/WebKit/WebsiteData/IndexedDB/v1"),
        ("AppDomainGroup-group.com.microsoft.shared", "com.microsoft.splists_logs"),
        ("AppDomain-com.microsoft.onenote", "Library/Application Support/Microsoft/UserInfoCache"),
        ("AppDomainGroup-group.com.microsoft.onedrive", "AriaEventEntryCache"),
        ("AppDomainGroup-group.com.microsoft.onedrive", "File Provider Storage"),
        (
            "AppDomainGroup-group.com.microsoft.onedrive",
            "File Provider Storage/item|149|8b1f1304%2Dfead%2D4bf0%2D9326%2D23f87a71040c",
        ),
    ]

    for domain, relative_path in paths:
        assert is_likely_directory_record(domain, relative_path), relative_path


def test_milestone_1_2_clear_files_under_virtual_containers_are_not_skipped():
    paths = [
        ("AppDomainGroup-group.com.microsoft.onedrive", "File Provider Storage/item|1|abc/file.json"),
        ("AppDomain-com.microsoft.sharepoint", "Library/localCacheRoot/cache.sqlite"),
        ("AppDomain-com.microsoft.msedge", "Library/WebKit/WebsiteData/Default/foo/IndexedDB/blob.sqlite"),
        ("AppDomain-com.example.app", "Library/Caches/user"),
    ]

    for domain, relative_path in paths:
        assert not is_likely_directory_record(domain, relative_path), relative_path


def test_milestone_1_2_onedrive_item_pseudo_path_is_not_skipped_when_metadata_proves_file():
    path = "File Provider Storage/item|149|8b1f1304%2Dfead%2D4bf0%2D9326%2D23f87a71040c"

    assert not is_likely_directory_record(
        "AppDomainGroup-group.com.microsoft.onedrive",
        path,
        {"Mode": 0o100644},
    )
