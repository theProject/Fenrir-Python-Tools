# Main CLI for Python iOS Rescue Tools
import argparse, os, sys
from utils import log_info, log_warn, log_ok, ensure_dir
from settings import VERSION, normalize_path
from tools.manifest_parser import parse_manifest
from tools.contact_parser import extract_contacts
from tools.message_parser import extract_messages
from tools.photo_recovery import export_photos
from tools.note_parser import extract_notes
from tools.calendar_parser import extract_calendar
from tools.password_rescue import probe_password_artifacts
from tools.report_generator import build_report
from tools.forensic_backup import add_forensic_parser, run_forensic_triage
from tools.forensic_case_focus import add_investigate_parser, run_investigate

def main():
    parser = argparse.ArgumentParser(prog="iOS Rescue Tools", description="Extract • Decode • Recover")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # analyze
    p_an = sub.add_parser("analyze", help="Parse Manifest.db and index backup")
    p_an.add_argument("source")
    p_an.add_argument("--output", "-o", default="./rescue/manifest")

    # contacts
    p_ct = sub.add_parser("contacts", help="Extract contacts")
    p_ct.add_argument("--source", required=True)
    p_ct.add_argument("--output", "-o", default="./rescue/contacts")
    p_ct.add_argument("--format", choices=["csv","json","html"], default="csv")

    # messages
    p_ms = sub.add_parser("messages", help="Extract messages and attachments")
    p_ms.add_argument("--source", required=True)
    p_ms.add_argument("--output", "-o", default="./rescue/messages")

    # photos
    p_ph = sub.add_parser("photos", help="Export photos/media")
    p_ph.add_argument("--source", required=True)
    p_ph.add_argument("--output", "-o", default="./rescue/photos")
    p_ph.add_argument("--convert-heic", action="store_true")

    # notes
    p_no = sub.add_parser("notes", help="Extract notes")
    p_no.add_argument("--source", required=True)
    p_no.add_argument("--output", "-o", default="./rescue/notes")

    # calendar
    p_ca = sub.add_parser("calendar", help="Extract calendar events")
    p_ca.add_argument("--source", required=True)
    p_ca.add_argument("--output", "-o", default="./rescue/calendar")

    # password (probe only)
    p_pw = sub.add_parser("passwords", help="Probe for possible keychain artifacts (no decryption)")
    p_pw.add_argument("--source", required=True)

    # report
    p_rp = sub.add_parser("report", help="Build summary report from module exports")
    p_rp.add_argument("--source", required=True, help="Root folder where module exports live")
    p_rp.add_argument("--output", "-o", default="./rescue/summary.html")

    add_forensic_parser(sub)
    add_investigate_parser(sub)

    args = parser.parse_args()

    if args.cmd == "analyze":
        idx = parse_manifest(normalize_path(args.source), normalize_path(args.output))
        return

    if args.cmd == "contacts":
        extract_contacts(normalize_path(args.source), normalize_path(args.output), fmt=args.format)
        return

    if args.cmd == "messages":
        extract_messages(normalize_path(args.source), normalize_path(args.output))
        return

    if args.cmd == "photos":
        export_photos(normalize_path(args.source), normalize_path(args.output), convert_heic=args.convert_heic)
        return

    if args.cmd == "notes":
        extract_notes(normalize_path(args.source), normalize_path(args.output))
        return

    if args.cmd == "calendar":
        extract_calendar(normalize_path(args.source), normalize_path(args.output))
        return

    if args.cmd == "passwords":
        probe_password_artifacts(normalize_path(args.source))
        return

    if args.cmd == "report":
        build_report(normalize_path(args.source), normalize_path(args.output))
        return

    if args.cmd == "forensics":
        run_forensic_triage(args)
        return

    if args.cmd == "investigate":
        run_investigate(args)
        return

if __name__ == "__main__":
    main()
