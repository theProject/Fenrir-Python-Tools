# Case Investigation Guide

This workflow narrows forensic review around a case objective. It does not prove the case by itself; it creates a focused review queue from local backup artefacts.

## Target Pack

Create a JSON file such as `case_targets.json`:

```json
{
  "case_name": "tesla_accommodation_monitor",
  "date_range": {
    "from": "YYYY-MM-DD",
    "to": "YYYY-MM-DD"
  },
  "emails": [],
  "domains": ["tesla.com"],
  "people": [],
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
    "granted"
  ],
  "near_terms": [
    ["ADHD", "monitor"],
    ["accommodation", "monitor"],
    ["reasonable accommodation", "display"],
    ["Tesla", "ADHD"],
    ["IT", "monitor"]
  ]
}
```

## Run The Profile

```bash
.venv/bin/python rescue.py forensics \
  --source "/path/to/MobileSync/Backup/BACKUP_UUID" \
  --output "./rescue/tesla-accommodation-monitor" \
  --prompt-password \
  --case-profile tesla-accommodation-monitor \
  --target-pack case_targets.json \
  --screenshot-candidate-scan
```

Use `--password-env IOS_BACKUP_PASSWORD` instead of `--prompt-password` if you prefer environment variables. Do not put live Microsoft, Tesla, Apple, or Google account passwords into prompts, logs, target packs, or command history.

## Guided Command Builder

```bash
.venv/bin/python rescue.py investigate --dry-run \
  --source "/path/to/MobileSync/Backup/BACKUP_UUID" \
  --case-profile tesla-accommodation-monitor
```

The wizard prints the equivalent `forensics` command before any run. It may use `--prompt-password` for the local encrypted iOS backup password only.

## Confidence Labels

| Label | Meaning |
| --- | --- |
| high | Strong source plus exact/near-term matches, often with date or domain context. |
| medium | Useful match that needs review against source path, table, and snippet. |
| low | Weak contextual match. Treat as a lead, not proof. |
| fragment_only | Raw string, SQLite raw byte, or binary-adjacent fragment without enough context for higher confidence. |

## Interpretation Notes

- Microsoft CoreData rows are entity or relationship records. They are not automatically messages.
- Raw string hits are fragment-level evidence. They can identify leads but need source validation.
- SQLite raw byte hits are not deleted-row recovery unless independently proven.
- Notification fragments can show local notification content, not complete cloud message history.
- Screenshot and photo candidate scans only identify candidates in this milestone. OCR is not performed.
