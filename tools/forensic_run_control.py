from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STAGES = (
    "workspace",
    "sms",
    "teams",
    "deep_scan",
    "system_artifacts",
    "photos",
    "timeline",
    "review",
    "case_focus",
    "evidence_manifest",
    "case_summary",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunControl:
    def __init__(self, output: Path, only_stage: str | None = None, skip_stages: list[str] | None = None, stop_after_stage: str | None = None):
        self.output = output
        self.status_path = output / "partial_run_status.json"
        self.log_path = output / "run_log.txt"
        self.only_stage = only_stage
        self.skip_stages = set(skip_stages or [])
        self.stop_after_stage = stop_after_stage
        self.status: dict[str, Any] = {"generated_at": utc_now_iso(), "stages": {}}

    def enabled(self, stage: str) -> bool:
        if self.only_stage and stage != self.only_stage:
            return False
        return stage not in self.skip_stages

    def should_stop_after(self, stage: str) -> bool:
        return bool(self.stop_after_stage and self.stop_after_stage == stage)

    def log(self, message: str) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        line = f"{utc_now_iso()} {message}"
        print(line, flush=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()

    def start(self, stage: str) -> None:
        self.log(f"START {stage}")
        self.status["stages"][stage] = {
            "started_at": utc_now_iso(),
            "completed_at": "",
            "status": "running",
            "row_counts": {},
            "error": "",
        }
        self.write()

    def complete(self, stage: str, row_counts: dict[str, Any] | None = None) -> None:
        entry = self.status["stages"].setdefault(stage, {"started_at": "", "completed_at": "", "status": "", "row_counts": {}, "error": ""})
        entry["completed_at"] = utc_now_iso()
        entry["status"] = "completed"
        entry["row_counts"] = row_counts or {}
        self.log(f"COMPLETE {stage} {json.dumps(entry['row_counts'], default=str)}")
        self.write()

    def skip(self, stage: str, reason: str) -> None:
        self.status["stages"][stage] = {
            "started_at": "",
            "completed_at": utc_now_iso(),
            "status": "skipped",
            "row_counts": {},
            "error": reason,
        }
        self.log(f"SKIP {stage} {reason}")
        self.write()

    def fail(self, stage: str, error: Exception) -> None:
        entry = self.status["stages"].setdefault(stage, {"started_at": "", "completed_at": "", "status": "", "row_counts": {}, "error": ""})
        entry["completed_at"] = utc_now_iso()
        entry["status"] = "error"
        entry["error"] = str(error)
        self.log(f"ERROR {stage} {error}")
        self.write()

    def write(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        self.status["updated_at"] = utc_now_iso()
        self.status_path.write_text(json.dumps(self.status, indent=2, default=str), encoding="utf-8")
