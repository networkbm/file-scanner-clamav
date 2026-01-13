import json
from datetime import datetime, timezone
from pathlib import Path


def write_audit_event(event: dict, log_path: str = "audit.log.jsonl") -> None:
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **event
    }
    Path(log_path).write_text("", encoding="utf-8") if not Path(log_path).exists() else None
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
