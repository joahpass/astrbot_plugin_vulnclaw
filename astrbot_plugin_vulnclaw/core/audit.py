from __future__ import annotations

import json
import hashlib
import os
import threading
from pathlib import Path
from typing import Any

from .models import utc_now


REDACT_KEYS = {
    "api_key",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "worker_secret",
}


class AuditLogger:
    def __init__(self, data_dir: str | Path, filename: str = "audit.jsonl") -> None:
        self.path = Path(data_dir) / filename
        self._lock = threading.RLock()
        self._last_hash = self._read_last_hash()

    def record(self, event: str, *, task_id: str = "", **data: Any) -> dict[str, Any]:
        with self._lock:
            entry = {
                "time": utc_now(),
                "event": event,
                "task_id": task_id,
                "data": self._redact(data),
                "previous_hash": self._last_hash,
            }
            canonical = json.dumps(
                entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            entry["entry_hash"] = hashlib.sha256(canonical).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            self._last_hash = entry["entry_hash"]
        return entry

    def tail(self, task_id: str = "", limit: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if not task_id or item.get("task_id") == task_id:
                entries.append(item)
        return entries[-max(1, min(limit, 200)) :]

    def verify_chain(self) -> bool:
        previous = ""
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            entry_hash = str(item.pop("entry_hash", ""))
            if item.get("previous_hash", "") != previous:
                return False
            canonical = json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != entry_hash:
                return False
            previous = entry_hash
        return True

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return ""
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line]
        if not lines:
            return ""
        try:
            return str(json.loads(lines[-1]).get("entry_hash", ""))
        except json.JSONDecodeError:
            return ""

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): (
                    "***REDACTED***"
                    if any(marker in str(key).lower() for marker in REDACT_KEYS)
                    else self._redact(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value
