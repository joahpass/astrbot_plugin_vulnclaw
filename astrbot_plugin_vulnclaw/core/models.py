from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TaskMode(StrEnum):
    RECON = "recon"
    SCAN = "scan"
    RUN = "run"
    EXPLOIT = "exploit"
    PERSISTENT = "persistent"
    REPORT = "report"
    POST_EXPLOITATION = "post-exploitation"


HIGH_RISK_MODES = {
    TaskMode.RUN,
    TaskMode.EXPLOIT,
    TaskMode.PERSISTENT,
    TaskMode.POST_EXPLOITATION,
}


class TaskStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_STATUSES = {
    TaskStatus.COMPLETED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
    TaskStatus.INTERRUPTED,
}


@dataclass
class TaskScope:
    target: str
    hostname: str
    scheme: str
    resolved_ips: list[str]
    ports: list[int]
    paths: list[str]
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskScope":
        return cls(
            target=str(data["target"]),
            hostname=str(data["hostname"]),
            scheme=str(data.get("scheme", "")),
            resolved_ips=[str(item) for item in data.get("resolved_ips", [])],
            ports=[int(item) for item in data.get("ports", [])],
            paths=[str(item) for item in data.get("paths", [])],
            expires_at=str(data["expires_at"]),
        )


@dataclass
class TaskRecord:
    task_id: str
    mode: TaskMode
    scope: TaskScope
    status: TaskStatus
    requester_umo: str
    requester_id: str
    created_at: str
    updated_at: str
    approval_hash: str = ""
    approval_expires_at: str = ""
    approved_by: str = ""
    approved_at: str = ""
    risk_summary: str = ""
    current_stage: str = "planned"
    progress_summary: str = ""
    report_path: str = ""
    error: str = ""
    worker_run_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mode"] = self.mode.value
        data["status"] = self.status.value
        data["scope"] = self.scope.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskRecord":
        return cls(
            task_id=str(data["task_id"]),
            mode=TaskMode(data["mode"]),
            scope=TaskScope.from_dict(dict(data["scope"])),
            status=TaskStatus(data["status"]),
            requester_umo=str(data.get("requester_umo", "")),
            requester_id=str(data.get("requester_id", "")),
            created_at=str(data["created_at"]),
            updated_at=str(data["updated_at"]),
            approval_hash=str(data.get("approval_hash", "")),
            approval_expires_at=str(data.get("approval_expires_at", "")),
            approved_by=str(data.get("approved_by", "")),
            approved_at=str(data.get("approved_at", "")),
            risk_summary=str(data.get("risk_summary", "")),
            current_stage=str(data.get("current_stage", "planned")),
            progress_summary=str(data.get("progress_summary", "")),
            report_path=str(data.get("report_path", "")),
            error=str(data.get("error", "")),
            worker_run_id=str(data.get("worker_run_id", "")),
            metadata=dict(data.get("metadata", {})),
        )

