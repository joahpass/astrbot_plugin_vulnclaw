from __future__ import annotations

from astrbot_plugin_vulnclaw.core.audit import AuditLogger
from astrbot_plugin_vulnclaw.core.database import TaskRepository
from astrbot_plugin_vulnclaw.core.models import (
    TaskMode,
    TaskRecord,
    TaskScope,
    TaskStatus,
    utc_now,
)


def make_task(status: TaskStatus = TaskStatus.RUNNING) -> TaskRecord:
    now = utc_now()
    return TaskRecord(
        task_id="vuln-123456abcdef",
        mode=TaskMode.SCAN,
        scope=TaskScope(
            target="https://target.example",
            hostname="target.example",
            scheme="https",
            resolved_ips=["203.0.113.8"],
            ports=[443],
            paths=["/"],
            expires_at="2099-01-01T00:00:00+00:00",
        ),
        status=status,
        requester_umo="qq:test",
        requester_id="42",
        created_at=now,
        updated_at=now,
    )


def test_repository_recovers_running_task_as_interrupted(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    repository.save(make_task())
    reopened = TaskRepository(tmp_path)
    task = reopened.get("vuln-123456abcdef")
    assert task.status == TaskStatus.INTERRUPTED
    assert "不会自动恢复" in task.error


def test_audit_redacts_nested_secrets(tmp_path) -> None:
    audit = AuditLogger(tmp_path)
    audit.record(
        "tool",
        task_id="vuln-123456abcdef",
        token="secret-value",
        nested={"Authorization": "Bearer abc", "safe": "ok"},
    )
    entry = audit.tail()[0]
    assert "secret-value" not in str(entry)
    assert "Bearer abc" not in str(entry)
    assert entry["data"]["nested"]["safe"] == "ok"
    audit.record("second", task_id="vuln-123456abcdef")
    assert audit.verify_chain()
