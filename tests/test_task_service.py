from __future__ import annotations

import pytest

from astrbot_plugin_vulnclaw.core.audit import AuditLogger
from astrbot_plugin_vulnclaw.core.database import TaskRepository
from astrbot_plugin_vulnclaw.core.models import TaskStatus
from astrbot_plugin_vulnclaw.core.scope import ScopeValidator
from astrbot_plugin_vulnclaw.core.task_service import TaskService


class FakeWorker:
    def __init__(self) -> None:
        self.finished = False

    async def start_task(self, task_id, spec):
        return {"run_id": "container-id", "status": "running"}

    async def finish(self, task_id, *, summary, findings, report_markdown):
        self.finished = True
        return {"status": "completed"}

    async def status(self, task_id):
        return {
            "status": "completed",
            "stage": "completed",
            "summary": "完成",
            "findings": [{"title": "测试发现", "severity": "low"}],
            "report_path": f"/task/{task_id}/report.md",
        }

    async def cancel(self, task_id):
        return {"status": "cancelled"}


@pytest.mark.asyncio
async def test_plan_approve_agent_and_finish(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    worker = FakeWorker()

    async def agent(task):
        return {
            "summary": "完成",
            "findings": [{"title": "测试发现", "severity": "low"}],
            "report_markdown": "# 报告",
        }

    service = TaskService(
        repository=repository,
        audit=AuditLogger(tmp_path),
        scope_validator=ScopeValidator(lambda _host: ["203.0.113.12"]),
        worker=worker,
        enable_high_risk_modes=False,
        agent_runner=agent,
    )
    task, code = service.create_plan(
        mode="scan",
        target="https://target.example",
        ports=[443],
        paths=["/"],
        requester_umo="qq:test",
        requester_id="42",
        authorization_statement="已取得目标所有者授权",
    )
    assert task.status == TaskStatus.DRAFT
    await service.approve(task.task_id, code, approver_id="admin", is_admin=True)
    await service._queue.join()
    completed = repository.get(task.task_id)
    assert completed.status == TaskStatus.COMPLETED
    assert worker.finished
    assert repository.findings(task.task_id)[0]["title"] == "测试发现"


def test_high_risk_mode_disabled_and_authorization_required(tmp_path) -> None:
    service = TaskService(
        repository=TaskRepository(tmp_path),
        audit=AuditLogger(tmp_path),
        scope_validator=ScopeValidator(lambda _host: ["203.0.113.12"]),
        worker=None,
        enable_high_risk_modes=False,
    )
    with pytest.raises(ValueError, match="高风险"):
        service.create_plan(
            mode="exploit",
            target="https://target.example",
            ports=[443],
            paths=["/"],
            requester_umo="qq:test",
            requester_id="42",
            authorization_statement="authorized",
        )
    with pytest.raises(ValueError, match="授权"):
        service.create_plan(
            mode="scan",
            target="https://target.example",
            ports=[443],
            paths=["/"],
            requester_umo="qq:test",
            requester_id="42",
        )

