from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

from .approval import generate_approval_code, hash_approval_code, verify_approval_code
from .audit import AuditLogger
from .database import TaskRepository
from .models import (
    HIGH_RISK_MODES,
    TERMINAL_STATUSES,
    TaskMode,
    TaskRecord,
    TaskStatus,
    utc_now,
)
from .scope import ScopeValidator
from .worker_client import WorkerClient


StageCallback = Callable[[TaskRecord], Awaitable[None]]
AgentRunner = Callable[[TaskRecord], Awaitable[dict[str, Any]]]


class TaskService:
    def __init__(
        self,
        *,
        repository: TaskRepository,
        audit: AuditLogger,
        scope_validator: ScopeValidator,
        worker: WorkerClient | None,
        enable_high_risk_modes: bool,
        approval_ttl_seconds: int = 600,
        task_timeout_seconds: int = 1800,
        on_stage: StageCallback | None = None,
        agent_runner: AgentRunner | None = None,
    ) -> None:
        self.repository = repository
        self.audit = audit
        self.scope_validator = scope_validator
        self.worker = worker
        self.enable_high_risk_modes = enable_high_risk_modes
        self.approval_ttl_seconds = max(60, approval_ttl_seconds)
        self.task_timeout_seconds = max(60, task_timeout_seconds)
        self.on_stage = on_stage
        self.agent_runner = agent_runner
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._runner_task: asyncio.Task[None] | None = None
        self._stop = False

    def create_plan(
        self,
        *,
        mode: str,
        target: str,
        ports: list[int],
        paths: list[str],
        requester_umo: str,
        requester_id: str,
        authorization_statement: str = "",
    ) -> tuple[TaskRecord, str]:
        task_mode = TaskMode(mode.strip().lower())
        if task_mode in HIGH_RISK_MODES and not self.enable_high_risk_modes:
            raise ValueError("插件配置未启用高风险模式")
        if not authorization_statement.strip():
            raise ValueError("必须提供本次任务的明确授权说明")
        scope = self.scope_validator.build_scope(target, ports, paths)
        task_id = f"vuln-{uuid4().hex[:12]}"
        code = generate_approval_code()
        now = utc_now()
        approval_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=self.approval_ttl_seconds
        )
        risk = self._risk_summary(task_mode, scope.hostname, scope.ports)
        task = TaskRecord(
            task_id=task_id,
            mode=task_mode,
            scope=scope,
            status=TaskStatus.DRAFT,
            requester_umo=requester_umo,
            requester_id=requester_id,
            created_at=now,
            updated_at=now,
            approval_hash=hash_approval_code(task_id, code),
            approval_expires_at=approval_expiry.isoformat(timespec="seconds"),
            risk_summary=risk,
            metadata={
                "authorization_statement_hash": hashlib.sha256(
                    authorization_statement.strip().encode("utf-8")
                ).hexdigest()
            },
        )
        self.repository.save(task)
        self.audit.record(
            "task_planned",
            task_id=task.task_id,
            mode=task.mode.value,
            requester=requester_id,
            scope=scope.to_dict(),
            authorization_statement=authorization_statement,
        )
        return task, code

    async def approve(
        self, task_id: str, code: str, *, approver_id: str, is_admin: bool
    ) -> TaskRecord:
        if not is_admin:
            raise PermissionError("只有 AstrBot 管理员可以批准任务")
        task = self.repository.get(task_id)
        if task.status != TaskStatus.DRAFT:
            raise ValueError(f"任务当前状态不能批准：{task.status.value}")
        if datetime.now(timezone.utc) > datetime.fromisoformat(task.approval_expires_at):
            raise ValueError("审批口令已过期，请重新创建计划")
        if not verify_approval_code(task_id, code, task.approval_hash):
            raise ValueError("审批口令错误")
        task.approved_by = approver_id
        task.approved_at = utc_now()
        task.approval_hash = ""
        task.status = TaskStatus.QUEUED
        task.current_stage = "queued"
        self.repository.save(task)
        self.audit.record("task_approved", task_id=task_id, approver=approver_id)
        await self._queue.put(task_id)
        self.ensure_runner()
        return task

    async def direct_admin_start(
        self,
        *,
        mode: str,
        target: str,
        ports: list[int],
        paths: list[str],
        requester_umo: str,
        requester_id: str,
        authorization_statement: str,
        is_admin: bool,
    ) -> TaskRecord:
        if not is_admin:
            raise PermissionError("只有管理员的明确授权指令可以直接启动")
        task, code = self.create_plan(
            mode=mode,
            target=target,
            ports=ports,
            paths=paths,
            requester_umo=requester_umo,
            requester_id=requester_id,
            authorization_statement=authorization_statement,
        )
        return await self.approve(task.task_id, code, approver_id=requester_id, is_admin=True)

    async def cancel(self, task_id: str, *, requester_id: str, is_admin: bool) -> TaskRecord:
        task = self.repository.get(task_id)
        if not is_admin and requester_id != task.requester_id:
            raise PermissionError("只能取消自己发起的任务")
        if task.status in TERMINAL_STATUSES:
            return task
        if task.status == TaskStatus.RUNNING and self.worker is not None:
            await self.worker.cancel(task_id)
        task.status = TaskStatus.CANCELLED
        task.current_stage = "cancelled"
        self.repository.save(task)
        self.audit.record("task_cancelled", task_id=task_id, requester=requester_id)
        return task

    def ensure_runner(self) -> None:
        if self._runner_task is None or self._runner_task.done():
            self._runner_task = asyncio.create_task(self._run_queue())

    async def restore_queue(self) -> None:
        for task in reversed(self.repository.list(statuses=[TaskStatus.QUEUED], limit=500)):
            await self._queue.put(task.task_id)
        if not self._queue.empty():
            self.ensure_runner()

    async def _run_queue(self) -> None:
        while not self._stop:
            try:
                task_id = await asyncio.wait_for(self._queue.get(), timeout=1)
            except asyncio.TimeoutError:
                if self._queue.empty():
                    return
                continue
            try:
                await self._execute(task_id)
            finally:
                self._queue.task_done()

    async def _execute(self, task_id: str) -> None:
        task = self.repository.get(task_id)
        if task.status != TaskStatus.QUEUED:
            return
        if self.worker is None:
            task.status = TaskStatus.FAILED
            task.error = "Worker 未配置"
            self.repository.save(task)
            return
        task.status = TaskStatus.RUNNING
        task.current_stage = "initializing"
        self.repository.save(task)
        await self._notify(task)
        self.audit.record("task_started", task_id=task_id)
        spec = {
            "mode": task.mode.value,
            "scope": task.scope.to_dict(),
            "timeout_seconds": self.task_timeout_seconds,
            "high_risk": task.mode in HIGH_RISK_MODES,
        }
        try:
            start = await self.worker.start_task(task_id, spec)
            task.worker_run_id = str(start.get("run_id", ""))
            self.repository.save(task)
            if self.agent_runner is None:
                raise RuntimeError("AstrBot Agent 执行器未配置")
            task.current_stage = "agent"
            task.progress_summary = "AstrBot 当前会话模型正在执行受控测试。"
            self.repository.save(task)
            await self._notify(task)
            result = await asyncio.wait_for(
                self.agent_runner(task), timeout=self.task_timeout_seconds
            )
            current = self.repository.get(task_id)
            if current.status == TaskStatus.CANCELLED:
                return
            reports_dir = Path(self.repository.data_dir) / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            local_report = reports_dir / f"{task_id}.md"
            local_report.write_text(
                str(result.get("report_markdown", "")), encoding="utf-8"
            )
            await self.worker.finish(
                task_id,
                summary=str(result.get("summary", "")),
                findings=list(result.get("findings", [])),
                report_markdown=str(result.get("report_markdown", "")),
            )
            await self._poll_once(task_id, local_report_path=str(local_report))
        except asyncio.TimeoutError:
            try:
                await self.worker.cancel(task_id)
            except Exception:
                pass
            task = self.repository.get(task_id)
            task.status = TaskStatus.FAILED
            task.error = "任务超时"
            task.current_stage = "timeout"
            self.repository.save(task)
            self.audit.record("task_timeout", task_id=task_id)
            await self._notify(task)
        except Exception as exc:
            task = self.repository.get(task_id)
            if task.status == TaskStatus.CANCELLED:
                return
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            task.current_stage = "failed"
            self.repository.save(task)
            self.audit.record("task_failed", task_id=task_id, error=str(exc))
            await self._notify(task)

    async def _poll_once(
        self, task_id: str, *, local_report_path: str = ""
    ) -> None:
        result = await self.worker.status(task_id)  # type: ignore[union-attr]
        task = self.repository.get(task_id)
        task.current_stage = str(result.get("stage", task.current_stage))
        task.progress_summary = str(result.get("summary", ""))
        for finding in result.get("findings", []):
            self.repository.add_finding(task.task_id, dict(finding))
        status = str(result.get("status", ""))
        if status != "completed":
            raise RuntimeError(f"Worker 完成状态异常：{status or 'unknown'}")
        task.status = TaskStatus.COMPLETED
        task.report_path = local_report_path or str(result.get("report_path", ""))
        self.repository.save(task)
        self.audit.record(
            "task_finished",
            task_id=task.task_id,
            status=task.status.value,
            report_path=task.report_path,
        )
        await self._notify(task)

    async def _poll(self, task: TaskRecord) -> None:
        last_stage = task.current_stage
        while True:
            await asyncio.sleep(2)
            result = await self.worker.status(task.task_id)  # type: ignore[union-attr]
            task = self.repository.get(task.task_id)
            task.current_stage = str(result.get("stage", task.current_stage))
            task.progress_summary = str(result.get("summary", ""))
            for finding in result.get("findings", []):
                self.repository.add_finding(task.task_id, dict(finding))
            status = str(result.get("status", "running"))
            if status == "completed":
                task.status = TaskStatus.COMPLETED
                task.report_path = str(result.get("report_path", ""))
            elif status == "failed":
                task.status = TaskStatus.FAILED
                task.error = str(result.get("error", "Worker 任务失败"))
            elif status == "cancelled":
                task.status = TaskStatus.CANCELLED
            self.repository.save(task)
            if task.current_stage != last_stage or task.status in TERMINAL_STATUSES:
                await self._notify(task)
                last_stage = task.current_stage
            if task.status in TERMINAL_STATUSES:
                self.audit.record(
                    "task_finished",
                    task_id=task.task_id,
                    status=task.status.value,
                    report_path=task.report_path,
                    error=task.error,
                )
                return

    async def _notify(self, task: TaskRecord) -> None:
        if self.on_stage is not None:
            await self.on_stage(task)

    @staticmethod
    def _risk_summary(mode: TaskMode, hostname: str, ports: list[int]) -> str:
        level = "高" if mode in HIGH_RISK_MODES else "中"
        return (
            f"风险等级：{level}；模式：{mode.value}；"
            f"仅允许主机 {hostname} 和端口 {','.join(str(port) for port in ports)}。"
        )
