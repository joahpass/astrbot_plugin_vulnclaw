from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from .agent import AstrBotAgentRunner
from .core import AuditLogger, HmacSigner, ScopeValidator, TaskRepository, TaskStatus
from .core.task_service import TaskService
from .core.worker_client import WorkerClient

try:
    from astrbot.api import AstrBotConfig, logger
    from astrbot.api.event import AstrMessageEvent, filter
    from astrbot.api.star import Context, Star, register
    from astrbot.core.utils.astrbot_path import get_astrbot_data_path
except ImportError:  # pragma: no cover - local unit tests
    import logging

    logger = logging.getLogger(__name__)
    AstrBotConfig = dict

    class AstrMessageEvent:
        unified_msg_origin = "test:private:test"

        def plain_result(self, text: str) -> str:
            return text

    class Context:
        pass

    class Star:
        def __init__(self, context: Context):
            self.context = context

    def _identity(*_args: Any, **_kwargs: Any) -> Callable[[Any], Any]:
        def decorator(obj: Any) -> Any:
            return obj

        return decorator

    def _group(*_args: Any, **_kwargs: Any) -> Callable[[Any], Any]:
        def decorator(obj: Any) -> Any:
            obj.command = _identity
            obj.group = _group
            return obj

        return decorator

    filter = SimpleNamespace(
        command_group=_group,
        command=_identity,
        llm_tool=_identity,
        permission_type=_identity,
        PermissionType=SimpleNamespace(ADMIN="ADMIN"),
    )

    def register(*_args: Any, **_kwargs: Any) -> Callable[[Any], Any]:
        return _identity()

    def get_astrbot_data_path() -> str:
        return str(Path.cwd() / "data")


def admin_only(func: Callable[..., Any]) -> Callable[..., Any]:
    decorator = getattr(filter, "permission_type", None)
    permission_type = getattr(filter, "PermissionType", None)
    admin = getattr(permission_type, "ADMIN", None)
    return decorator(admin)(func) if callable(decorator) and admin is not None else func


def config_value(config: Any, key: str, default: Any) -> Any:
    return config.get(key, default) if hasattr(config, "get") else default


@register(
    "astrbot_plugin_vulnclaw",
    "Codex",
    "隔离式、需授权的 VulnClaw 漏洞测试任务插件",
    "0.1.0",
)
class VulnClawPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig | None = None):
        super().__init__(context)
        self.config = config or {}
        self.data_root = (
            Path(get_astrbot_data_path()) / "plugin_data" / "astrbot_plugin_vulnclaw"
        )
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.repository = TaskRepository(self.data_root)
        self.audit = AuditLogger(self.data_root)
        self.scope_validator = ScopeValidator()
        self._event_by_umo: dict[str, AstrMessageEvent] = {}

        secret = str(config_value(self.config, "worker_secret", "")).strip()
        self.worker: WorkerClient | None = None
        agent_runner = None
        if secret:
            self.worker = WorkerClient(
                str(
                    config_value(
                        self.config, "worker_url", "http://127.0.0.1:8765"
                    )
                ),
                HmacSigner(secret),
            )
            agent_runner = AstrBotAgentRunner(
                context=context,
                worker=self.worker,
                audit=self.audit,
                event_resolver=self._event_by_umo.get,
                max_steps=int(config_value(self.config, "agent_max_steps", 24)),
                tool_timeout_seconds=int(
                    config_value(self.config, "tool_timeout_seconds", 120)
                ),
            )

        self.task_service = TaskService(
            repository=self.repository,
            audit=self.audit,
            scope_validator=self.scope_validator,
            worker=self.worker,
            enable_high_risk_modes=bool(
                config_value(self.config, "enable_high_risk_modes", False)
            ),
            approval_ttl_seconds=int(
                config_value(self.config, "approval_ttl_seconds", 600)
            ),
            task_timeout_seconds=int(
                config_value(self.config, "default_task_timeout_seconds", 1800)
            ),
            on_stage=self._on_stage,
            agent_runner=agent_runner,
        )
        try:
            asyncio.get_running_loop().create_task(self.task_service.restore_queue())
        except RuntimeError:
            pass

    @filter.command_group("vuln")
    def vuln(self):
        """VulnClaw 授权漏洞测试任务。"""

    @vuln.command("plan")
    async def plan(
        self,
        event: AstrMessageEvent,
        mode: str,
        target: str,
        ports: str = "",
        paths: str = "",
        authorization: str = "",
    ):
        """创建待审批任务。"""
        self._remember_event(event)
        yield self._plain(
            event, self._plan_text(event, mode, target, ports, paths, authorization)
        )

    @vuln.command("approve")
    @admin_only
    async def approve(self, event: AstrMessageEvent, task_id: str, code: str):
        """管理员使用一次性口令批准任务。"""
        self._remember_event(event)
        task = await self.task_service.approve(
            task_id, code, approver_id=self._sender_id(event), is_admin=True
        )
        yield self._plain(event, f"任务已批准并入队：{task.task_id}")

    @vuln.command("status")
    async def status(self, event: AstrMessageEvent, task_id: str = ""):
        """查看任务状态。"""
        self._remember_event(event)
        yield self._plain(event, self._status_text(task_id))

    @vuln.command("queue")
    async def queue(self, event: AstrMessageEvent):
        """查看全局任务队列。"""
        yield self._plain(event, self._queue_text())

    @vuln.command("cancel")
    async def cancel(self, event: AstrMessageEvent, task_id: str):
        """取消任务。"""
        task = await self.task_service.cancel(
            task_id,
            requester_id=self._sender_id(event),
            is_admin=self._is_admin(event),
        )
        yield self._plain(event, f"任务状态：{task.status.value}")

    @vuln.command("logs")
    async def logs(self, event: AstrMessageEvent, task_id: str = ""):
        """查看最近审计记录。"""
        entries = self.audit.tail(task_id, 20)
        if not entries:
            yield self._plain(event, "暂无审计记录。")
            return
        lines = ["最近审计记录："]
        lines.extend(
            f"- {item['time']} {item['event']} task={item['task_id'] or '-'}"
            for item in entries
        )
        yield self._plain(event, "\n".join(lines))

    @vuln.command("findings")
    async def findings(self, event: AstrMessageEvent, task_id: str):
        """查看结构化漏洞发现。"""
        rows = self.repository.findings(task_id)
        if not rows:
            yield self._plain(event, "暂无漏洞发现。")
            return
        lines = [f"任务 {task_id} 的发现："]
        lines.extend(
            f"- [{item.get('severity', 'info')}] {item.get('title', '未命名发现')}"
            for item in rows
        )
        yield self._plain(event, "\n".join(lines))

    @vuln.command("report")
    async def report(self, event: AstrMessageEvent, task_id: str):
        """查看最终报告。"""
        task = self.repository.get(task_id)
        report_text = ""
        if task.report_path:
            report_path = Path(task.report_path)
            if report_path.is_file() and report_path.resolve().is_relative_to(
                self.data_root.resolve()
            ):
                report_text = report_path.read_text(encoding="utf-8")[:20000]
        yield self._plain(
            event,
            f"任务：{task.task_id}\n状态：{task.status.value}\n"
            f"报告：{task.report_path or '尚未生成'}"
            + (f"\n\n{report_text}" if report_text else ""),
        )

    @vuln.command("doctor")
    async def doctor(self, event: AstrMessageEvent):
        """检查插件和 Supervisor。"""
        yield self._plain(event, await self._doctor_text())

    @vuln.group("scope")
    def scope(self):
        """任务授权边界。"""

    @scope.command("show")
    async def scope_show(self, event: AstrMessageEvent, task_id: str):
        """查看任务最终授权边界。"""
        task = self.repository.get(task_id)
        scope = task.scope
        yield self._plain(
            event,
            "\n".join(
                [
                    f"任务：{task.task_id}",
                    f"目标：{scope.target}",
                    f"解析 IP：{', '.join(scope.resolved_ips)}",
                    f"端口：{', '.join(str(item) for item in scope.ports)}",
                    f"路径：{', '.join(scope.paths)}",
                    f"有效期：{scope.expires_at}",
                ]
            ),
        )

    @vuln.group("worker")
    def worker_group(self):
        """Supervisor 管理。"""

    @worker_group.command("status")
    async def worker_status(self, event: AstrMessageEvent):
        """查看 Supervisor 状态。"""
        yield self._plain(event, await self._doctor_text())

    @filter.llm_tool(name="vulnclaw_plan")
    async def vulnclaw_plan_tool(
        self,
        event: AstrMessageEvent,
        mode: str,
        target: str,
        ports: str = "",
        paths: str = "",
        authorization: str = "",
    ):
        """创建待审批漏洞测试计划，不会启动任务。

        Args:
            mode(string): recon、scan、run、exploit、persistent、report 或 post-exploitation。
            target(string): 明确授权的 http/https 目标。
            ports(string): 逗号分隔的授权端口。
            paths(string): 逗号分隔的授权路径。
            authorization(string): 用户提供的授权说明。
        """
        self._remember_event(event)
        return self._plan_text(event, mode, target, ports, paths, authorization)

    @filter.llm_tool(name="vulnclaw_authorize_and_start")
    async def vulnclaw_authorize_and_start_tool(
        self,
        event: AstrMessageEvent,
        mode: str,
        target: str,
        authorization: str,
        ports: str = "",
        paths: str = "",
    ):
        """管理员明确授权后创建并启动任务。

        Args:
            mode(string): 测试模式。
            target(string): 明确授权的 http/https 目标。
            authorization(string): 必须明确包含“授权并启动”的声明。
            ports(string): 逗号分隔的授权端口。
            paths(string): 逗号分隔的授权路径。
        """
        self._remember_event(event)
        if not self._is_admin(event):
            return "拒绝：只有 AstrBot 管理员会话可以直接授权并启动。"
        lowered = authorization.lower()
        if not any(
            marker in lowered
            for marker in ("授权并启动", "授权启动", "authorized start")
        ):
            return "拒绝：授权说明必须明确包含“授权并启动”。"
        task = await self.task_service.direct_admin_start(
            mode=mode,
            target=target,
            ports=self._parse_ports(ports),
            paths=self._split_csv(paths),
            requester_umo=self._umo(event),
            requester_id=self._sender_id(event),
            authorization_statement=authorization,
            is_admin=True,
        )
        return f"任务已由管理员直接授权并入队：{task.task_id}"

    @filter.llm_tool(name="vulnclaw_status")
    async def vulnclaw_status_tool(
        self, event: AstrMessageEvent, task_id: str = ""
    ):
        """查看漏洞测试任务状态。

        Args:
            task_id(string): 任务 ID；为空时查看最近任务。
        """
        return self._status_text(task_id)

    def _plan_text(
        self,
        event: AstrMessageEvent,
        mode: str,
        target: str,
        ports: str,
        paths: str,
        authorization: str,
    ) -> str:
        task, code = self.task_service.create_plan(
            mode=mode,
            target=target,
            ports=self._parse_ports(ports),
            paths=self._split_csv(paths),
            requester_umo=self._umo(event),
            requester_id=self._sender_id(event),
            authorization_statement=authorization,
        )
        return (
            f"任务计划已创建：{task.task_id}\n"
            f"模式：{task.mode.value}\n"
            f"目标：{task.scope.target}\n"
            f"解析 IP：{', '.join(task.scope.resolved_ips)}\n"
            f"端口：{', '.join(str(item) for item in task.scope.ports)}\n"
            f"{task.risk_summary}\n"
            f"审批口令：{code}\n"
            f"管理员执行：/vuln approve {task.task_id} {code}"
        )

    def _status_text(self, task_id: str = "") -> str:
        if task_id.strip():
            task = self.repository.get(task_id.strip())
        else:
            tasks = self.repository.list(limit=1)
            if not tasks:
                return "暂无任务。"
            task = tasks[0]
        return (
            f"任务：{task.task_id}\n状态：{task.status.value}\n"
            f"模式：{task.mode.value}\n阶段：{task.current_stage}\n"
            f"进度：{task.progress_summary or '-'}\n错误：{task.error or '-'}"
        )

    def _queue_text(self) -> str:
        tasks = self.repository.list(
            statuses=[TaskStatus.QUEUED, TaskStatus.RUNNING], limit=50
        )
        if not tasks:
            return "队列为空。"
        return "\n".join(
            ["当前队列："]
            + [
                f"- {task.task_id} [{task.status.value}] "
                f"{task.mode.value} {task.scope.hostname}"
                for task in reversed(tasks)
            ]
        )

    async def _doctor_text(self) -> str:
        lines = [
            "VulnClaw 插件诊断：",
            f"- 数据库：正常 ({self.repository.path})",
            f"- Worker 配置：{'已配置' if self.worker else '未配置'}",
            f"- 高风险模式："
            f"{'开启' if self.task_service.enable_high_risk_modes else '关闭'}",
        ]
        if self.worker is not None:
            try:
                result = await self.worker.health()
                lines.append(
                    f"- Supervisor：正常 docker={result.get('docker')} "
                    f"vulnclaw={result.get('vulnclaw_version')}"
                )
            except Exception as exc:
                lines.append(f"- Supervisor：异常 {exc}")
        return "\n".join(lines)

    async def _on_stage(self, task: Any) -> None:
        if not bool(config_value(self.config, "notify_stage_updates", True)):
            return
        event = self._event_by_umo.get(task.requester_umo)
        send = getattr(event, "send", None) if event is not None else None
        if not callable(send):
            return
        text = (
            f"VulnClaw 任务更新：{task.task_id}\n"
            f"状态：{task.status.value}\n阶段：{task.current_stage}\n"
            f"{task.progress_summary or task.error or ''}"
        )
        try:
            await send(self._plain(event, text))
        except Exception:
            logger.warning("发送 VulnClaw 阶段通知失败", exc_info=True)

    def _remember_event(self, event: AstrMessageEvent) -> None:
        self._event_by_umo[self._umo(event)] = event

    @staticmethod
    def _plain(event: AstrMessageEvent, text: str):
        result = getattr(event, "plain_result", None)
        return result(text) if callable(result) else text

    @staticmethod
    def _umo(event: AstrMessageEvent) -> str:
        return str(getattr(event, "unified_msg_origin", ""))

    @staticmethod
    def _sender_id(event: AstrMessageEvent) -> str:
        method = getattr(event, "get_sender_id", None)
        if callable(method):
            try:
                return str(method())
            except Exception:
                pass
        return str(getattr(event, "sender_id", "unknown"))

    @staticmethod
    def _is_admin(event: AstrMessageEvent) -> bool:
        method = getattr(event, "is_admin", None)
        if callable(method):
            try:
                return bool(method())
            except Exception:
                pass
        return str(getattr(event, "role", "")).lower() in {"admin", "owner"}

    @staticmethod
    def _split_csv(value: str) -> list[str]:
        return [
            item.strip()
            for item in str(value or "").replace("，", ",").split(",")
            if item.strip()
        ]

    @classmethod
    def _parse_ports(cls, value: str) -> list[int]:
        ports: list[int] = []
        for item in cls._split_csv(value):
            if not item.isdigit():
                raise ValueError(f"端口不是整数：{item}")
            ports.append(int(item))
        return ports
