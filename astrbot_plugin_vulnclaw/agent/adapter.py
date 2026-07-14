from __future__ import annotations

import json
import re
from typing import Any, Callable

from ..core.audit import AuditLogger
from ..core.models import TaskRecord
from ..core.worker_client import WorkerClient


class AgentUnavailableError(RuntimeError):
    pass


TOOL_SCHEMAS: dict[str, tuple[str, dict[str, Any]]] = {
    "nmap_scan": (
        "对授权目标执行固定参数的 TCP 服务探测。不能传入原始 nmap 参数。",
        {
            "type": "object",
            "properties": {
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "仅可填写任务 scope 内端口",
                }
            },
            "required": ["ports"],
            "additionalProperties": False,
        },
    ),
    "fetch": (
        "访问任务 scope 内的 HTTP/HTTPS 路径，重定向会重新校验。",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "HEAD"]},
                "headers": {"type": "object"},
                "body": {"type": "string", "maxLength": 65536},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    ),
    "python_execute": (
        "执行受限的纯计算 Python 表达式。禁止导入、文件、进程和任意网络。",
        {
            "type": "object",
            "properties": {"code": {"type": "string", "maxLength": 4000}},
            "required": ["code"],
            "additionalProperties": False,
        },
    ),
    "crypto_decode": (
        "执行固定的编码或摘要辅助操作。",
        {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "base64_decode",
                        "url_decode",
                        "hex_decode",
                        "sha256_hash",
                    ],
                },
                "input": {"type": "string", "maxLength": 100000},
            },
            "required": ["operation", "input"],
            "additionalProperties": False,
        },
    ),
    "load_skill_reference": (
        "读取内置 VulnClaw 技能参考资料，不能读取任意文件。",
        {
            "type": "object",
            "properties": {
                "skill_name": {"type": "string", "maxLength": 120},
                "reference_name": {"type": "string", "maxLength": 180},
            },
            "required": ["skill_name", "reference_name"],
            "additionalProperties": False,
        },
    ),
}


class AstrBotAgentRunner:
    def __init__(
        self,
        *,
        context: Any,
        worker: WorkerClient,
        audit: AuditLogger,
        event_resolver: Callable[[str], Any | None],
        max_steps: int = 24,
        tool_timeout_seconds: int = 120,
    ) -> None:
        self.context = context
        self.worker = worker
        self.audit = audit
        self.event_resolver = event_resolver
        self.max_steps = max(1, min(max_steps, 50))
        self.tool_timeout_seconds = max(5, min(tool_timeout_seconds, 300))

    async def __call__(self, task: TaskRecord) -> dict[str, Any]:
        event = self.event_resolver(task.requester_umo)
        if event is None:
            raise AgentUnavailableError("原始会话事件不可用，不能复用当前会话模型")
        if not callable(getattr(self.context, "tool_loop_agent", None)):
            raise AgentUnavailableError(
                "当前 AstrBot 不支持 tool_loop_agent，请升级到 4.9.2 或更高版本"
            )
        provider_getter = getattr(self.context, "get_current_chat_provider_id", None)
        if not callable(provider_getter):
            raise AgentUnavailableError("无法取得当前 QQ 会话使用的模型")

        try:
            from astrbot.core.agent.tool import FunctionTool, ToolSet
        except ImportError as exc:
            raise AgentUnavailableError("AstrBot Agent Tool API 不可用") from exc

        runner = self
        evidence: list[dict[str, Any]] = []

        def record_evidence(
            tool: str,
            arguments: dict[str, Any],
            *,
            success: bool,
            result: Any = None,
            error: str = "",
        ) -> dict[str, Any]:
            item = {
                "evidence_id": f"evidence-{len(evidence) + 1:03d}",
                "tool": tool,
                "arguments": dict(arguments),
                "success": bool(success),
                "result": result,
                "error": error,
            }
            evidence.append(item)
            return item

        class RemoteTool(FunctionTool):
            def __init__(self, name: str, description: str, parameters: dict[str, Any]):
                super().__init__(
                    name=name,
                    description=description,
                    parameters=parameters,
                )

            async def call(self, context: Any, **kwargs: Any) -> str:
                if (
                    self.name == "fetch"
                    and task.mode.value in {"recon", "scan"}
                    and str(kwargs.get("method", "GET")).upper()
                    not in {"GET", "HEAD", "OPTIONS"}
                ):
                    item = record_evidence(
                        self.name,
                        kwargs,
                        success=False,
                        error="当前低风险模式禁止产生状态变化的 HTTP 方法",
                    )
                    return json.dumps(
                        {
                            "success": False,
                            "evidence_id": item["evidence_id"],
                            "error": item["error"],
                        },
                        ensure_ascii=False,
                    )
                runner.audit.record(
                    "model_tool_call",
                    task_id=task.task_id,
                    tool=self.name,
                    arguments=kwargs,
                )
                try:
                    result = await runner.worker.call_tool(task.task_id, self.name, kwargs)
                except Exception as exc:
                    item = record_evidence(
                        self.name, kwargs, success=False, error=str(exc)
                    )
                    runner.audit.record(
                        "model_tool_result",
                        task_id=task.task_id,
                        tool=self.name,
                        evidence_id=item["evidence_id"],
                        ok=False,
                        result_summary=str(exc)[:2000],
                    )
                    return json.dumps(
                        {
                            "success": False,
                            "evidence_id": item["evidence_id"],
                            "error": str(exc),
                        },
                        ensure_ascii=False,
                    )

                success = bool(result.get("ok", True)) and bool(
                    result.get("success", result.get("ok", True))
                )
                error = "" if success else str(
                    result.get("error") or result.get("detail") or "工具执行失败"
                )
                item = record_evidence(
                    self.name,
                    kwargs,
                    success=success,
                    result=result.get("result") if success else None,
                    error=error,
                )
                runner.audit.record(
                    "model_tool_result",
                    task_id=task.task_id,
                    tool=self.name,
                    evidence_id=item["evidence_id"],
                    ok=success,
                    result_summary=str(result)[:2000],
                )
                payload: dict[str, Any] = {
                    "success": success,
                    "evidence_id": item["evidence_id"],
                }
                if success:
                    payload["result"] = result.get("result")
                else:
                    payload["error"] = error
                return json.dumps(payload, ensure_ascii=False)

        allowed_names = set(TOOL_SCHEMAS)
        if task.mode.value == "report":
            allowed_names = {
                "load_skill_reference",
                "crypto_decode",
                "python_execute",
            }
        schemas = []
        for name, (description, parameters) in TOOL_SCHEMAS.items():
            if name not in allowed_names:
                continue
            parameters = json.loads(json.dumps(parameters))
            if name == "fetch" and task.mode.value in {
                "run",
                "exploit",
                "persistent",
                "post-exploitation",
            }:
                parameters["properties"]["method"]["enum"] = [
                    "GET",
                    "HEAD",
                    "OPTIONS",
                    "POST",
                ]
            schemas.append(RemoteTool(name, description, parameters))
        tools = ToolSet(schemas)
        provider_id = await provider_getter(task.requester_umo)
        if not provider_id:
            raise AgentUnavailableError("当前会话未配置可用聊天模型")

        self.audit.record(
            "agent_started",
            task_id=task.task_id,
            provider_id=str(provider_id),
            max_steps=self.max_steps,
        )
        response = await self.context.tool_loop_agent(
            event=event,
            chat_provider_id=provider_id,
            prompt=self._prompt(task),
            system_prompt=self._system_prompt(task),
            tools=tools,
            max_steps=self.max_steps,
            tool_call_timeout=self.tool_timeout_seconds,
        )
        text = str(getattr(response, "completion_text", "") or "")
        if not text:
            raise AgentUnavailableError("模型未返回最终测试结果")
        successful_actions = [
            item
            for item in evidence
            if item["success"] and item["tool"] in {"nmap_scan", "fetch"}
        ]
        if task.mode.value != "report" and not successful_actions:
            failed = [item for item in evidence if not item["success"]]
            detail = failed[-1]["error"][:500] if failed else "模型没有调用网络执行工具"
            raise AgentUnavailableError(f"没有可验证的工具执行证据：{detail}")

        result = self._parse_result(task, text, evidence=evidence)
        result["report_markdown"] = self._append_evidence(
            result["report_markdown"], evidence
        )
        self.audit.record(
            "agent_finished",
            task_id=task.task_id,
            finding_count=len(result["findings"]),
            successful_tool_calls=sum(1 for item in evidence if item["success"]),
            total_tool_calls=len(evidence),
        )
        return result

    @staticmethod
    def _system_prompt(task: TaskRecord) -> str:
        return (
            "你是授权漏洞测试代理。只能使用当前提供的固定工具，不能要求 shell、"
            "Docker、任意 Python、额外网络或扩大 scope。不得从当前模式升级到更高风险模式。"
            "遇到拒绝或不确定边界时停止该动作。所有结论必须有工具结果证据。"
            f"当前模式为 {task.mode.value}。最终仅输出 JSON 对象，字段为 "
            "summary、findings、report_markdown。findings 是对象数组，每项包含 "
            "title、severity、evidence、evidence_ids、remediation。每个发现必须在 "
            "evidence_ids 中引用成功工具结果返回的 evidence_id；没有证据就不得报告发现。"
        )

    @staticmethod
    def _prompt(task: TaskRecord) -> str:
        scope = task.scope
        return (
            f"任务 ID：{task.task_id}\n"
            f"授权目标：{scope.target}\n"
            f"固定解析 IP：{', '.join(scope.resolved_ips)}\n"
            f"授权端口：{', '.join(str(port) for port in scope.ports)}\n"
            f"授权路径：{', '.join(scope.paths)}\n"
            f"有效期：{scope.expires_at}\n"
            "按当前模式完成最小必要测试，避免破坏性验证，最后生成中文 Markdown 报告。"
        )

    @classmethod
    def _parse_result(
        cls,
        task: TaskRecord,
        text: str,
        *,
        evidence: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        candidate = text.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, re.S)
        if fenced:
            candidate = fenced.group(1)
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            clean_text = cls._redact_text(text)
            return {
                "summary": clean_text[:1000],
                "findings": [],
                "report_markdown": cls._fallback_report(task, clean_text),
            }
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        normalized = []
        successful_ids = {
            str(item.get("evidence_id"))
            for item in (evidence or [])
            if item.get("success")
        }
        for item in findings[:500]:
            if not isinstance(item, dict):
                continue
            evidence_ids = item.get("evidence_ids", [])
            if isinstance(evidence_ids, str):
                evidence_ids = [evidence_ids]
            if not isinstance(evidence_ids, list):
                evidence_ids = []
            referenced_ids = [str(value) for value in evidence_ids]
            if evidence is not None and not successful_ids.intersection(referenced_ids):
                continue
            normalized.append(
                {
                    "title": cls._redact_text(
                        str(item.get("title", "未命名发现"))
                    )[:300],
                    "severity": str(item.get("severity", "info")).lower()[:20],
                    "evidence": cls._redact_text(
                        str(item.get("evidence", ""))
                    )[:8000],
                    "evidence_ids": [
                        value for value in referenced_ids if value in successful_ids
                    ],
                    "remediation": cls._redact_text(
                        str(item.get("remediation", ""))
                    )[:8000],
                }
            )
        report = cls._redact_text(
            str(data.get("report_markdown", "")).strip()
        )
        summary = cls._redact_text(str(data.get("summary", "")).strip())[:4000]
        if not report:
            report = cls._fallback_report(task, summary)
        return {"summary": summary, "findings": normalized, "report_markdown": report}

    @classmethod
    def _append_evidence(
        cls, report_markdown: str, evidence: list[dict[str, Any]]
    ) -> str:
        lines = [report_markdown.rstrip(), "", "## 执行证据", ""]
        if not evidence:
            lines.append("- 无工具执行证据。")
            return "\n".join(lines).rstrip() + "\n"
        for item in evidence:
            status = "成功" if item.get("success") else "失败"
            detail = item.get("result") if item.get("success") else item.get("error")
            clean_detail = cls._redact_text(str(detail or ""))[:2000]
            lines.append(
                f"- `{item.get('evidence_id', '')}` `{item.get('tool', '')}`：{status}"
            )
            if clean_detail:
                lines.append(f"  - 结果摘要：`{clean_detail}`")
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _redact_text(text: str) -> str:
        patterns = [
            r"(?i)\b(api[_-]?key|token|password|secret|authorization)\b"
            r"(\s*[:=]\s*)([^\s,;]+)",
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
        ]
        value = re.sub(patterns[1], "Bearer ***REDACTED***", text)
        value = re.sub(
            patterns[0],
            lambda match: f"{match.group(1)}{match.group(2)}***REDACTED***",
            value,
        )
        return value

    @staticmethod
    def _fallback_report(task: TaskRecord, text: str) -> str:
        return (
            f"# VulnClaw 授权测试报告\n\n"
            f"- 任务：`{task.task_id}`\n"
            f"- 模式：`{task.mode.value}`\n"
            f"- 目标：`{task.scope.target}`\n"
            f"- 端口：`{', '.join(str(port) for port in task.scope.ports)}`\n\n"
            f"## 模型结论\n\n{text}\n"
        )

