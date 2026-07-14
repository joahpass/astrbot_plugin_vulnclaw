from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from astrbot_plugin_vulnclaw.agent.adapter import AgentUnavailableError, AstrBotAgentRunner
from astrbot_plugin_vulnclaw.core.audit import AuditLogger
from astrbot_plugin_vulnclaw.core.models import (
    TaskMode,
    TaskRecord,
    TaskScope,
    TaskStatus,
    utc_now,
)


def task() -> TaskRecord:
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
        status=TaskStatus.RUNNING,
        requester_umo="qq:test",
        requester_id="42",
        created_at=now,
        updated_at=now,
    )


def test_agent_result_parser_accepts_json_and_normalizes_findings() -> None:
    parsed = AstrBotAgentRunner._parse_result(
        task(),
        """```json
        {"summary":"完成","findings":[{"title":"X","severity":"HIGH",
        "evidence":"proof","remediation":"fix"}],"report_markdown":"# R"}
        ```""",
    )
    assert parsed["summary"] == "完成"
    assert parsed["findings"][0]["severity"] == "high"
    assert parsed["report_markdown"] == "# R"


def test_agent_result_parser_falls_back_to_markdown() -> None:
    parsed = AstrBotAgentRunner._parse_result(task(), "普通文本结论")
    assert parsed["findings"] == []
    assert "普通文本结论" in parsed["report_markdown"]


def test_agent_result_redacts_credentials() -> None:
    parsed = AstrBotAgentRunner._parse_result(
        task(),
        '{"summary":"token=abc123","findings":[],"report_markdown":"Authorization: Bearer xyz"}',
    )
    assert "abc123" not in parsed["summary"]
    assert "xyz" not in parsed["report_markdown"]


def test_agent_result_rejects_finding_without_successful_evidence() -> None:
    parsed = AstrBotAgentRunner._parse_result(
        task(),
        '{"summary":"完成","findings":[{"title":"虚构漏洞","severity":"high",'
        '"evidence":"模型声称存在","evidence_ids":["evidence-999"],'
        '"remediation":"fix"}],"report_markdown":"# R"}',
        evidence=[
            {
                "evidence_id": "evidence-001",
                "tool": "fetch",
                "success": True,
                "result": {"status": 200},
            }
        ],
    )
    assert parsed["findings"] == []


def test_agent_result_accepts_finding_with_successful_evidence() -> None:
    parsed = AstrBotAgentRunner._parse_result(
        task(),
        '{"summary":"完成","findings":[{"title":"已验证","severity":"info",'
        '"evidence":"HTTP 200","evidence_ids":["evidence-001"],'
        '"remediation":"none"}],"report_markdown":"# R"}',
        evidence=[
            {
                "evidence_id": "evidence-001",
                "tool": "fetch",
                "success": True,
                "result": {"status": 200},
            }
        ],
    )
    assert parsed["findings"][0]["evidence_ids"] == ["evidence-001"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [TaskMode.RECON, TaskMode.SCAN, TaskMode.EXPLOIT, TaskMode.REPORT])
async def test_agent_uses_current_provider_and_fixed_tools(
    tmp_path, monkeypatch, mode
) -> None:
    class FakeFunctionTool:
        def __init__(self, name, description, parameters):
            self.name = name
            self.description = description
            self.parameters = parameters

    class FakeToolSet:
        def __init__(self, tools):
            self.tools = tools

    tool_module = ModuleType("astrbot.core.agent.tool")
    tool_module.FunctionTool = FakeFunctionTool
    tool_module.ToolSet = FakeToolSet
    monkeypatch.setitem(sys.modules, "astrbot", ModuleType("astrbot"))
    monkeypatch.setitem(sys.modules, "astrbot.core", ModuleType("astrbot.core"))
    monkeypatch.setitem(sys.modules, "astrbot.core.agent", ModuleType("astrbot.core.agent"))
    monkeypatch.setitem(sys.modules, "astrbot.core.agent.tool", tool_module)

    class FakeWorker:
        async def call_tool(self, task_id, name, arguments):
            return {"success": True, "result": {"tool": name}}

    class FakeContext:
        async def get_current_chat_provider_id(self, umo):
            assert umo == "qq:test"
            return "provider-1"

        async def tool_loop_agent(self, **kwargs):
            assert kwargs["chat_provider_id"] == "provider-1"
            names = {tool.name for tool in kwargs["tools"].tools}
            assert "run_shell" not in names
            if mode == TaskMode.REPORT:
                assert "fetch" not in names
            else:
                result = await kwargs["tools"].tools[0].call(None, ports=[443])
                assert "success" in result
            return SimpleNamespace(
                completion_text='{"summary":"ok","findings":[],"report_markdown":"# ok"}'
            )

    current = task()
    current.mode = mode
    runner = AstrBotAgentRunner(
        context=FakeContext(),
        worker=FakeWorker(),
        audit=AuditLogger(tmp_path),
        event_resolver=lambda _umo: object(),
    )
    result = await runner(current)
    assert result["summary"] == "ok"


@pytest.mark.asyncio
async def test_agent_rejects_narrative_only_scan(tmp_path, monkeypatch) -> None:
    class FakeFunctionTool:
        def __init__(self, name, description, parameters):
            self.name = name

    class FakeToolSet:
        def __init__(self, tools):
            self.tools = tools

    tool_module = ModuleType("astrbot.core.agent.tool")
    tool_module.FunctionTool = FakeFunctionTool
    tool_module.ToolSet = FakeToolSet
    monkeypatch.setitem(sys.modules, "astrbot", ModuleType("astrbot"))
    monkeypatch.setitem(sys.modules, "astrbot.core", ModuleType("astrbot.core"))
    monkeypatch.setitem(sys.modules, "astrbot.core.agent", ModuleType("astrbot.core.agent"))
    monkeypatch.setitem(sys.modules, "astrbot.core.agent.tool", tool_module)

    class FakeWorker:
        async def call_tool(self, task_id, name, arguments):
            raise AssertionError("模型不应绕过工具")

    class FakeContext:
        async def get_current_chat_provider_id(self, umo):
            return "provider-1"

        async def tool_loop_agent(self, **kwargs):
            return SimpleNamespace(
                completion_text='{"summary":"扫描完成，无漏洞","findings":[],"report_markdown":"# 完成"}'
            )

    runner = AstrBotAgentRunner(
        context=FakeContext(),
        worker=FakeWorker(),
        audit=AuditLogger(tmp_path),
        event_resolver=lambda _umo: object(),
    )
    with pytest.raises(AgentUnavailableError, match="没有可验证的工具执行证据"):
        await runner(task())


@pytest.mark.asyncio
async def test_agent_rejects_failed_worker_tool(tmp_path, monkeypatch) -> None:
    class FakeFunctionTool:
        def __init__(self, name, description, parameters):
            self.name = name

    class FakeToolSet:
        def __init__(self, tools):
            self.tools = tools

    tool_module = ModuleType("astrbot.core.agent.tool")
    tool_module.FunctionTool = FakeFunctionTool
    tool_module.ToolSet = FakeToolSet
    monkeypatch.setitem(sys.modules, "astrbot", ModuleType("astrbot"))
    monkeypatch.setitem(sys.modules, "astrbot.core", ModuleType("astrbot.core"))
    monkeypatch.setitem(sys.modules, "astrbot.core.agent", ModuleType("astrbot.core.agent"))
    monkeypatch.setitem(sys.modules, "astrbot.core.agent.tool", tool_module)

    class FakeWorker:
        async def call_tool(self, task_id, name, arguments):
            return {"ok": True, "success": False, "error": "nmap 不可用"}

    class FakeContext:
        async def get_current_chat_provider_id(self, umo):
            return "provider-1"

        async def tool_loop_agent(self, **kwargs):
            output = await kwargs["tools"].tools[0].call(None, ports=[443])
            assert '"success": false' in output
            return SimpleNamespace(
                completion_text='{"summary":"仍然声称完成","findings":[],"report_markdown":"# 完成"}'
            )

    runner = AstrBotAgentRunner(
        context=FakeContext(),
        worker=FakeWorker(),
        audit=AuditLogger(tmp_path),
        event_resolver=lambda _umo: object(),
    )
    with pytest.raises(AgentUnavailableError, match="nmap 不可用"):
        await runner(task())

