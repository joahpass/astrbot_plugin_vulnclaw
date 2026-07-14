from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "astrbot_plugin_vulnclaw" / "vendor"))

from vulnclaw.agent.tool_call_manager import handle_tool_calls_with_results
from vulnclaw.web.services.task_service import _require_execution_evidence


def test_web_task_rejects_narrative_without_tool_evidence() -> None:
    agent = SimpleNamespace(runtime=SimpleNamespace(tool_calls=[]))
    request = SimpleNamespace(command="scan")

    with pytest.raises(RuntimeError, match="没有可验证的网络工具执行证据"):
        _require_execution_evidence(agent, request)


def test_web_task_accepts_successful_network_evidence() -> None:
    agent = SimpleNamespace(
        runtime=SimpleNamespace(
            tool_calls=[
                {
                    "evidence_id": "web-evidence-001",
                    "tool": "fetch",
                    "success": True,
                    "output": "HTTP 200",
                }
            ]
        )
    )
    request = SimpleNamespace(command="scan")

    _require_execution_evidence(agent, request)


@pytest.mark.asyncio
async def test_tool_manager_executes_each_tool_only_once() -> None:
    calls: list[tuple[str, dict]] = []

    class Agent:
        mcp_manager = SimpleNamespace(
            call_tool=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("工具不应被二次执行")
            )
        )

        async def _execute_mcp_tool(self, name, arguments):
            calls.append((name, arguments))
            return "ok"

    tool_call = SimpleNamespace(
        id="call-1",
        function=SimpleNamespace(name="fetch", arguments='{"url":"https://example.test"}'),
    )
    message = SimpleNamespace(tool_calls=[tool_call])

    results, skipped = await handle_tool_calls_with_results(Agent(), message)

    assert calls == [("fetch", {"url": "https://example.test"})]
    assert results[0]["tool_call_id"] == "call-1"
    assert skipped == []

