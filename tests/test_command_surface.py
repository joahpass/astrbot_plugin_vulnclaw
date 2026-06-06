from __future__ import annotations

from astrbot_plugin_vulnclaw.main import VulnClawPlugin
from astrbot_plugin_vulnclaw.core.scope import ScopeValidator


class FakeEvent:
    unified_msg_origin = "qq:private:42"
    sender_id = "42"
    role = "member"

    def plain_result(self, text):
        return text


class FakeContext:
    pass


def test_plan_and_status_return_chinese_text(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    plugin = VulnClawPlugin(FakeContext(), {})
    plugin.scope_validator = ScopeValidator(lambda _host: ["203.0.113.20"])
    plugin.task_service.scope_validator = plugin.scope_validator
    event = FakeEvent()
    text = plugin._plan_text(
        event,
        "scan",
        "https://target.example",
        "443",
        "/",
        "已获得系统所有者授权",
    )
    assert "任务计划已创建" in text
    task_id = text.splitlines()[0].split("：", 1)[1]
    assert "状态：draft" in plugin._status_text(task_id)


def test_non_admin_cannot_direct_start(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    plugin = VulnClawPlugin(FakeContext(), {})
    assert not plugin._is_admin(FakeEvent())
