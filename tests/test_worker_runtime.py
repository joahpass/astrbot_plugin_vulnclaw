from __future__ import annotations

import socket

import pytest

from worker.runtime import RuntimeScopeGuard, _restricted_python, execute_tool


def spec() -> dict:
    return {
        "mode": "scan",
        "scope": {
            "hostname": "target.example",
            "resolved_ips": ["203.0.113.21"],
            "ports": [443],
            "paths": ["/api"],
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
    }


def test_runtime_scope_checks_dns_path_and_port(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("203.0.113.21", 0))],
    )
    guard = RuntimeScopeGuard(spec())
    guard.validate_url("https://target.example/api/check")
    with pytest.raises(ValueError, match="port"):
        guard.validate_url("https://target.example:8443/api")
    with pytest.raises(ValueError, match="path"):
        guard.validate_url("https://target.example/admin")


def test_runtime_rejects_dns_change(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("198.51.100.9", 0))],
    )
    with pytest.raises(ValueError, match="DNS"):
        RuntimeScopeGuard(spec()).validate_url("https://target.example/api")


def test_restricted_python_allows_calculation_but_blocks_imports() -> None:
    guard = RuntimeScopeGuard(spec())
    result = _restricted_python(guard, {"code": "print(sum(range(5)))"})
    assert result["stdout"] == "10"
    with pytest.raises(ValueError, match="Import"):
        _restricted_python(guard, {"code": "import os"})
    with pytest.raises(ValueError):
        _restricted_python(guard, {"code": "open('/etc/passwd').read()"})


def test_unknown_tool_is_rejected() -> None:
    with pytest.raises(ValueError, match="未知工具"):
        execute_tool(spec(), "run_shell", {"command": "id"})


def test_skill_reference_path_escape_is_rejected() -> None:
    with pytest.raises(ValueError, match="reference_name"):
        execute_tool(
            spec(),
            "load_skill_reference",
            {"skill_name": "web-pentest", "reference_name": "../../request.json"},
        )
