from __future__ import annotations

import json
import subprocess

import pytest

from supervisor.docker_backend import DockerBackend, DockerBackendError


def test_backend_rejects_raw_tools_and_invalid_task_ids(tmp_path) -> None:
    backend = DockerBackend(tmp_path, image="worker:test")
    with pytest.raises(DockerBackendError, match="task_id"):
        backend.call_tool("../escape", {"tool_name": "fetch", "arguments": {}})
    task_id = "vuln-123456abcdef"
    (tmp_path / "tasks" / task_id).mkdir(parents=True)
    with pytest.raises(DockerBackendError, match="白名单"):
        backend.call_tool(
            task_id, {"tool_name": "run_shell", "arguments": {"command": "id"}}
        )


def test_backend_validates_fixed_spec(tmp_path) -> None:
    backend = DockerBackend(tmp_path, image="worker:test")
    with pytest.raises(DockerBackendError, match="模式"):
        backend._validate_spec({"mode": "shell", "scope": {}})
    with pytest.raises(DockerBackendError, match="不完整"):
        backend._validate_spec({"mode": "scan", "scope": {"hostname": "x"}})


def test_egress_reject_rule_is_inserted_before_allow_rules(
    tmp_path, monkeypatch
) -> None:
    backend = DockerBackend(tmp_path, image="worker:test")
    commands = []

    def fake_run(command, *, check, timeout=30):
        commands.append(command)
        if command[:2] == ["docker", "inspect"]:
            stdout = "172.30.0.2\n"
        elif command[:3] == ["docker", "network", "inspect"]:
            stdout = json.dumps(
                [{"IPAM": {"Config": [{"Gateway": "172.30.0.1"}]}}]
            )
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr("supervisor.docker_backend.shutil.which", lambda _name: "ok")
    backend._apply_egress_policy(
        "vulnclaw-vuln-123456abcdef",
        {
            "scope": {
                "resolved_ips": ["203.0.113.10"],
                "ports": [443],
            }
        },
    )
    inserts = [command for command in commands if command[:3] == ["iptables", "-I", "DOCKER-USER"]]
    assert "REJECT" in inserts[0]
    assert "ESTABLISHED,RELATED" in inserts[-1]
