from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4


TASK_ID_PATTERN = re.compile(r"^vuln-[a-f0-9]{12}$")
ALLOWED_MODES = {
    "recon",
    "scan",
    "run",
    "exploit",
    "persistent",
    "report",
    "post-exploitation",
}
ALLOWED_TOOLS = {
    "nmap_scan",
    "fetch",
    "python_execute",
    "crypto_decode",
    "load_skill_reference",
}


class DockerBackendError(RuntimeError):
    pass


class DockerBackend:
    def __init__(self, data_dir: str | Path, *, image: str) -> None:
        self.data_dir = Path(data_dir)
        self.image = image
        self.tasks_dir = self.data_dir / "tasks"
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        self.network = os.environ.get("VULNCLAW_TASK_NETWORK", "vulnclaw-tasks")
        self._lock = threading.RLock()

    def doctor(self) -> str:
        if not shutil.which("docker"):
            return "missing"
        result = self._run(
            ["docker", "version", "--format", "{{.Server.Version}}"], check=False
        )
        return result.stdout.strip() if result.returncode == 0 else "unavailable"

    def start(self, task_id: str, spec: dict[str, Any]) -> dict[str, Any]:
        self._validate_task_id(task_id)
        self._validate_spec(spec)
        if self.doctor() in {"missing", "unavailable"}:
            raise DockerBackendError("Docker 不可用")

        with self._lock:
            task_dir = self.tasks_dir / task_id
            container = f"vulnclaw-{task_id}"
            if task_dir.exists():
                raise DockerBackendError("任务容器已经存在")
            task_dir.mkdir(parents=True)
            try:
                self._write_json(task_dir / "request.json", spec)
                self._write_json(
                    task_dir / "state.json",
                    {
                        "status": "running",
                        "stage": "ready",
                        "summary": "隔离容器已启动，等待 AstrBot Agent 调用工具。",
                        "findings": [],
                        "report_path": "",
                    },
                )
                self._ensure_network()
                self._validate_not_supervisor_host(spec)
                created = self._run(
                    [
                        "docker",
                        "create",
                        "--name",
                        container,
                        "--label",
                        f"astrbot.vulnclaw.task={task_id}",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "--pids-limit",
                        "128",
                        "--memory",
                        os.environ.get("VULNCLAW_TASK_MEMORY", "512m"),
                        "--cpus",
                        os.environ.get("VULNCLAW_TASK_CPUS", "1.0"),
                        "--tmpfs",
                        "/tmp:rw,noexec,nosuid,size=64m",
                        "--network",
                        "none",
                        "--user",
                        "65532:65532",
                        "--volume",
                        f"{task_dir.resolve()}:/task:rw",
                        self.image,
                        "idle",
                        "/task/request.json",
                    ],
                    check=True,
                )
                self._run(
                    ["docker", "network", "connect", self.network, container], check=True
                )
                self._apply_egress_policy(container, spec)
                self._run(["docker", "start", container], check=True)
                return {
                    "run_id": created.stdout.strip(),
                    "status": "running",
                    "stage": "ready",
                }
            except Exception:
                self._remove_egress_policy(container)
                self._run(["docker", "rm", "-f", container], check=False)
                shutil.rmtree(task_dir, ignore_errors=True)
                raise

    def status(self, task_id: str) -> dict[str, Any]:
        self._validate_task_id(task_id)
        state_path = self.tasks_dir / task_id / "state.json"
        if not state_path.exists():
            raise DockerBackendError("任务状态不存在")
        return json.loads(state_path.read_text(encoding="utf-8"))

    def call_tool(self, task_id: str, request: dict[str, Any]) -> dict[str, Any]:
        self._validate_task_id(task_id)
        tool_name = str(request.get("tool_name", ""))
        arguments = request.get("arguments", {})
        if tool_name not in ALLOWED_TOOLS:
            raise DockerBackendError(f"工具不在白名单：{tool_name}")
        if not isinstance(arguments, dict):
            raise DockerBackendError("工具参数必须是对象")
        task_dir = self.tasks_dir / task_id
        if not task_dir.exists():
            raise DockerBackendError("任务不存在")

        request_id = uuid4().hex
        request_path = task_dir / f"tool-{request_id}.json"
        response_path = task_dir / f"result-{request_id}.json"
        self._write_json(
            request_path, {"tool_name": tool_name, "arguments": arguments}
        )
        try:
            result = self._run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "65532:65532",
                    f"vulnclaw-{task_id}",
                    "python",
                    "-m",
                    "worker.runtime",
                    "tool",
                    f"/task/{request_path.name}",
                    f"/task/{response_path.name}",
                ],
                check=False,
                timeout=int(os.environ.get("VULNCLAW_TOOL_TIMEOUT", "120")),
            )
            if result.returncode != 0:
                raise DockerBackendError(result.stderr.strip() or "工具执行失败")
            if not response_path.exists():
                raise DockerBackendError("工具未生成结果")
            return json.loads(response_path.read_text(encoding="utf-8"))
        finally:
            request_path.unlink(missing_ok=True)
            response_path.unlink(missing_ok=True)

    def finish(self, task_id: str, result: dict[str, Any]) -> dict[str, Any]:
        self._validate_task_id(task_id)
        summary = str(result.get("summary", ""))[:4000]
        report_markdown = str(result.get("report_markdown", ""))
        if len(report_markdown.encode("utf-8")) > 2 * 1024 * 1024:
            raise DockerBackendError("报告超过 2 MiB 上限")
        findings = result.get("findings", [])
        if not isinstance(findings, list) or len(findings) > 500:
            raise DockerBackendError("发现列表格式无效或数量超限")

        task_dir = self.tasks_dir / task_id
        report_path = task_dir / "report.md"
        report_path.write_text(report_markdown, encoding="utf-8")
        self._write_json(
            task_dir / "state.json",
            {
                "status": "completed",
                "stage": "completed",
                "summary": summary,
                "findings": findings,
                "report_path": str(report_path),
            },
        )
        self._destroy_container(task_id)
        return self.status(task_id)

    def cancel(self, task_id: str) -> dict[str, Any]:
        self._validate_task_id(task_id)
        self._destroy_container(task_id)
        state_path = self.tasks_dir / task_id / "state.json"
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state.update(
                status="cancelled", stage="cancelled", summary="任务已取消。"
            )
            self._write_json(state_path, state)
        return {"status": "cancelled", "stage": "cancelled"}

    def _destroy_container(self, task_id: str) -> None:
        container = f"vulnclaw-{task_id}"
        self._remove_egress_policy(container)
        self._run(["docker", "rm", "-f", container], check=False)

    def _ensure_network(self) -> None:
        inspect = self._run(
            ["docker", "network", "inspect", self.network], check=False
        )
        if inspect.returncode == 0:
            return
        self._run(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--label",
                "astrbot.vulnclaw=true",
                self.network,
            ],
            check=True,
        )

    def _apply_egress_policy(self, container: str, spec: dict[str, Any]) -> None:
        if os.environ.get("VULNCLAW_ENFORCE_IPTABLES", "true").lower() != "true":
            raise DockerBackendError("安全配置要求启用 iptables 出口策略")
        if not shutil.which("iptables"):
            raise DockerBackendError("Supervisor 缺少 iptables，拒绝启动任务")
        inspect = self._run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container,
            ],
            check=True,
        )
        source_ip = inspect.stdout.strip()
        if not source_ip:
            raise DockerBackendError("无法取得任务容器 IP")

        scope = dict(spec["scope"])
        comment = f"vulnclaw:{container}"
        gateway = self._network_gateway()
        rules = [
            [
                "-s",
                source_ip,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        ]
        if gateway:
            rules.extend(
                [
                    [
                        "-s",
                        source_ip,
                        "-d",
                        gateway,
                        "-p",
                        protocol,
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ]
                    for protocol in ("udp", "tcp")
                ]
            )
        for ip in scope["resolved_ips"]:
            for port in scope["ports"]:
                rules.append(
                    [
                        "-s",
                        source_ip,
                        "-d",
                        str(ip),
                        "-p",
                        "tcp",
                        "--dport",
                        str(port),
                        "-j",
                        "ACCEPT",
                    ]
                )
        rules.append(["-s", source_ip, "-j", "REJECT"])
        for rule in reversed(rules):
            self._run(
                [
                    "iptables",
                    "-I",
                    "DOCKER-USER",
                    "1",
                    *rule,
                    "-m",
                    "comment",
                    "--comment",
                    comment,
                ],
                check=True,
            )

    def _network_gateway(self) -> str:
        network_info = json.loads(
            self._run(
                ["docker", "network", "inspect", self.network], check=True
            ).stdout
        )
        configs = network_info[0].get("IPAM", {}).get("Config", [])
        if not configs:
            return ""
        return str(configs[0].get("Gateway", ""))

    def _validate_not_supervisor_host(self, spec: dict[str, Any]) -> None:
        blocked = {
            item.strip()
            for item in os.environ.get("VULNCLAW_BLOCKED_HOST_IPS", "").split(",")
            if item.strip()
        }
        gateway = self._network_gateway()
        if gateway:
            blocked.add(gateway)
        try:
            blocked.update(
                item[4][0]
                for item in socket.getaddrinfo(
                    socket.gethostname(), None, type=socket.SOCK_STREAM
                )
            )
        except socket.gaierror:
            pass
        requested = {str(item) for item in spec["scope"]["resolved_ips"]}
        overlap = sorted(requested & blocked)
        if overlap:
            raise DockerBackendError(
                f"目标解析到 Supervisor、宿主机或 Docker 网关地址：{overlap}"
            )

    def _remove_egress_policy(self, container: str) -> None:
        if not shutil.which("iptables-save"):
            return
        comment = f"vulnclaw:{container}"
        saved = self._run(["iptables-save"], check=False).stdout
        for line in saved.splitlines():
            if comment not in line or not line.startswith("-A DOCKER-USER "):
                continue
            try:
                rule = shlex.split(line.removeprefix("-A DOCKER-USER "))
            except ValueError:
                continue
            self._run(
                ["iptables", "-D", "DOCKER-USER", *rule],
                check=False,
            )

    @staticmethod
    def _validate_task_id(task_id: str) -> None:
        if not TASK_ID_PATTERN.fullmatch(task_id):
            raise DockerBackendError("task_id 格式无效")

    @staticmethod
    def _validate_spec(spec: dict[str, Any]) -> None:
        if str(spec.get("mode", "")) not in ALLOWED_MODES:
            raise DockerBackendError("任务模式无效")
        scope = spec.get("scope")
        if not isinstance(scope, dict):
            raise DockerBackendError("任务缺少 scope")
        required = {"hostname", "resolved_ips", "ports", "paths", "expires_at"}
        if not required.issubset(scope):
            raise DockerBackendError("scope 字段不完整")

    @staticmethod
    def _write_json(path: Path, value: dict[str, Any]) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @staticmethod
    def _run(
        command: list[str],
        *,
        check: bool,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
        if check and result.returncode != 0:
            raise DockerBackendError(result.stderr.strip() or "命令执行失败")
        return result
