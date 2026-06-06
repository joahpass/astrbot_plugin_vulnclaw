from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse


def load_task_spec(path: str | Path = "/task/request.json") -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


class RuntimeScopeGuard:
    def __init__(self, spec: dict[str, Any]) -> None:
        self.scope = dict(spec["scope"])

    def validate_url(self, url: str) -> None:
        self._validate_expiry()
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if host != str(self.scope["hostname"]).lower().rstrip("."):
            raise ValueError(f"host 超出 scope：{host}")
        self._validate_resolution(host)
        if port not in [int(item) for item in self.scope["ports"]]:
            raise ValueError(f"port 超出 scope：{port}")
        if not any(
            path == allowed or path.startswith(str(allowed).rstrip("/") + "/")
            for allowed in self.scope["paths"]
        ):
            raise ValueError(f"path 超出 scope：{path}")

    def validate_host_ports(self, host: str, ports: list[int]) -> None:
        self._validate_expiry()
        if host.lower().rstrip(".") != str(self.scope["hostname"]).lower().rstrip("."):
            raise ValueError(f"host 超出 scope：{host}")
        self._validate_resolution(host)
        invalid = [port for port in ports if port not in self.scope["ports"]]
        if invalid:
            raise ValueError(f"port 超出 scope：{invalid}")

    def _validate_resolution(self, host: str) -> None:
        resolved = {
            item[4][0]
            for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
        approved = {str(item) for item in self.scope["resolved_ips"]}
        if not resolved or not resolved.issubset(approved):
            raise ValueError("DNS 解析结果超出审批时固定 IP")

    def _validate_expiry(self) -> None:
        expires_at = datetime.fromisoformat(str(self.scope["expires_at"]))
        if datetime.now(timezone.utc) > expires_at:
            raise ValueError("任务 scope 已过期")


def execute_tool(spec: dict[str, Any], tool_name: str, arguments: dict[str, Any]) -> Any:
    guard = RuntimeScopeGuard(spec)
    if tool_name == "load_skill_reference":
        skill_name = str(arguments.get("skill_name", ""))
        reference_name = str(arguments.get("reference_name", ""))
        if not re.fullmatch(r"[a-z0-9_-]{1,120}", skill_name):
            raise ValueError("skill_name 格式无效")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,180}", reference_name)
            or ".." in reference_name
        ):
            raise ValueError("reference_name 格式无效")
        from vulnclaw.skills.loader import load_skill_reference

        return load_skill_reference(
            skill_name,
            reference_name,
        )
    if tool_name == "crypto_decode":
        from vulnclaw.skills.crypto_tools import execute

        operation = str(arguments.get("operation", ""))
        if operation not in {
            "base64_decode",
            "url_decode",
            "hex_decode",
            "sha256_hash",
        }:
            raise ValueError("crypto operation 不在白名单")
        return execute(
            operation=operation,
            input_str=str(arguments.get("input", "")),
            **{
                key: arguments[key]
                for key in ("key", "iv", "shift", "secret", "header", "algorithm")
                if key in arguments
            },
        )
    if tool_name == "fetch":
        return asyncio.run(_fetch(guard, arguments))
    if tool_name == "nmap_scan":
        return asyncio.run(_nmap(spec, guard, arguments))
    if tool_name == "python_execute":
        return _restricted_python(guard, arguments)
    raise ValueError(f"未知工具：{tool_name}")


async def _fetch(guard: RuntimeScopeGuard, arguments: dict[str, Any]) -> dict[str, Any]:
    import httpx

    url = str(arguments.get("url", ""))
    guard.validate_url(url)
    method = str(arguments.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        raise ValueError("HTTP method 不在白名单")
    async with httpx.AsyncClient(follow_redirects=False, timeout=20) as client:
        response = await client.request(
            method,
            url,
            headers=dict(arguments.get("headers", {})),
            content=str(arguments.get("body", ""))[:65536],
        )
    location = response.headers.get("location", "")
    if location:
        from urllib.parse import urljoin

        guard.validate_url(urljoin(url, location))
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text[:20000],
    }


async def _nmap(
    spec: dict[str, Any], guard: RuntimeScopeGuard, arguments: dict[str, Any]
) -> dict[str, Any]:
    import shutil
    import subprocess

    if not shutil.which("nmap"):
        raise ValueError("任务镜像未安装 nmap")
    host = str(arguments.get("target", spec["scope"]["hostname"]))
    raw_ports = arguments.get("ports", [])
    if isinstance(raw_ports, list):
        ports = sorted({int(item) for item in raw_ports})
    else:
        ports = _parse_ports(str(raw_ports))
    ports = ports or [int(item) for item in spec["scope"]["ports"]]
    guard.validate_host_ports(host, ports)
    command = [
        "nmap",
        "-Pn",
        "-sT",
        "--max-retries",
        "1",
        "--host-timeout",
        "60s",
        "-p",
        ",".join(str(port) for port in ports),
        "--",
        host,
    ]
    result = await asyncio.to_thread(
        subprocess.run,
        command,
        capture_output=True,
        text=True,
        timeout=75,
        shell=False,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout[:20000],
        "stderr": result.stderr[:4000],
    }


def _restricted_python(guard: RuntimeScopeGuard, arguments: dict[str, Any]) -> dict[str, Any]:
    code = str(arguments.get("code", ""))
    if len(code.splitlines()) > 50 or len(code) > 12000:
        raise ValueError("Python 代码超过限制")
    tree = ast.parse(code, mode="exec")
    blocked_nodes = (
        ast.Import,
        ast.ImportFrom,
        ast.With,
        ast.AsyncWith,
        ast.Try,
        ast.Raise,
        ast.Global,
        ast.Nonlocal,
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
    )
    blocked_names = {
        "__import__",
        "breakpoint",
        "compile",
        "eval",
        "exec",
        "globals",
        "input",
        "locals",
        "open",
    }
    for node in ast.walk(tree):
        if isinstance(node, blocked_nodes):
            raise ValueError(f"Python safe 模式禁止语法：{type(node).__name__}")
        if isinstance(node, ast.Name) and node.id in blocked_names:
            raise ValueError(f"Python safe 模式禁止名称：{node.id}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise ValueError("Python safe 模式禁止 dunder 属性")
    safe_builtins = {
        "abs": abs,
        "all": all,
        "any": any,
        "bool": bool,
        "dict": dict,
        "enumerate": enumerate,
        "float": float,
        "int": int,
        "len": len,
        "list": list,
        "max": max,
        "min": min,
        "print": print,
        "range": range,
        "set": set,
        "sorted": sorted,
        "str": str,
        "sum": sum,
        "tuple": tuple,
        "zip": zip,
    }
    output: list[str] = []
    safe_builtins["print"] = lambda *items, **_kwargs: output.append(
        " ".join(str(item) for item in items)
    )
    namespace: dict[str, Any] = {
        "__builtins__": safe_builtins,
        "scope": {
            "hostname": guard.scope["hostname"],
            "ports": guard.scope["ports"],
            "paths": guard.scope["paths"],
        },
    }
    exec(compile(tree, "<vulnclaw-safe-python>", "exec"), namespace, namespace)
    return {"stdout": "\n".join(output)[:8000]}


def _parse_ports(value: str) -> list[int]:
    ports = []
    for item in value.split(","):
        clean = item.strip()
        if clean.isdigit():
            ports.append(int(clean))
    return sorted(set(ports))


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit("usage: runtime.py idle <spec> | tool <request> <response>")
    action = sys.argv[1]
    if action == "idle":
        load_task_spec(sys.argv[2])
        while True:
            time.sleep(3600)
    if action == "tool":
        request_path = Path(sys.argv[2])
        response_path = Path(sys.argv[3])
        spec = load_task_spec()
        request = json.loads(request_path.read_text(encoding="utf-8"))
        try:
            result = execute_tool(spec, str(request["tool_name"]), dict(request["arguments"]))
            payload = {"success": True, "result": result}
        except Exception as exc:
            payload = {"success": False, "error": str(exc)}
        response_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return
    raise SystemExit(f"unknown action: {action}")


if __name__ == "__main__":
    main()
