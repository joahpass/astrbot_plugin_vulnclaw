from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

from .models import TaskScope


class ScopeError(ValueError):
    pass


BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}

DOCKER_GATEWAY_IPS = {
    ipaddress.ip_address("172.17.0.1"),
    ipaddress.ip_address("172.18.0.1"),
    ipaddress.ip_address("192.168.65.1"),
}

HOST_MANAGEMENT_PORTS = {22, 2375, 2376, 2379, 2380, 3306, 5432, 6379, 6443}


@dataclass(frozen=True)
class TargetInfo:
    target: str
    hostname: str
    scheme: str
    ports: list[int]
    paths: list[str]


class ScopeValidator:
    def __init__(self, resolver=None) -> None:
        self.resolver = resolver or self._resolve

    def build_scope(
        self,
        target: str,
        ports: list[int],
        paths: list[str],
        *,
        ttl_seconds: int = 3600,
    ) -> TaskScope:
        info = self.parse_target(target, ports, paths)
        resolved = self.resolver(info.hostname)
        if not resolved:
            raise ScopeError(f"目标无法解析：{info.hostname}")
        self.validate_ips(resolved)
        self.validate_ports(info.ports)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(60, ttl_seconds))
        return TaskScope(
            target=info.target,
            hostname=info.hostname,
            scheme=info.scheme,
            resolved_ips=sorted(set(resolved)),
            ports=info.ports,
            paths=info.paths,
            expires_at=expires_at.isoformat(timespec="seconds"),
        )

    def parse_target(self, target: str, ports: list[int], paths: list[str]) -> TargetInfo:
        clean = target.strip()
        if not clean:
            raise ScopeError("目标不能为空")
        parsed = urlparse(clean if "://" in clean else f"https://{clean}")
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError("首版只接受 http/https 目标")
        if not parsed.hostname:
            raise ScopeError("目标缺少有效主机名")
        final_ports = sorted(set(int(port) for port in ports))
        if parsed.port:
            final_ports = sorted(set([*final_ports, parsed.port]))
        if not final_ports:
            final_ports = [443 if parsed.scheme == "https" else 80]
        final_paths = [self._normalize_path(item) for item in paths if item.strip()]
        if parsed.path and parsed.path != "/":
            final_paths.append(self._normalize_path(parsed.path))
        if not final_paths:
            final_paths = ["/"]
        canonical_target = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            canonical_target += f":{parsed.port}"
        return TargetInfo(
            target=canonical_target,
            hostname=parsed.hostname.lower().rstrip("."),
            scheme=parsed.scheme,
            ports=final_ports,
            paths=sorted(set(final_paths)),
        )

    def validate_runtime_target(self, scope: TaskScope, target: str, port: int, path: str) -> None:
        parsed = urlparse(target if "://" in target else f"{scope.scheme}://{target}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if hostname != scope.hostname:
            raise ScopeError(f"主机不在任务 scope：{hostname}")
        resolved = self.resolver(hostname)
        self.validate_ips(resolved)
        if not set(resolved).issubset(set(scope.resolved_ips)):
            raise ScopeError("DNS 解析结果发生变化且超出审批时 scope")
        if port not in scope.ports:
            raise ScopeError(f"端口不在任务 scope：{port}")
        normalized_path = self._normalize_path(path or parsed.path or "/")
        if not any(
            normalized_path == allowed or normalized_path.startswith(allowed.rstrip("/") + "/")
            for allowed in scope.paths
        ):
            raise ScopeError(f"路径不在任务 scope：{normalized_path}")

    def validate_redirect(self, scope: TaskScope, current_url: str, location: str) -> str:
        redirected = urljoin(current_url, location)
        parsed = urlparse(redirected)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.validate_runtime_target(scope, redirected, port, parsed.path or "/")
        return redirected

    @staticmethod
    def validate_ips(values: list[str]) -> None:
        for value in values:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ScopeError(f"无效解析地址：{value}") from exc
            if ip in METADATA_IPS:
                raise ScopeError(f"禁止访问云 metadata 地址：{ip}")
            if ip in DOCKER_GATEWAY_IPS:
                raise ScopeError(f"禁止访问 Docker 网关地址：{ip}")
            if any(ip.version == network.version and ip in network for network in BLOCKED_NETWORKS):
                raise ScopeError(f"禁止访问保留或宿主机网络：{ip}")

    @staticmethod
    def validate_ports(ports: list[int]) -> None:
        if not ports:
            raise ScopeError("至少需要一个端口")
        invalid = [port for port in ports if port < 1 or port > 65535]
        if invalid:
            raise ScopeError(f"端口超出范围：{invalid}")
        blocked = sorted(set(ports) & HOST_MANAGEMENT_PORTS)
        if blocked:
            raise ScopeError(f"默认禁止宿主机管理端口：{blocked}")

    @staticmethod
    def _normalize_path(path: str) -> str:
        clean = "/" + path.strip().lstrip("/")
        if ".." in clean.split("/"):
            raise ScopeError("路径不能包含 ..")
        return clean

    @staticmethod
    def _resolve(hostname: str) -> list[str]:
        try:
            return sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                }
            )
        except socket.gaierror as exc:
            raise ScopeError(f"DNS 解析失败：{hostname}") from exc
