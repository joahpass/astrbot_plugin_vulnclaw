from __future__ import annotations

import pytest

from astrbot_plugin_vulnclaw.core.scope import ScopeError, ScopeValidator


def test_scope_pins_dns_ports_and_paths() -> None:
    validator = ScopeValidator(lambda _host: ["203.0.113.25"])
    scope = validator.build_scope(
        "https://target.example/app", [8443], ["/api"], ttl_seconds=600
    )
    assert scope.hostname == "target.example"
    assert scope.resolved_ips == ["203.0.113.25"]
    assert scope.ports == [8443]
    assert scope.paths == ["/api", "/app"]
    validator.validate_runtime_target(
        scope, "https://target.example:8443/api/check", 8443, "/api/check"
    )


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "169.254.169.254", "100.100.100.200", "172.17.0.1"],
)
def test_scope_blocks_reserved_targets(address: str) -> None:
    validator = ScopeValidator(lambda _host: [address])
    with pytest.raises(ScopeError):
        validator.build_scope(f"http://{address}", [80], ["/"])


def test_dns_rebinding_and_redirect_escape_are_rejected() -> None:
    answers = iter([["203.0.113.10"], ["198.51.100.9"]])
    validator = ScopeValidator(lambda _host: next(answers))
    scope = validator.build_scope("https://safe.example", [443], ["/"])
    with pytest.raises(ScopeError, match="DNS"):
        validator.validate_runtime_target(
            scope, "https://safe.example/", 443, "/"
        )

    fixed = ScopeValidator(lambda _host: ["203.0.113.10"])
    scope = fixed.build_scope("https://safe.example", [443], ["/"])
    with pytest.raises(ScopeError, match="scope"):
        fixed.validate_redirect(scope, scope.target, "https://evil.example/")


def test_path_escape_and_management_ports_are_rejected() -> None:
    validator = ScopeValidator(lambda _host: ["203.0.113.10"])
    with pytest.raises(ScopeError):
        validator.build_scope("https://safe.example", [22], ["/"])
    with pytest.raises(ScopeError):
        validator.build_scope("https://safe.example", [443], ["/../../etc"])
