from __future__ import annotations

import pytest

from astrbot_plugin_vulnclaw.core.approval import (
    generate_approval_code,
    hash_approval_code,
    verify_approval_code,
)
from astrbot_plugin_vulnclaw.core.signing import HmacSigner, SignatureError


def test_approval_code_is_one_time_secret_material() -> None:
    code = generate_approval_code()
    assert len(code) == 6 and code.isdigit()
    digest = hash_approval_code("vuln-123456abcdef", code)
    assert code not in digest
    assert verify_approval_code("vuln-123456abcdef", code, digest)
    assert not verify_approval_code("vuln-123456abcdef", "000000", digest)


def test_hmac_verifies_task_and_rejects_replay() -> None:
    signer = HmacSigner("x" * 32)
    payload = signer.sign("vuln-123456abcdef", {"mode": "scan"}).to_dict()
    used: set[str] = set()

    def consume(nonce: str) -> bool:
        if nonce in used:
            return False
        used.add(nonce)
        return True

    request = signer.verify(
        payload, expected_task_id="vuln-123456abcdef", nonce_consumer=consume
    )
    assert request.body == {"mode": "scan"}
    with pytest.raises(SignatureError, match="nonce"):
        signer.verify(
            payload, expected_task_id="vuln-123456abcdef", nonce_consumer=consume
        )
    with pytest.raises(SignatureError, match="task_id"):
        signer.verify(payload, expected_task_id="vuln-ffffffffffff")

