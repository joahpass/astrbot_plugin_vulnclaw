from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_approval_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_approval_code(task_id: str, code: str) -> str:
    return hashlib.sha256(f"{task_id}:{code}".encode("utf-8")).hexdigest()


def verify_approval_code(task_id: str, code: str, expected_hash: str) -> bool:
    actual = hash_approval_code(task_id, code.strip())
    return hmac.compare_digest(actual, expected_hash)

