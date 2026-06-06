from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4


class SignatureError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class SignedRequest:
    timestamp: int
    nonce: str
    task_id: str
    body: dict[str, Any]
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "task_id": self.task_id,
            "body": self.body,
            "signature": self.signature,
        }


class HmacSigner:
    def __init__(self, secret: str, *, max_clock_skew_seconds: int = 60) -> None:
        if len(secret.encode("utf-8")) < 32:
            raise ValueError("worker_secret 至少需要 32 字节")
        self.secret = secret.encode("utf-8")
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def sign(self, task_id: str, body: dict[str, Any]) -> SignedRequest:
        timestamp = int(time.time())
        nonce = uuid4().hex
        unsigned = {
            "timestamp": timestamp,
            "nonce": nonce,
            "task_id": task_id,
            "body": body,
        }
        signature = hmac.new(self.secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
        return SignedRequest(signature=signature, **unsigned)

    def verify(
        self,
        payload: dict[str, Any],
        *,
        expected_task_id: str = "",
        nonce_consumer: Callable[[str], bool] | None = None,
    ) -> SignedRequest:
        try:
            request = SignedRequest(
                timestamp=int(payload["timestamp"]),
                nonce=str(payload["nonce"]),
                task_id=str(payload["task_id"]),
                body=dict(payload["body"]),
                signature=str(payload["signature"]),
            )
        except Exception as exc:
            raise SignatureError("签名请求格式错误") from exc
        if abs(int(time.time()) - request.timestamp) > self.max_clock_skew_seconds:
            raise SignatureError("请求时间戳已过期")
        if expected_task_id and request.task_id != expected_task_id:
            raise SignatureError("task_id 不匹配")
        unsigned = {
            "timestamp": request.timestamp,
            "nonce": request.nonce,
            "task_id": request.task_id,
            "body": request.body,
        }
        expected = hmac.new(self.secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, request.signature):
            raise SignatureError("HMAC 签名无效")
        if nonce_consumer is not None and not nonce_consumer(request.nonce):
            raise SignatureError("nonce 已使用，拒绝重放")
        return request

