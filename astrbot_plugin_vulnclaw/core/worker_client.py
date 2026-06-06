from __future__ import annotations

from typing import Any

import httpx

from .signing import HmacSigner


class WorkerClientError(RuntimeError):
    pass


class WorkerClient:
    def __init__(
        self,
        base_url: str,
        signer: HmacSigner,
        *,
        timeout_seconds: int = 30,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.signer = signer
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def health(self) -> dict[str, Any]:
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, transport=self.transport
        ) as client:
            response = await client.get(f"{self.base_url}/health")
        return self._decode(response)

    async def start_task(self, task_id: str, spec: dict[str, Any]) -> dict[str, Any]:
        return await self._post(f"/v1/tasks/{task_id}/start", task_id, spec)

    async def status(self, task_id: str) -> dict[str, Any]:
        return await self._post(f"/v1/tasks/{task_id}/status", task_id, {})

    async def cancel(self, task_id: str) -> dict[str, Any]:
        return await self._post(f"/v1/tasks/{task_id}/cancel", task_id, {})

    async def finish(
        self,
        task_id: str,
        *,
        summary: str,
        findings: list[dict[str, Any]],
        report_markdown: str,
    ) -> dict[str, Any]:
        return await self._post(
            f"/v1/tasks/{task_id}/finish",
            task_id,
            {
                "summary": summary,
                "findings": findings,
                "report_markdown": report_markdown,
            },
        )

    async def call_tool(
        self, task_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._post(
            f"/v1/tasks/{task_id}/tool",
            task_id,
            {"tool_name": tool_name, "arguments": arguments},
        )

    async def _post(self, path: str, task_id: str, body: dict[str, Any]) -> dict[str, Any]:
        payload = self.signer.sign(task_id, body).to_dict()
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, transport=self.transport
        ) as client:
            response = await client.post(f"{self.base_url}{path}", json=payload)
        return self._decode(response)

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except Exception as exc:
            raise WorkerClientError(
                f"Worker 返回非 JSON 响应：HTTP {response.status_code}"
            ) from exc
        if response.status_code >= 400 or not data.get("ok", False):
            raise WorkerClientError(
                str(
                    data.get("error")
                    or data.get("detail")
                    or f"HTTP {response.status_code}"
                )
            )
        return data
