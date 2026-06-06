from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

from astrbot_plugin_vulnclaw.core.database import TaskRepository
from astrbot_plugin_vulnclaw.core.signing import HmacSigner, SignatureError

from .docker_backend import DockerBackend, DockerBackendError


DATA_DIR = Path(os.environ.get("VULNCLAW_SUPERVISOR_DATA", "/var/lib/vulnclaw"))
SECRET = os.environ.get("VULNCLAW_WORKER_SECRET", "")
IMAGE = os.environ.get("VULNCLAW_TASK_IMAGE", "astrbot-vulnclaw-worker:0.1.0")

if len(SECRET.encode("utf-8")) < 32:
    raise RuntimeError("VULNCLAW_WORKER_SECRET 至少需要 32 字节")

repository = TaskRepository(DATA_DIR, "supervisor.db")
signer = HmacSigner(SECRET)
backend = DockerBackend(DATA_DIR, image=IMAGE)
app = FastAPI(title="AstrBot VulnClaw Supervisor", docs_url=None, redoc_url=None)


def verify(payload: dict[str, Any], task_id: str) -> dict[str, Any]:
    try:
        request = signer.verify(
            payload,
            expected_task_id=task_id,
            nonce_consumer=repository.use_nonce,
        )
        return request.body
    except SignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "docker": backend.doctor(),
        "vulnclaw_version": "0.2.9",
        "image": IMAGE,
    }


@app.post("/v1/tasks/{task_id}/start")
def start(task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = verify(payload, task_id)
    try:
        return {"ok": True, **backend.start(task_id, body)}
    except DockerBackendError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/tasks/{task_id}/status")
def status(task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    verify(payload, task_id)
    try:
        return {"ok": True, **backend.status(task_id)}
    except DockerBackendError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/v1/tasks/{task_id}/cancel")
def cancel(task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    verify(payload, task_id)
    return {"ok": True, **backend.cancel(task_id)}


@app.post("/v1/tasks/{task_id}/finish")
def finish(task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = verify(payload, task_id)
    try:
        return {"ok": True, **backend.finish(task_id, body)}
    except DockerBackendError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/tasks/{task_id}/tool")
def tool(task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = verify(payload, task_id)
    try:
        return {"ok": True, **backend.call_tool(task_id, body)}
    except DockerBackendError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
