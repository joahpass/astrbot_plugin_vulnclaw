from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import TaskRecord, TaskStatus, utc_now


class TaskRepository:
    def __init__(self, data_dir: str | Path, filename: str = "vulnclaw_tasks.db") -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / filename
        self._lock = threading.RLock()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.recover_interrupted()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    requester_umo TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status_created
                    ON tasks(status, created_at);
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    used_at TEXT NOT NULL
                );
                """
            )

    def save(self, task: TaskRecord) -> TaskRecord:
        task.updated_at = utc_now()
        payload = json.dumps(task.to_dict(), ensure_ascii=False, separators=(",", ":"))
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO tasks(task_id, status, mode, requester_umo, created_at, updated_at, payload_json)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status=excluded.status,
                    mode=excluded.mode,
                    requester_umo=excluded.requester_umo,
                    updated_at=excluded.updated_at,
                    payload_json=excluded.payload_json
                """,
                (
                    task.task_id,
                    task.status.value,
                    task.mode.value,
                    task.requester_umo,
                    task.created_at,
                    task.updated_at,
                    payload,
                ),
            )
        return task

    def get(self, task_id: str) -> TaskRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"未知任务：{task_id}")
        return TaskRecord.from_dict(json.loads(row["payload_json"]))

    def list(self, *, statuses: list[TaskStatus] | None = None, limit: int = 50) -> list[TaskRecord]:
        query = "SELECT payload_json FROM tasks"
        params: list[Any] = []
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            query += f" WHERE status IN ({placeholders})"
            params.extend(status.value for status in statuses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [TaskRecord.from_dict(json.loads(row["payload_json"])) for row in rows]

    def next_queued(self) -> TaskRecord | None:
        tasks = self.list(statuses=[TaskStatus.QUEUED], limit=100)
        return tasks[-1] if tasks else None

    def add_finding(self, task_id: str, finding: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO findings(task_id, severity, title, payload_json, created_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    str(finding.get("severity", "info")),
                    str(finding.get("title", "未命名发现")),
                    json.dumps(finding, ensure_ascii=False),
                    utc_now(),
                ),
            )

    def findings(self, task_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM findings WHERE task_id = ? ORDER BY finding_id",
                (task_id,),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def use_nonce(self, nonce: str) -> bool:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO nonces(nonce, used_at) VALUES(?, ?)", (nonce, utc_now())
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def recover_interrupted(self) -> None:
        for task in self.list(statuses=[TaskStatus.RUNNING], limit=500):
            task.status = TaskStatus.INTERRUPTED
            task.error = "AstrBot 或任务调度器重启；高风险任务不会自动恢复。"
            self.save(task)

