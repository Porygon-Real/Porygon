"""Durable operation receipts and completion delivery, separate from Docker calls."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator


class CompletionStore:
    def __init__(self, path: str, max_operations: int = 50000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_operations = max_operations
        self.lock_file = None
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS operations(
                operation_key TEXT PRIMARY KEY, execution_id TEXT NOT NULL,
                operation TEXT NOT NULL, started_at TEXT NOT NULL,
                state TEXT NOT NULL, payload TEXT, acknowledged INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL)""")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def acquire_worker(self) -> bool:
        """One worker per shared journal; the OS releases ownership after a crash."""
        if self.lock_file is not None:
            return True
        handle = self.path.with_suffix(".worker-lock").open("a")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False
        self.lock_file = handle
        return True

    def close(self) -> None:
        if self.lock_file is not None:
            self.lock_file.close()
            self.lock_file = None

    @staticmethod
    def key(execution: dict[str, Any], operation: str) -> tuple[str, str]:
        start = execution.get(
            "rollback_started_at" if operation == "rollback" else "started_at"
        )
        if not start:
            raise ValueError("Claim lacks a durable operation start identity")
        return f"{execution['execution_id']}:{operation}:{start}", str(start)

    def reserve(
        self, execution: dict[str, Any], operation: str
    ) -> tuple[str, dict[str, Any] | None]:
        key, start = self.key(execution, operation)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM operations WHERE operation_key=?", (key,)
            ).fetchone()
            if existing is not None:
                return key, dict(existing)
            count = db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
            if count >= self.max_operations:
                # Completed, acknowledged receipts cannot be claimed by the backend
                # again; manual retries have a different started_at generation.
                db.execute(
                    "DELETE FROM operations WHERE operation_key IN (SELECT operation_key FROM operations WHERE acknowledged=1 ORDER BY created_at LIMIT 1000)"
                )
                count = db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
                if count >= self.max_operations:
                    raise RuntimeError(
                        "Completion journal is full; refusing a new Docker action"
                    )
            db.execute(
                "INSERT INTO operations(operation_key,execution_id,operation,started_at,state,created_at) VALUES(?,?,?,?,?,?)",
                (
                    key,
                    execution["execution_id"],
                    operation,
                    start,
                    "in_flight",
                    time.time(),
                ),
            )
        return key, None

    def complete(self, key: str, payload: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE operations SET state='completed',payload=?,acknowledged=0,next_attempt_at=0 WHERE operation_key=?",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")), key),
            )

    def pending(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM operations WHERE state='completed' AND acknowledged=0 AND next_attempt_at<=? ORDER BY created_at LIMIT 100",
                    (time.time(),),
                )
            ]

    def pending_count(self) -> int:
        with self.connect() as db:
            return db.execute(
                "SELECT COUNT(*) FROM operations WHERE state='completed' AND acknowledged=0"
            ).fetchone()[0]

    def acknowledge(self, key: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE operations SET acknowledged=1 WHERE operation_key=?", (key,)
            )

    def retry(self, key: str) -> None:
        with self.connect() as db:
            row = db.execute(
                "SELECT attempts FROM operations WHERE operation_key=?", (key,)
            ).fetchone()
            if row is not None:
                attempts = int(row["attempts"]) + 1
                db.execute(
                    "UPDATE operations SET attempts=?,next_attempt_at=? WHERE operation_key=?",
                    (attempts, time.time() + min(60, 2 ** min(attempts, 6)), key),
                )
