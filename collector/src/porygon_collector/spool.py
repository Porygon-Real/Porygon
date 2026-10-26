from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from porygon_collector.event_identity import action_detail, canonicalize_action


class SpoolFullError(RuntimeError):
    pass


class OutboxStore:
    def __init__(self, path: str, max_events: int) -> None:
        self.path = Path(path)
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    enqueued_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_outbox_due
                    ON outbox(next_attempt_at, enqueued_at);

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS container_cache (
                    container_id TEXT PRIMARY KEY,
                    snapshot TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            self._repair_legacy_actions(connection)

    @staticmethod
    def _repair_legacy_actions(connection: sqlite3.Connection) -> None:
        """Make queued pre-fix Docker actions conform to the categorical API field.

        Event IDs remain unchanged because they were durably assigned at capture time.
        The raw event and attributes retain the original Docker action detail.
        """
        actions_repaired = 0
        commands_repaired = 0
        rows = connection.execute("SELECT event_id, payload FROM outbox").fetchall()
        for row in rows:
            payload = json.loads(row["payload"])
            original = str(payload.get("action") or "unknown")
            canonical = canonicalize_action(original)
            changed = False
            if canonical != original:
                payload["action"] = canonical
                actions_repaired += 1
                changed = True

            raw_event = payload.get("raw_event")
            raw_action = (
                raw_event.get("Action") if isinstance(raw_event, dict) else None
            )
            detail = action_detail(raw_action)
            if (
                canonical in {"exec_create", "exec_start"}
                and detail
                and payload.get("command") != detail
            ):
                payload["command"] = detail
                commands_repaired += 1
                changed = True

            if not changed:
                continue
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            connection.execute(
                "UPDATE outbox SET payload = ? WHERE event_id = ?",
                (serialized, row["event_id"]),
            )

        if actions_repaired:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'legacy_actions_repaired_total'"
            ).fetchone()
            previous = int(row["value"]) if row else 0
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES ('legacy_actions_repaired_total', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(previous + actions_repaired),),
            )

        if commands_repaired:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'legacy_exec_commands_repaired_total'"
            ).fetchone()
            previous = int(row["value"]) if row else 0
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES ('legacy_exec_commands_repaired_total', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(previous + commands_repaired),),
            )

    def enqueue(self, payload: dict[str, Any]) -> bool:
        inserted, _ = self.enqueue_batch([payload])
        return inserted == 1

    def enqueue_batch(
        self, payloads: list[dict[str, Any]], cursor: int | None = None
    ) -> tuple[int, int]:
        """Commit a bounded batch and its replay cursor together, or commit neither."""
        serialized = {
            str(payload["event_id"]): json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            )
            for payload in payloads
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0])
            existing: set[str] = set()
            ids = list(serialized)
            for offset in range(0, len(ids), 500):
                chunk = ids[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                existing.update(
                    row[0]
                    for row in connection.execute(
                        f"SELECT event_id FROM outbox WHERE event_id IN ({placeholders})",
                        chunk,
                    )
                )
            new = [
                (key, value, time.time())
                for key, value in serialized.items()
                if key not in existing
            ]
            if count + len(new) > self.max_events:
                raise SpoolFullError(
                    f"Durable outbox reached configured limit of {self.max_events} events"
                )
            connection.executemany(
                "INSERT INTO outbox(event_id, payload, enqueued_at) VALUES (?, ?, ?)",
                new,
            )
            if cursor is not None:
                connection.execute(
                    """INSERT INTO metadata(key, value) VALUES ('last_event_time_nano', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    WHERE CAST(metadata.value AS INTEGER) < CAST(excluded.value AS INTEGER)""",
                    (str(cursor),),
                )
        return len(new), count + len(new)

    def fetch_due(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM outbox
                WHERE next_attempt_at <= ?
                ORDER BY enqueued_at, event_id
                LIMIT ?
                """,
                (time.time(), limit),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as connection:
            connection.execute(
                f"DELETE FROM outbox WHERE event_id IN ({placeholders})",
                event_ids,
            )

    def mark_failed(
        self, event_ids: list[str], error: str, max_retry_seconds: int
    ) -> None:
        if not event_ids:
            return
        now = time.time()
        with self._connect() as connection:
            for event_id in event_ids:
                row = connection.execute(
                    "SELECT attempts FROM outbox WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    continue
                attempts = int(row["attempts"]) + 1
                delay = min(max_retry_seconds, 2 ** min(attempts, 10))
                connection.execute(
                    """
                    UPDATE outbox
                    SET attempts = ?, next_attempt_at = ?, last_error = ?
                    WHERE event_id = ?
                    """,
                    (attempts, now + delay, error[:1000], event_id),
                )

    def count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0])

    def set_metadata(self, key: str, value: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_metadata(self, key: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (key,),
            ).fetchone()
        return str(row["value"]) if row else None

    def update_cursor(self, time_nano: int) -> None:
        self.enqueue_batch([], cursor=time_nano)

    def get_cursor(self) -> int | None:
        value = self.get_metadata("last_event_time_nano")
        return int(value) if value is not None else None

    def cache_container(self, container_id: str, snapshot: dict[str, Any]) -> None:
        serialized = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO container_cache(container_id, snapshot, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(container_id) DO UPDATE
                SET snapshot = excluded.snapshot, updated_at = excluded.updated_at
                """,
                (container_id, serialized, time.time()),
            )

    def get_cached_container(self, container_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT snapshot FROM container_cache WHERE container_id = ?",
                (container_id,),
            ).fetchone()
        return json.loads(row["snapshot"]) if row else None
