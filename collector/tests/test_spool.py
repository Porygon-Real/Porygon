from __future__ import annotations

import json
import sqlite3

from porygon_collector.spool import OutboxStore


def _event(event_id: str) -> dict[str, object]:
    return {"event_id": event_id, "action": "start"}


def test_outbox_deduplicates_and_acknowledges(tmp_path) -> None:
    store = OutboxStore(str(tmp_path / "outbox.db"), max_events=10)
    event_id = "a" * 64

    assert store.enqueue(_event(event_id)) is True
    assert store.enqueue(_event(event_id)) is False
    assert store.count() == 1
    assert store.fetch_due(10)[0]["event_id"] == event_id

    store.acknowledge([event_id])
    assert store.count() == 0


def test_container_cache_survives_store_reopen(tmp_path) -> None:
    path = str(tmp_path / "outbox.db")
    first = OutboxStore(path, max_events=10)
    first.cache_container("container-1", {"container": {"name": "probe"}})

    second = OutboxStore(path, max_events=10)
    assert second.get_cached_container("container-1") == {
        "container": {"name": "probe"}
    }


def test_store_repairs_legacy_detailed_actions_without_dropping_events(
    tmp_path,
) -> None:
    path = str(tmp_path / "outbox.db")
    event_id = "b" * 64
    store = OutboxStore(path, max_events=10)
    assert store.enqueue(
        {
            "event_id": event_id,
            "action": "exec_create: sh -c " + "echo-safe " * 100,
            "command": "sleep 300",
            "raw_event": {"Action": "exec_create: sh -c echo-safe"},
        }
    )

    reopened = OutboxStore(path, max_events=10)
    repaired = reopened.fetch_due(10)

    assert reopened.count() == 1
    assert repaired[0]["event_id"] == event_id
    assert repaired[0]["action"] == "exec_create"
    assert repaired[0]["command"] == "sh -c echo-safe"
    assert repaired[0]["raw_event"]["Action"] == "exec_create: sh -c echo-safe"
    assert reopened.get_metadata("legacy_actions_repaired_total") == "1"
    assert reopened.get_metadata("legacy_exec_commands_repaired_total") == "1"

    OutboxStore(path, max_events=10)
    assert reopened.get_metadata("legacy_actions_repaired_total") == "1"
    assert reopened.get_metadata("legacy_exec_commands_repaired_total") == "1"

    with sqlite3.connect(path) as connection:
        raw = connection.execute(
            "SELECT payload FROM outbox WHERE event_id = ?", (event_id,)
        ).fetchone()[0]
    assert json.loads(raw)["action"] == "exec_create"


def test_batch_failure_rolls_back_events_and_cursor(tmp_path):
    import pytest
    from porygon_collector.spool import SpoolFullError

    store = OutboxStore(str(tmp_path / "batch.db"), max_events=2)
    store.enqueue_batch([_event("a")], cursor=10)
    with pytest.raises(SpoolFullError):
        store.enqueue_batch([_event("b"), _event("c")], cursor=30)
    assert store.count() == 1
    assert store.get_cursor() == 10
    assert store.enqueue_batch([_event("a"), _event("b"), _event("b")], cursor=20) == (
        1,
        2,
    )
    store.enqueue_batch([], cursor=15)
    assert store.get_cursor() == 20
    assert OutboxStore(str(store.path), 2).count() == 2


def test_concurrent_batches_cannot_exceed_capacity(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from porygon_collector.spool import SpoolFullError

    path = str(tmp_path / "race.db")
    stores = [OutboxStore(path, 1), OutboxStore(path, 1)]

    def insert(index):
        try:
            stores[index].enqueue_batch([_event(str(index))], cursor=index + 1)
            return True
        except SpoolFullError:
            return False

    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(insert, range(2))) == 1
    assert stores[0].count() == 1
