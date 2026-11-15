from datetime import datetime, timezone
from threading import Event, Thread
from types import SimpleNamespace
import time

import pytest

from porygon_collector.docker_source import DockerEventSource
from porygon_collector.spool import OutboxStore
from porygon_collector.state import CollectorState


def source(tmp_path, monkeypatch, capacity=100):
    store = OutboxStore(str(tmp_path / "spool.db"), capacity)
    state = CollectorState(started_at=datetime.now(timezone.utc))
    instance = DockerEventSource(SimpleNamespace(), state, store)
    monkeypatch.setattr(
        "porygon_collector.docker_source.normalize_event", lambda c, s, h, raw: raw
    )
    return instance, store


def test_sparse_stream_flushes_before_window_ends(tmp_path, monkeypatch):
    instance, store = source(tmp_path, monkeypatch)
    release = Event()

    def events(**kwargs):
        yield {"event_id": "one", "time_nano": 7}
        release.wait(3)

    worker = Thread(
        target=lambda: instance._capture_window(
            SimpleNamespace(events=events), "h", since=0, until=10
        )
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while store.count() != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert store.count() == 1
        assert worker.is_alive()
        assert store.get_cursor() == 7
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive()


def test_stream_failure_commits_valid_prefix(tmp_path, monkeypatch):
    instance, store = source(tmp_path, monkeypatch)

    def events(**kwargs):
        yield {"event_id": "one", "time_nano": 7}
        raise OSError("connection lost")

    with pytest.raises(OSError):
        instance._capture_window(SimpleNamespace(events=events), "h", since=0, until=10)
    assert store.count() == 1
    assert store.get_cursor() == 7


def test_full_spool_preserves_uncommitted_cursor_on_shutdown(tmp_path, monkeypatch):
    instance, store = source(tmp_path, monkeypatch, capacity=1)
    store.enqueue_batch([{"event_id": "old", "time_nano": 1}], cursor=1)

    def stop(seconds):
        instance.stop_event.set()
        return True

    monkeypatch.setattr(instance.stop_event, "wait", stop)
    client = SimpleNamespace(
        events=lambda **kwargs: iter([{"event_id": "new", "time_nano": 2}])
    )
    assert instance._capture_window(client, "h", since=0, until=10) is False
    assert store.get_cursor() == 1
    assert store.fetch_due(10)[0]["event_id"] == "old"


def test_batch_prefix_fills_remaining_capacity_without_checkpointing_tail(
    tmp_path, monkeypatch
):
    instance, store = source(tmp_path, monkeypatch, capacity=100)
    store.enqueue_batch(
        [{"event_id": f"old-{index}", "time_nano": index + 1} for index in range(98)],
        cursor=100,
    )
    events = [
        {"event_id": "new-0", "time_nano": 203},
        {"event_id": "new-1", "time_nano": 201},
        {"event_id": "new-2", "time_nano": 202},
    ]
    result = []
    worker = Thread(
        target=lambda: result.append(
            instance._capture_window(
                SimpleNamespace(events=lambda **_kwargs: iter(events)),
                "host-a",
                since=0,
                until=300,
            )
        )
    )
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while (
            (store.count() < 100 or instance.state.snapshot()["spool_overflow_count"] == 0)
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert store.count() == 100
        assert instance.state.snapshot()["spool_overflow_count"] > 0
        assert store.get_cursor() == 100
        queued_ids = {event["event_id"] for event in store.fetch_due(100)}
        assert {"new-0", "new-1"} <= queued_ids
        assert "new-2" not in queued_ids
    finally:
        instance.stop_event.set()
        worker.join(3)
    assert not worker.is_alive()
    assert result == [False]
    assert store.get_cursor() == 100

    # A replay after capacity becomes available recognizes the committed prefix,
    # inserts the retained tail, and only then advances the original checkpoint.
    store.acknowledge(["old-0"])
    instance.stop_event.clear()
    assert instance._capture_window(
        SimpleNamespace(events=lambda **_kwargs: iter(events)),
        "host-a",
        since=0,
        until=300,
    ) is True
    assert store.count() == 100
    assert store.get_cursor() == 203
    queued_ids = {event["event_id"] for event in store.fetch_due(100)}
    assert {"new-0", "new-1", "new-2"} <= queued_ids
