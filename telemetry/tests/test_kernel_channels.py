import asyncio
from datetime import datetime, timezone
import json
import sqlite3

import httpx
import pytest

from porygon_telemetry.main import deliver_events
from porygon_telemetry.normalizer import normalize_falco_event
from porygon_telemetry.spool import TelemetryStore, SpoolFullError
from porygon_telemetry.state import TelemetryState
from test_normalizer import _raw_event

RULE = "Porygon Container Process Execution"


def raw(kind="net_outbound"):
    event = _raw_event()
    event["rule"] = {
        "net_outbound": "Porygon Container Outbound Connection",
        "memfd_create": "Porygon Container Memory Backed File",
        "file_write_open": "Porygon Container Sensitive Write Open",
        "file_write": "Porygon Container Sensitive File Write",
    }[kind]
    event["output_fields"].update(
        {
            "evt.type": {
                "net_outbound": "connect",
                "memfd_create": "memfd_create",
                "file_write_open": "openat",
                "file_write": "write",
            }[kind],
            "evt.rawres": 1,
            "fd.rip": "192.0.2.10",
            "fd.rport": 443,
            "fd.lip": "172.20.0.2",
            "fd.lport": 39000,
            "fd.name": "/etc/porygon-test",
            "evt.arg.name": "porygon-test-memory",
        }
    )
    return event


def normalized(event):
    return normalize_falco_event(
        event, sensor_instance_id="sensor", expected_rule=RULE, reported_docker_host_id="host"
    )


@pytest.mark.parametrize("kind", ["net_outbound", "memfd_create", "file_write_open", "file_write"])
def test_runtime_families_have_separate_stable_identities(kind):
    payload = normalized(raw(kind))
    assert payload["_event_channel"] == "kernel"
    assert payload["runtime_action"] == kind
    assert payload == normalized(raw(kind))
    assert payload["event_id"] != normalized(_raw_event())["event_id"]
    assert "parent_event_id" not in payload


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"]
)
def test_loopback_and_unspecified_peers_are_not_outbound_evidence(address):
    event = raw()
    event["output_fields"]["fd.rip"] = address
    assert normalized(event) is None


def test_nonblocking_connect_is_observed_as_in_progress_not_success():
    event = raw()
    event["output_fields"]["evt.rawres"] = -115
    assert normalized(event)["return_value"] == -115
    event["output_fields"]["evt.rawres"] = -111
    assert normalized(event) is None


def test_failed_or_zero_byte_writes_are_not_positive_write_evidence():
    event = raw("file_write")
    for value in (0, -1):
        event["output_fields"]["evt.rawres"] = value
        assert normalized(event) is None


def test_exec_rule_cannot_smuggle_other_syscalls_into_the_historical_stream():
    event = _raw_event()
    event["output_fields"]["evt.type"] = "connect"
    with pytest.raises(ValueError, match="other syscalls"):
        normalized(event)


def test_mixed_checkpoint_rollback_and_fair_delivery_survive_store_reopen(tmp_path):
    path = str(tmp_path / "outbox.db")
    store = TelemetryStore(path, 100)
    process = normalized(_raw_event())
    kernel = normalized(raw())
    for index in range(20):
        store.enqueue({**kernel, "event_id": f"{index:064x}"})
    store.enqueue(process)
    reopened = TelemetryStore(path, 100)
    selected = reopened.fetch_fair_due(2)
    assert {event.get("_event_channel", "process") for event in selected} == {"process", "kernel"}
    assert len(reopened.fetch_fair_due(50)) == 21
    full = TelemetryStore(str(tmp_path / "full.db"), 1)
    with pytest.raises(SpoolFullError):
        full.enqueue_batch([process, kernel], inode=2, offset=100)
    assert full.count() == 0 and full.get_file_cursor()[1] == 0


def test_legacy_spool_schema_upgrades_without_rewriting_exec_payloads(tmp_path):
    path = str(tmp_path / "old.db")
    payload = normalized(_raw_event())
    encoded = json.dumps(payload)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE outbox(event_id TEXT PRIMARY KEY,payload TEXT NOT NULL,enqueued_at REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at REAL NOT NULL DEFAULT 0,last_error TEXT)"
        )
        db.execute(
            "INSERT INTO outbox(event_id,payload,enqueued_at) VALUES(?,?,0)",
            (payload["event_id"], encoded),
        )
    store = TelemetryStore(path, 100)
    assert store.fetch_fair_due(1) == [payload]
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT payload,channel FROM outbox").fetchone() == (encoded, "process")


def test_one_failed_channel_does_not_repeat_or_drop_the_acknowledged_channel(tmp_path):
    store = TelemetryStore(str(tmp_path / "outbox.db"), 100)
    process, kernel = normalized(_raw_event()), normalized(raw())
    store.enqueue_batch([process, kernel], inode=1, offset=200)
    state = TelemetryState(started_at=datetime.now(timezone.utc))
    calls = []

    def transport(request):
        body = json.loads(request.content)
        calls.append((request.url.path, body))
        assert all("_event_channel" not in event for event in body["events"])
        if "kernel-events" in request.url.path:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"received": len(body["events"])})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            await deliver_events(client, state, store, store.fetch_fair_due(100))

    asyncio.run(run())
    assert state.process_events_delivered == 1 and state.kernel_events_delivered == 0
    assert store.count() == 1
    with store._connect() as db:
        assert db.execute("SELECT event_id FROM outbox").fetchone()[0] == kernel["event_id"]
        db.execute("UPDATE outbox SET next_attempt_at=0")
    assert store.get_file_cursor() == (1, 200)


@pytest.mark.parametrize('container_id', ['system.slice', 'user.slice', 'kubepods', 'host'])
def test_non_docker_cgroups_are_outside_the_kernel_evidence_scope(container_id):
    event = raw()
    event['output_fields']['container.id'] = container_id
    assert normalized(event) is None
