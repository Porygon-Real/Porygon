import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from porygon_responder.completions import CompletionStore
from porygon_responder.executor import ActionResult
from porygon_responder.main import deliver_completions, process_claim


def claim(start="2026-10-26T00:00:00Z"):
    return dict(
        execution_id="execution",
        started_at=start,
        action_type="pause_container",
        target_container_id="a" * 64,
    )


def test_saved_receipt_survives_restart_and_reclaim_without_docker(tmp_path):
    path = str(tmp_path / "receipt.db")
    executor = SimpleNamespace(
        execute=Mock(return_value=ActionResult(True, {}, {}, {"paused": True}))
    )
    store = CompletionStore(path)
    asyncio.run(process_claim(executor, store, claim(), "execute"))
    reopened = CompletionStore(path)
    asyncio.run(process_claim(executor, reopened, claim(), "execute"))
    assert executor.execute.call_count == 1
    assert json.loads(reopened.pending()[0]["payload"])["success"] is True
    asyncio.run(
        process_claim(executor, reopened, claim("2026-10-26T00:01:00Z"), "execute")
    )
    assert executor.execute.call_count == 2


def test_crash_after_intent_does_not_repeat_unknown_action(tmp_path):
    store = CompletionStore(str(tmp_path / "receipt.db"))
    store.reserve(claim(), "execute")
    executor = SimpleNamespace(execute=Mock())
    asyncio.run(process_claim(executor, store, claim(), "execute"))
    executor.execute.assert_not_called()
    payload = json.loads(store.pending()[0]["payload"])
    assert payload["error_code"] == "executor_outcome_unknown"
    assert payload["success"] is False


def test_lost_completion_ack_retains_result_and_retries(tmp_path):
    store = CompletionStore(str(tmp_path / "receipt.db"))
    executor = SimpleNamespace(
        execute=Mock(return_value=ActionResult(True, {}, {}, {}))
    )
    asyncio.run(process_claim(executor, store, claim(), "execute"))
    key = store.pending()[0]["operation_key"]
    state = dict(executions_completed=0, executions_failed=0)
    calls = []

    def failed(request):
        calls.append(json.loads(request.content))
        raise httpx.ReadError("lost ack", request=request)

    async def deliver(transport):
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport)
        ) as client:
            await deliver_completions(client, store, "http://backend", {}, state)

    asyncio.run(deliver(failed))
    assert store.pending_count() == 1
    assert store.pending() == []  # bounded retry backoff
    with store.connect() as db:
        db.execute("UPDATE operations SET next_attempt_at=0")

    def success(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={})

    asyncio.run(deliver(success))
    assert calls[0] == calls[1]
    assert store.pending_count() == 0
    assert state["executions_completed"] == 1
    # Receipt remains available even after acknowledgement.
    assert store.reserve(claim(), "execute")[1]["acknowledged"] == 1
    assert executor.execute.call_count == 1
    assert key


def test_single_worker_and_full_pending_journal_fail_closed(tmp_path):
    path = str(tmp_path / "receipt.db")
    first, second = CompletionStore(path, 1), CompletionStore(path, 1)
    assert first.acquire_worker()
    assert not second.acquire_worker()
    first.close()
    assert second.acquire_worker()
    second.close()
    first.reserve(claim(), "execute")
    with pytest.raises(RuntimeError, match="full"):
        first.reserve(claim("different-generation"), "execute")
