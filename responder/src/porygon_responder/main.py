from __future__ import annotations

import asyncio
import logging
import json
import sqlite3
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any

import httpx
from docker.errors import DockerException
from fastapi import FastAPI, HTTPException, Request, status

from porygon_responder.config import get_settings
from porygon_responder.completions import CompletionStore
from porygon_responder.executor import ActionResult, DockerResponseExecutor

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("porygon.responder")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def heartbeat_loop(app: FastAPI) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/heartbeats"
    headers = {
        "X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()
    }
    timeout = httpx.Timeout(5.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            state: dict[str, Any] = app.state.responder_state
            payload = {
                "service_name": settings.service_name,
                "instance_id": settings.responder_instance_id,
                "status": "healthy" if state["docker_connected"] else "degraded",
                "observed_at": _now().isoformat(),
                "metadata": {
                    "version": settings.version,
                    "environment": settings.environment,
                    "capability": "containment-response",
                    "docker_connected": state["docker_connected"],
                    "last_claim_at": state["last_claim_at"],
                    "last_completion_at": state["last_completion_at"],
                    "executions_completed": state["executions_completed"],
                    "executions_failed": state["executions_failed"],
                    "pending_completions": state["pending_completions"],
                    "journal_worker_active": state["journal_worker_active"],
                },
            }
            try:
                response = await client.post(endpoint, headers=headers, json=payload)
                response.raise_for_status()
                state["backend_last_success_at"] = _now()
                state["backend_last_error"] = None
            except httpx.HTTPError as exc:
                state["backend_last_error"] = f"{exc.__class__.__name__}: {exc}"
                logger.warning("Responder heartbeat failed: %s", exc.__class__.__name__)
            await asyncio.sleep(settings.heartbeat_interval_seconds)


async def deliver_completions(
    client, store: CompletionStore, base: str, headers: dict, state: dict
) -> None:
    for row in store.pending():
        payload = json.loads(row["payload"])
        try:
            response = await client.post(
                f"{base}/internal/v1/response-executions/{row['execution_id']}/complete",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 409:
                current = await client.get(
                    f"{base}/api/v1/response-executions/{row['execution_id']}"
                )
                current.raise_for_status()
                document = current.json()
                field = (
                    "rollback_started_at"
                    if row["operation"] == "rollback"
                    else "started_at"
                )
                terminal = (
                    {"rolled_back", "rollback_failed"}
                    if row["operation"] == "rollback"
                    else {
                        "succeeded",
                        "failed",
                        "rollback_pending",
                        "rollback_claimed",
                        "rolled_back",
                        "rollback_failed",
                    }
                )
                if (
                    document.get(field) != row["started_at"]
                    or document.get("status") in terminal
                ):
                    store.acknowledge(row["operation_key"])
                    continue
            store.retry(row["operation_key"])
            state["backend_last_error"] = (
                "Completion delivery rejected; result retained"
            )
            continue
        except httpx.HTTPError:
            store.retry(row["operation_key"])
            state["backend_last_error"] = (
                "Completion delivery unavailable; result retained"
            )
            continue
        store.acknowledge(row["operation_key"])
        state["last_completion_at"] = _now().isoformat()
        state[
            "executions_completed" if payload["success"] else "executions_failed"
        ] += 1


async def response_loop(app: FastAPI) -> None:
    base = settings.api_base_url.rstrip("/")
    headers = {
        "X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()
    }
    executor = app.state.executor
    store: CompletionStore = app.state.completion_store
    state = app.state.responder_state
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=3.0)) as client:
        while True:
            try:
                if not store.acquire_worker():
                    state["journal_worker_active"] = False
                    await asyncio.sleep(settings.poll_seconds)
                    continue
                state["journal_worker_active"] = True
                await deliver_completions(client, store, base, headers, state)
                state["pending_completions"] = store.pending_count()
                if state["pending_completions"]:
                    await asyncio.sleep(settings.poll_seconds)
                    continue
                await asyncio.to_thread(executor.client.ping)
                state["docker_connected"] = True
                state["docker_last_error"] = None
                claim = await client.post(
                    f"{base}/internal/v1/response-executions/claim",
                    headers=headers,
                    json={
                        "executor_instance_id": settings.responder_instance_id,
                        "lease_seconds": settings.lease_seconds,
                    },
                )
                claim.raise_for_status()
                document = claim.json()
                execution, operation = (
                    document.get("execution"),
                    document.get("operation"),
                )
                if execution is None:
                    await asyncio.sleep(settings.poll_seconds)
                    continue
                state["last_claim_at"] = _now().isoformat()
                await process_claim(executor, store, execution, operation)
            except DockerException as exc:
                state["docker_connected"] = False
                state["docker_last_error"] = exc.__class__.__name__
                await asyncio.sleep(settings.poll_seconds)
            except (
                httpx.HTTPError,
                ValueError,
                KeyError,
                OSError,
                sqlite3.Error,
                RuntimeError,
            ) as exc:
                state["backend_last_error"] = (
                    f"Response processing failed: {exc.__class__.__name__}"
                )
                logger.warning("Response processing failed: %s", exc.__class__.__name__)
                await asyncio.sleep(settings.poll_seconds)


async def process_claim(
    executor, store: CompletionStore, execution: dict, operation: str
) -> None:
    key, previous = store.reserve(execution, operation)
    if previous is not None and previous["state"] == "completed":
        # Reclaimed lease, same operation generation: replay its receipt only.
        payload = json.loads(previous["payload"])
        payload["executor_instance_id"] = settings.responder_instance_id
        store.complete(key, payload)
        return
    if previous is not None:
        # A crash between durable intent and receipt leaves an uncertain outcome.
        # Never repeat that Docker operation without a fresh operator decision.
        result = ActionResult(
            False,
            {},
            {},
            {"verification": "outcome_unknown"},
            "executor_outcome_unknown",
            "Interrupted operation requires operator review",
        )
    else:
        try:
            result = await asyncio.to_thread(
                executor.execute,
                action_type=str(execution["action_type"]),
                target_container_id=execution.get("target_container_id"),
                operation=operation,
            )
        except Exception as exc:
            logger.exception("Unhandled responder executor failure")
            result = ActionResult(
                False,
                {},
                {},
                {"verification": "not_completed"},
                "executor_outcome_unknown",
                exc.__class__.__name__,
            )
    _, start = store.key(execution, operation)
    store.complete(
        key,
        {
            "executor_instance_id": settings.responder_instance_id,
            "operation": operation,
            "operation_started_at": start,
            "success": result.success,
            "pre_state": result.pre_state,
            "post_state": result.post_state,
            "result": result.result,
            "error_code": result.error_code,
            "error_message": result.error_message,
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    executor = DockerResponseExecutor(
        base_url=settings.docker_base_url,
        timeout_seconds=settings.docker_timeout_seconds,
        stop_timeout_seconds=settings.stop_timeout_seconds,
        protected_label=settings.protected_label,
    )
    app.state.executor = executor
    app.state.completion_store = CompletionStore(
        settings.completion_store_path, settings.completion_max_operations
    )
    app.state.responder_state = {
        "started_at": _now(),
        "journal_worker_active": False,
        "pending_completions": 0,
        "docker_connected": False,
        "docker_last_error": None,
        "backend_last_success_at": None,
        "backend_last_error": None,
        "last_claim_at": None,
        "last_completion_at": None,
        "executions_completed": 0,
        "executions_failed": 0,
    }
    heartbeat_task = asyncio.create_task(
        heartbeat_loop(app), name="responder-heartbeat"
    )
    response_task = asyncio.create_task(response_loop(app), name="responder-execution")
    try:
        yield
    finally:
        for task in (heartbeat_task, response_task):
            task.cancel()
        for task in (heartbeat_task, response_task):
            with suppress(asyncio.CancelledError):
                await task
        executor.client.close()
        app.state.completion_store.close()


app = FastAPI(
    title="Porygon Responder",
    version=settings.version,
    description="Executes only explicitly approved, typed Docker response actions.",
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
def health_live() -> dict[str, str]:
    return {"status": "ok", "service": "responder", "version": settings.version}


@app.get("/health/ready", tags=["health"])
def health_ready(request: Request) -> dict[str, object]:
    state: dict[str, Any] = request.app.state.responder_state
    if not state["docker_connected"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker Engine is unavailable",
        )
    last_backend = state["backend_last_success_at"]
    if last_backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No successful backend heartbeat yet",
        )
    age = (_now() - last_backend).total_seconds()
    if age > settings.heartbeat_interval_seconds * 3:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend heartbeat is stale",
        )
    return {
        "status": "ok",
        "service": "responder",
        "docker_connected": True,
        "last_claim_at": state["last_claim_at"],
        "last_completion_at": state["last_completion_at"],
    }


@app.get("/status", tags=["system"])
def responder_status(request: Request) -> dict[str, object]:
    state: dict[str, Any] = request.app.state.responder_state
    return {
        "service": settings.service_name,
        "instance_id": settings.responder_instance_id,
        "capability": "containment-response",
        **state,
    }
