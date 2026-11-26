"""Opt-in, bounded maintenance with one database transaction per tick."""

from __future__ import annotations

import logging
import threading
from typing import Callable

from sqlalchemy import select, func, text
from sqlalchemy.orm import Session

from porygon_api.config import Settings
from porygon_api.retention import apply_retention

logger = logging.getLogger("porygon.retention")
_RETENTION_LOCK = 728164092


class RetentionWorker:
    def __init__(self, settings: Settings, session_factory: Callable[[], Session]) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="porygon-retention", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=15)

    def run_once(self) -> bool:
        """Prune one batch only while holding the cross-worker transaction lock.

        The database session is never kept during the scheduling interval. The
        first scheduled tick is delayed, so startup does not delete evidence.
        """
        with self.session_factory() as db:
            db.execute(text("SET LOCAL lock_timeout = '2s'"))
            db.execute(text("SET LOCAL statement_timeout = '10s'"))
            if not db.scalar(select(func.pg_try_advisory_xact_lock(_RETENTION_LOCK))):
                db.rollback()
                return False
            result = apply_retention(
                db,
                retention_days=self.settings.raw_event_retention_days,
                max_delete_batch=self.settings.retention_max_delete_batch,
                dry_run=False,
            )
            db.commit()
            logger.info(
                "Retention batch completed: process=%d runtime=%d kernel=%d cutoff=%s",
                result.process_exec_events_deleted,
                result.runtime_events_deleted,
                result.kernel_runtime_events_deleted,
                result.cutoff.isoformat(),
            )
            return True

    def _run(self) -> None:
        while not self.stop_event.wait(self.settings.retention_interval_seconds):
            try:
                self.run_once()
            except Exception:
                # Session context rollback/close releases the transaction lock.
                # Keep the worker alive for the next interval after an outage.
                logger.exception("Retention batch failed; retrying at the next interval")
