"""Coalesced, bounded repair outside ingestion transactions.

Pending evidence rows are the durable work inventory: restart loses only a wake
hint, never the rows. A transaction-scoped leader lock coordinates API replicas.
"""

import logging
from threading import Event, Lock, Thread
from datetime import datetime, timezone
from sqlalchemy import func, select, text

logger = logging.getLogger("porygon.reconciliation")
LOCK_ID = 728164093


class IdentityReconciliationWorker:
    def __init__(
        self, session_factory, process_repair, kernel_repair, *, interval=5, batch_size=500
    ):
        self.session_factory = session_factory
        self.process_repair = process_repair
        self.kernel_repair = kernel_repair
        self.interval = interval
        self.batch_size = batch_size
        self.wake = Event()
        self.stopping = Event()
        self.lock = Lock()
        self.thread = None
        self.state = {
            "running": False,
            "last_success_at": None,
            "last_error": None,
            "process_repaired": 0,
            "kernel_repaired": 0,
        }

    def snapshot(self):
        with self.lock:
            return dict(self.state)

    def notify(self):
        self.wake.set()

    def start(self):
        self.thread = Thread(target=self.run, name="porygon-identity-reconciliation", daemon=True)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.wake.set()
        if self.thread is not None:
            self.thread.join(timeout=15)

    def run_once(self):
        with self.session_factory() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(text("SET LOCAL lock_timeout='2s'"))
                db.execute(text("SET LOCAL statement_timeout='10s'"))
                if not db.scalar(select(func.pg_try_advisory_xact_lock(LOCK_ID))):
                    db.rollback()
                    return False
            process = self.process_repair(db, self.batch_size)
            kernel = self.kernel_repair(db, self.batch_size)
            db.commit()
        with self.lock:
            self.state.update(
                last_success_at=datetime.now(timezone.utc).isoformat(), last_error=None
            )
            self.state["process_repaired"] += process
            self.state["kernel_repaired"] += kernel
        return True

    def run(self):
        with self.lock:
            self.state["running"] = True
        try:
            while not self.stopping.is_set():
                self.wake.wait(self.interval)
                self.wake.clear()
                if self.stopping.is_set():
                    break
                try:
                    self.run_once()
                except Exception as exc:
                    # Do not log statement parameters, event contents, or credentials.
                    logger.warning("Identity repair deferred: %s", exc.__class__.__name__)
                    with self.lock:
                        self.state["last_error"] = exc.__class__.__name__
        finally:
            with self.lock:
                self.state["running"] = False
