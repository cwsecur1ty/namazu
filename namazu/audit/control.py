"""Run-wide execution control: one budget, one pacer, one stop, one write gate.

A server-owned run binds its reviewed operations to a single :class:`RunControl`
and passes it to every :func:`~namazu.audit.engine.audit_operation` and
:func:`~namazu.audit.engine.audit_inventory` call. That is what turns a batch of
independent per-operation audits into one run:

* **One request budget.** Each operation (and the inventory sweep) gets its own
  per-operation ceiling as a *child* of the run budget, so an operation keeps
  its own limit while the run total holds across every operation and every
  concurrent worker. No single operation can reset or overshoot the run total.

* **One pacer.** The rate limit, and the HTTP 429 kill-switch, are shared, so a
  429 seen in any operation stops dispatch everywhere after it.

* **One stop signal.** Setting it refuses the next dispatch anywhere in the run,
  including inside an operation that is part-way through its probes. A request
  already on the wire is never abandoned; its response is still captured.

* **One write gate.** Withdrawing write authorisation mid-run refuses every
  further state-changing request from that point, without stopping the read-only
  work.

Everything here is thread-safe because a single operation already fans its
probes out across worker threads over exactly these shared objects.
"""
from __future__ import annotations

import threading

from .transport import Budget, Pace


class RunControl:
    """The shared execution state of one server-owned run."""

    def __init__(self, *, request_budget: int, requests_per_second: float | None = None,
                 write_authorized: bool = True, receipts: object | None = None) -> None:
        self.run_budget = Budget(request_budget)
        self.cancel = threading.Event()
        self.write_withdrawn = threading.Event()
        if not write_authorized:
            self.write_withdrawn.set()
        # The pacer carries the stop event so a probe waiting out the rate
        # interval abandons the wait promptly when the run is stopped.
        self.pace = Pace(requests_per_second, cancel=self.cancel)
        self.receipts = receipts

    def per_operation_budget(self, limit: int) -> Budget:
        """A per-operation budget chained to the one run-wide budget."""
        return Budget(limit, parent=self.run_budget)

    def stop(self) -> None:
        self.cancel.set()

    def withdraw_writes(self) -> None:
        self.write_withdrawn.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    @property
    def writes_withdrawn(self) -> bool:
        return self.write_withdrawn.is_set()

    @property
    def rate_limited(self) -> bool:
        return self.pace.stopped

    @property
    def spent(self) -> int:
        return self.run_budget.spent

    @property
    def remaining(self) -> int:
        return self.run_budget.remaining

    @property
    def limit(self) -> int:
        return self.run_budget.limit
