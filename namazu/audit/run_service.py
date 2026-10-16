"""The server-owned audit run: one lifecycle, bound once, surviving the browser.

A run is created from a plan the operator has already reviewed in the browser
(scope, target, identity references, profile, write authorisation, budget and
rate). Creating it binds those; changing any of them is a new review and a new
run. The server then executes the run on its own background thread, so closing
or reloading the page does not touch it.

The run owns exactly one of each shared thing: httpx client, request budget,
pacer, stop signal, write gate: via :class:`~namazu.audit.control.RunControl`,
and persists every request durably through :class:`~namazu.audit.run_store`
*before* it is sent. It reuses the existing engine (``audit_inventory`` /
``audit_operation``) unchanged for all interpretation; this module only
sequences the operations, shares the one budget/pacer/stop across them, and
records progress honestly.

Credentials live only here, in the run thread's memory, never in the store, a
log line, an event or an export. A process restart therefore cannot resume a
run: it can only report it as interrupted and require the operator to set it up
and authorise it again.
"""
from __future__ import annotations

import contextlib
import threading
import uuid
from datetime import datetime, timezone

from ..discovery import connection_for
from ..runner import credential_names_for
from .control import RunControl
from .engine import audit_inventory, audit_operation
from .run_store import RunStore
from .transport import build_client

# How the run thread tells which operations are out of scope for writes before
# it even starts: mirrors the engine's own SAFE_METHODS.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RunReceipts:
    """The receipt sink an :class:`Executor` calls around every dispatch.

    One per run, shared across its worker threads. ``current_case`` is set by
    the run thread before each operation so a receipt is filed under the right
    case. Sequence numbers are monotonic across the whole run, giving every
    request a stable, run-unique id.
    """

    def __init__(self, store: RunStore, run_id: str) -> None:
        self._store = store
        self._run_id = run_id
        self._seq = 0
        self._lock = threading.Lock()
        self.current_case = "run"
        self.current_context: dict = {}
        self.redact = None

    def _record(self, exchange):
        record = {**exchange.to_dict(), **self.current_context}
        return self.redact(record) if self.redact is not None else record

    def dispatch(self, exchange) -> str:
        with self._lock:
            self._seq += 1
            seq = self._seq
        exchange_id = f"{self._run_id[:8]}-x{seq:05d}"
        self._store.dispatch_exchange(
            self._run_id, self.current_case, exchange_id, seq,
            dispatched_at=_now(), method=exchange.method, label=exchange.label,
            mutating=bool(exchange.mutating), record=self._record(exchange))
        return exchange_id

    def settle(self, exchange_id: str, exchange) -> None:
        if not exchange_id:
            return
        self._store.settle_exchange(
            self._run_id, exchange_id, settled_at=_now(),
            outcome=exchange.outcome or "responded", record=self._record(exchange))


class RunManager:
    """Holds the store and the in-process threads for active runs."""

    def __init__(self, store: RunStore | None = None) -> None:
        self.store = store or RunStore()
        self._controls: dict[str, RunControl] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        # On startup, any run left running was interrupted by the previous
        # process ending. Record that honestly; never resume or replay it.
        self.interrupted_on_start = self.store.mark_interrupted_on_start()

    # -- creation ---------------------------------------------------------

    def create(self, config: dict) -> dict:
        operations = config.get("operations") or []
        if not operations:
            raise ValueError("A run needs at least one reviewed operation.")
        profile = config.get("profile") or "readonly"
        allow_mutating = bool(config.get("allow_mutating"))
        if profile == "writes" and not allow_mutating and not config.get("workspace"):
            raise ValueError("The writes profile needs write authorisation; authorise the reviewed plan first.")
        budget = int(config.get("budget") or 0)
        if budget < 1:
            raise ValueError("Set a request budget for the run.")
        if config.get("workspace"):
            from .workspace_execution import validate_config
            validate_config(config)

        run_id = uuid.uuid4().hex
        rate = config.get("requests_per_second")
        receipts = RunReceipts(self.store, run_id)
        if config.get("workspace"):
            from .workspace_execution import redact_run_value
            receipts.redact = lambda value: redact_run_value(value, config)
        control = RunControl(request_budget=budget, requests_per_second=rate,
                             write_authorized=True, receipts=receipts)

        context = dict(config.get("context") or {})
        created = _now()
        total = len(operations)
        stored_config = self._redacted_config(config)
        snapshot = self._initial_snapshot(run_id, config, context, created, total, control)
        if config.get("workspace"):
            context = snapshot["context"]
        target = context.get("base_url") or config.get("base_url") or ""
        self.store.create_run(
            run_id, created_at=created, status="starting", phase="starting",
            kind="live-run", title=str(context.get("title") or ""), target=str(target),
            config=stored_config, snapshot=snapshot)

        with self._lock:
            self._controls[run_id] = control
        thread = threading.Thread(target=self._execute, args=(run_id, config, control, receipts),
                                  name=f"namazu-run-{run_id[:8]}", daemon=True)
        with self._lock:
            self._threads[run_id] = thread
        thread.start()
        return snapshot

    # -- execution (on the run thread) ------------------------------------

    def _execute(self, run_id: str, config: dict, control: RunControl, receipts: RunReceipts) -> None:
        if config.get("workspace"):
            from .workspace_execution import execute_workspace
            execute_workspace(self, run_id, config, control, receipts)
            return
        operations = config.get("operations") or []
        profile = config.get("profile") or "readonly"
        allow_mutating = bool(config.get("allow_mutating"))
        spec = config.get("spec") or {}
        base_url = config.get("base_url")
        identities = config.get("identities") or {}
        timeout = float(config.get("timeout") or 15.0)
        concurrency = config.get("concurrency")
        rate = config.get("requests_per_second")
        response_comparison = config.get("response_comparison")
        credential_names = config.get("credential_names") or []
        inventory_planned = bool(config.get("inventory"))
        link = connection_for(self._connection(config),
                              bool(config.get("verify_tls", True)), config.get("user_agent"))
        http = build_client(connection=link)
        shared = dict(base_url=base_url, identities=identities, profile=profile,
                      allow_mutating=allow_mutating, timeout=timeout, concurrency=concurrency,
                      connection=link, requests_per_second=rate,
                      credential_names=credential_names, response_comparison=response_comparison,
                      client=http, control=control)

        done = 0
        stop_reason = ""
        try:
            self._set_status(run_id, "running", "starting", control)
            if inventory_planned and not control.cancelled and control.remaining > 0:
                receipts.current_case = "inventory"
                self._set_status(run_id, "running", "inventory", control)
                inv_budget = min(60, max(1, control.remaining))
                try:
                    result = audit_inventory(spec, base_url=base_url, identities=identities,
                                             timeout=timeout, budget=inv_budget, connection=link,
                                             concurrency=concurrency, requests_per_second=rate,
                                             credential_names=credential_names, client=http,
                                             control=control)
                except Exception as exc:
                    result = {"scope": "inventory", "error": f"{type(exc).__name__}",
                              "notes": [f"The inventory sweep could not run: {type(exc).__name__}."]}
                self._save_case(run_id, "inventory", 0, "surface sweep", "inventory", result, control)

            for index, item in enumerate(operations):
                if control.cancelled:
                    stop_reason = "cancelled"
                    break
                if control.rate_limited:
                    stop_reason = "rate-limited"
                    break
                if control.remaining <= 0:
                    stop_reason = "budget"
                    break
                operation_id = item.get("operation_id") or item.get("operationId") or ""
                case_id = f"op-{index:03d}"
                receipts.current_case = case_id
                self._set_status(run_id, "running", operation_id, control)
                try:
                    result = audit_operation(
                        spec, operation_id, example=item.get("example"),
                        expectation=item.get("expectation"), **shared)
                except Exception as exc:
                    result = {"endpoint": operation_id, "operation_id": operation_id,
                              "error": f"{type(exc).__name__}",
                              "notes": [f"This operation could not be audited: {type(exc).__name__}."]}
                self._save_case(run_id, case_id, index + 1, operation_id, "operation", result, control)
                done += 1
        except BaseException as exc:
            stop_reason = stop_reason or f"error:{type(exc).__name__}"
        finally:
            with contextlib.suppress(Exception):
                http.close()
            self._finalise(run_id, config, control, done, stop_reason)
            with self._lock:
                self._threads.pop(run_id, None)
                self._controls.pop(run_id, None)

    # -- controls ---------------------------------------------------------

    def stop(self, run_id: str) -> bool:
        with self._lock:
            control = self._controls.get(run_id)
        if control is None:
            return False
        control.stop()
        return True

    def withdraw_writes(self, run_id: str) -> bool:
        with self._lock:
            control = self._controls.get(run_id)
        if control is None:
            return False
        control.withdraw_writes()
        # Record the withdrawal immediately so a poll sees it even before the
        # current operation's next dispatch is refused.
        run = self.store.get_run(run_id)
        if run and run.get("snapshot"):
            snapshot = run["snapshot"]
            snapshot["writes_withdrawn"] = True
            snapshot.setdefault("notes", []).append(
                "Write authorisation was withdrawn. No further state-changing request will be "
                "dispatched; requests already sent are not recalled.")
            self.store.update_run(run_id, updated_at=_now(), snapshot=snapshot)
        return True

    def is_active(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._controls

    def is_stopping(self, run_id: str) -> bool:
        with self._lock:
            control = self._controls.get(run_id)
            return bool(control and control.cancelled)

    # -- reads ------------------------------------------------------------

    def snapshot(self, run_id: str) -> dict | None:
        run = self.store.get_run(run_id)
        if run is None:
            return None
        snapshot = run.get("snapshot") or {}
        snapshot = dict(snapshot)
        snapshot["run_id"] = run_id
        snapshot["revision"] = run.get("revision", 0)
        snapshot["status"] = run.get("status")
        snapshot["kind"] = run.get("kind")
        snapshot["interrupted"] = bool(run.get("interrupted"))
        snapshot["active"] = self.is_active(run_id)
        snapshot["cases"] = [
            {"case_id": row["case_id"], "scope": row["scope"], "operation": row["operation"],
             "status": row["status"], "result": row["result"]}
            for row in self.store.cases(run_id)]
        if run.get("status") == "interrupted" or run.get("interrupted"):
            unsettled = self.store.dispatched_unsettled(run_id)
            snapshot["dispatched_unsettled"] = unsettled
            note = ("This run was interrupted when the application stopped. "
                    + (f"{unsettled} request(s) had been dispatched with no recorded outcome; "
                       "whether the server processed them is unknown and they were not re-sent. "
                       if unsettled else "")
                    + "Partial evidence is retained. Set up and authorise a new run to continue.")
            if note not in snapshot.get("notes", []):
                snapshot.setdefault("notes", []).append(note)
            snapshot["run_status"] = "interrupted"
        return snapshot

    def list_runs(self) -> list[dict]:
        rows = self.store.list_runs()
        for row in rows:
            row["interrupted"] = bool(row.get("interrupted"))
            row["active"] = self.is_active(row["run_id"])
        return rows

    def delete(self, run_id: str) -> bool:
        if self.is_active(run_id):
            self.stop(run_id)
        return self.store.delete_run(run_id)

    def delete_all(self) -> int:
        with self._lock:
            active = list(self._controls.values())
        for control in active:
            control.stop()
        return self.store.delete_all()

    def export(self, run_id: str) -> dict | None:
        """The import/assess/download-shaped record, rebuilt from retained cases."""
        run = self.store.get_run(run_id)
        if run is None:
            return None
        return self._build_export(run)

    # -- internals --------------------------------------------------------

    def _connection(self, config: dict):
        from ..discovery import Connection
        return Connection.build(
            verify_tls=bool(config.get("verify_tls", True)), user_agent=config.get("user_agent"),
            quiet=bool(config.get("quiet")), proxy=config.get("proxy"),
            ca_bundle=config.get("ca_bundle"), client_cert=config.get("client_cert"),
            client_key=config.get("client_key"), client_key_password=config.get("client_key_password"))

    def _redacted_config(self, config: dict) -> dict:
        """The stored plan carries identity NAMES and settings, never secrets."""
        if config.get("workspace"):
            from .workspace_execution import stored_config
            return stored_config(config)
        return {
            "profile": config.get("profile"),
            "allow_mutating": bool(config.get("allow_mutating")),
            "budget": config.get("budget"),
            "requests_per_second": config.get("requests_per_second"),
            "concurrency": config.get("concurrency"),
            "timeout": config.get("timeout"),
            "inventory": bool(config.get("inventory")),
            "operations": [str(item.get("operation_id") or item.get("operationId") or "")
                           for item in (config.get("operations") or [])],
            "identity_names": sorted(credential_names_for({}, config.get("credential_names") or [])),
            "second_identity": bool((config.get("identities") or {}).get("secondary")),
            "response_comparison": config.get("response_comparison"),
        }

    def _context(self, config: dict) -> dict:
        context = dict(config.get("context") or {})
        context.setdefault("profile", config.get("profile"))
        context.setdefault("budget", config.get("budget"))
        context.setdefault("rate", config.get("requests_per_second"))
        context.setdefault("concurrency", config.get("concurrency"))
        # The persisted context never carries a raw credential; redact the URL.
        from .model import redact_url
        if context.get("base_url"):
            context["base_url"] = redact_url(str(context["base_url"]))
        return context

    def _initial_snapshot(self, run_id, config, context, created, total, control) -> dict:
        snapshot = {
            "run_id": run_id, "revision": 1, "status": "starting", "phase": "starting",
            "kind": "live-run", "run_status": "running", "cancelled": False,
            "rate_limited": False, "writes_withdrawn": False, "interrupted": False,
            "started_at": created, "finished_at": None,
            "total": total, "done": 0, "inventory_planned": bool(config.get("inventory")),
            "requests_sent": 0, "budget": control.limit, "remaining": control.remaining,
            "notes": [], "cases": [], "context": self._context(config),
        }
        if config.get("workspace"):
            from .workspace_execution import redact_run_value, safe_workspace
            snapshot["workspace"] = safe_workspace(config)
            snapshot["context"] = redact_run_value(snapshot["context"], config)
            snapshot["contract_assessments"] = 0
            snapshot["reused_assessments"] = 0
            snapshot["overlap_exclusions"] = 0
        return snapshot

    def _set_status(self, run_id, status, phase, control) -> None:
        run = self.store.get_run(run_id)
        snapshot = dict(run.get("snapshot") or {}) if run else {}
        snapshot["phase"] = phase
        snapshot["requests_sent"] = self._request_count(run_id, snapshot, control)
        snapshot["remaining"] = control.remaining
        snapshot["cancelled"] = control.cancelled
        snapshot["rate_limited"] = control.rate_limited
        snapshot["writes_withdrawn"] = control.writes_withdrawn
        self.store.update_run(run_id, updated_at=_now(), status=status, phase=phase, snapshot=snapshot)

    def _save_case(self, run_id, case_id, seq, operation, scope, result, control) -> None:
        status = "error" if result.get("error") else "recorded"
        self.store.save_case(run_id, case_id, seq, operation=operation, scope=scope,
                             status=status, updated_at=_now(), result=result)
        run = self.store.get_run(run_id)
        snapshot = dict(run.get("snapshot") or {}) if run else {}
        snapshot["requests_sent"] = self._request_count(run_id, snapshot, control)
        snapshot["remaining"] = control.remaining
        snapshot["cancelled"] = control.cancelled
        snapshot["rate_limited"] = control.rate_limited
        snapshot["writes_withdrawn"] = control.writes_withdrawn
        if scope == "operation":
            snapshot["done"] = int(snapshot.get("done", 0)) + 1
            if snapshot.get("workspace"):
                field = ("overlap_exclusions" if result.get("assessment_status") == "excluded"
                         else "contract_assessments")
                snapshot[field] = int(snapshot.get(field, 0)) + 1
                if result.get("evidence_reused"):
                    snapshot["reused_assessments"] = int(snapshot.get("reused_assessments", 0)) + 1
        self.store.update_run(run_id, updated_at=_now(), snapshot=snapshot)

    def _finalise(self, run_id, config, control, done, stop_reason) -> None:
        run = self.store.get_run(run_id)
        snapshot = dict(run.get("snapshot") or {}) if run else {}
        total = int(snapshot.get("total", 0))
        finished = _now()
        snapshot["finished_at"] = finished
        snapshot["requests_sent"] = self._request_count(run_id, snapshot, control)
        snapshot["remaining"] = control.remaining
        snapshot["cancelled"] = control.cancelled
        snapshot["rate_limited"] = control.rate_limited
        snapshot["writes_withdrawn"] = control.writes_withdrawn
        snapshot["phase"] = None
        notes = snapshot.setdefault("notes", [])
        if control.cancelled:
            notes.append("The run was stopped. No further operations were started; the evidence "
                         "captured before the stop is retained.")
        if control.rate_limited:
            notes.append("The target returned HTTP 429. The run stopped at the observed rate limit; "
                         "remaining operations were not started. Partial evidence is retained.")
        if stop_reason == "budget":
            notes.append("The run-wide request budget was exhausted. Remaining operations were not started.")
        if stop_reason.startswith("error:"):
            notes.append(f"The run ended early: {stop_reason.split(':', 1)[1]}. Its accounting may be incomplete.")
        completed = control.cancelled is False and control.rate_limited is False \
            and not stop_reason and done >= total
        run_status = "finished" if completed else "incomplete"
        snapshot["run_status"] = run_status
        status = "finished" if completed else "incomplete"
        export = self._build_export({**run, "snapshot": snapshot}) if run else None
        self.store.update_run(run_id, updated_at=finished, status=status, phase=None,
                              snapshot=snapshot, export=export)

    def _request_count(self, run_id, snapshot, control):
        # A budget reservation whose durable receipt failed never reached the
        # wire. Workspace accounting is the retained unique dispatch ledger.
        return len(self.store.exchanges(run_id)) if snapshot.get("workspace") else control.spent

    def _build_export(self, run: dict) -> dict:
        """Assemble an export-shaped record from retained cases, no traffic."""
        if (run.get("config") or {}).get("workspace"):
            from .workspace_execution import build_export
            return build_export(run, self.store.cases(run["run_id"]), self.store.exchanges(run["run_id"]))
        snapshot = run.get("snapshot") or {}
        config = run.get("config") or {}
        context = snapshot.get("context") or {}
        cases = self.store.cases(run["run_id"])
        operations = [row for row in cases if row["scope"] == "operation"]
        inventory = next((row for row in cases if row["scope"] == "inventory"), None)
        findings: list = []
        requests: list = []
        test_plans: list = []
        contract_snapshots: dict = {}
        notes: list = list(snapshot.get("notes") or [])
        requests_sent = 0
        for row in ([inventory] if inventory else []) + operations:
            result = row.get("result") or {}
            findings.extend(result.get("findings") or [])
            requests.extend(result.get("log") or [])
            requests_sent += int(result.get("requests_sent") or 0)
            if result.get("test_plan"):
                test_plans.append(result["test_plan"])
            snap = result.get("contract_snapshot")
            if snap and result.get("operation_id"):
                contract_snapshots[result["operation_id"]] = snap
        interrupted = bool(run.get("interrupted")) or run.get("status") == "interrupted"
        kind = "interrupted-run" if interrupted else "live-run"
        return {
            "application": "Namazu", "export": "security-audit",
            "exported_at": snapshot.get("finished_at") or snapshot.get("started_at"),
            "started_at": snapshot.get("started_at"),
            "run": {"status": snapshot.get("run_status"),
                    "cancelled": bool(snapshot.get("cancelled")),
                    "rate_limited": bool(snapshot.get("rate_limited")),
                    "writes_withdrawn": bool(snapshot.get("writes_withdrawn")),
                    "interrupted": interrupted,
                    "finished_at": snapshot.get("finished_at"),
                    "environment": context.get("environment"),
                    "identity_label": context.get("identity_label")},
            "provenance": {"kind": kind, "requests_sent_during_current_action": 0,
                           "source_run": {"target": run.get("target"),
                                          "environment": context.get("environment"),
                                          "started_at": snapshot.get("started_at"),
                                          "status": snapshot.get("run_status")}},
            "api": {"title": context.get("title"), "version": context.get("version"),
                    "base_url": context.get("base_url")},
            "scope": {"profile": config.get("profile"),
                      "endpoints_audited": len(operations),
                      "endpoints_in_scope": int(snapshot.get("total", len(operations))),
                      "requests_sent": requests_sent,
                      "request_budget": snapshot.get("budget"),
                      "inventory_planned": bool(snapshot.get("inventory_planned")),
                      "second_identity": bool(config.get("second_identity"))},
            "contract_snapshots": contract_snapshots,
            "test_plans": test_plans,
            "requests": requests,
            "findings": findings,
            "notes": notes,
            "response_comparison": config.get("response_comparison"),
        }


_MANAGER: RunManager | None = None
_MANAGER_LOCK = threading.Lock()


def manager() -> RunManager:
    """The process-wide run manager, created on first use."""
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = RunManager()
        return _MANAGER


def set_manager(instance: RunManager | None) -> None:
    """Install a manager (tests point this at an isolated store)."""
    global _MANAGER
    with _MANAGER_LOCK:
        _MANAGER = instance
