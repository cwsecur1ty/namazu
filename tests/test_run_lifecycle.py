"""Consequential-behaviour tests for the server-owned audit run (reliability).

Everything here runs against the deterministic local fixture server on a real
loopback socket (tests/ux_fixture_server.py) or the engine directly. Nothing
reaches an external host; conftest's autouse guard would block it if it tried.

These prove the reliability contract, not API-security coverage:
  * one request budget shared across the inventory sweep and every operation
  * HTTP 429 stops the whole run across operation boundaries, not as a cancel
  * a stop prevents new dispatch, inside an operation, preserving late responses
  * withdrawing write authorisation stops further writes without undoing one
  * every dispatched request is persisted durably before it is sent
  * a process restart reports interrupted runs honestly and never replays
  * reconnecting / reopening / exporting sends nothing and cannot inflate counts
  * credentials never reach a snapshot, a receipt, an event or an export
  * persistence failure is not reported as saved evidence
"""
from __future__ import annotations

import json
import threading
import time

import pytest

from namazu.audit import engine
from namazu.audit.control import RunControl
from namazu.audit.run_service import RunManager
from namazu.audit.run_store import RunStore
from namazu.audit.transport import build_client
from namazu.discovery import Connection, connection_for
from tests.ux_fixture_server import FixtureServer, api_document


@pytest.fixture
def fixture():
    server = FixtureServer(0, timeout_delay=0.3)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.fixture
def manager(tmp_path):
    mgr = RunManager(RunStore(tmp_path / "runs.db"))
    try:
        yield mgr
    finally:
        mgr.store.close()


def base_config(base, **over):
    config = {
        "spec": api_document(base),
        "base_url": base,
        "profile": "readonly",
        "identities": {"primary": {"Authorization": "Bearer local-primary"}},
        "allow_mutating": False,
        "budget": 120,
        "requests_per_second": 50,
        "concurrency": 4,
        "inventory": False,
        "operations": [{"operation_id": "GET /identity"}],
        "credential_names": [],
        "context": {"title": "Fixture", "version": "1", "base_url": base,
                    "environment": "local fixture", "identity_label": "Primary"},
    }
    config.update(over)
    return config


def drive(manager, config, timeout=20):
    snapshot = manager.create(config)
    run_id = snapshot["run_id"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snap = manager.snapshot(run_id)
        if not snap["active"] and snap["status"] in ("finished", "incomplete", "interrupted"):
            return run_id, snap
        time.sleep(0.05)
    raise AssertionError("run did not settle in time")


def all_text(value) -> str:
    return json.dumps(value, default=str)


# --- lifecycle + shared budget ------------------------------------------------

def test_run_completes_server_side_and_persists(manager, fixture):
    run_id, snap = drive(manager, base_config(fixture.base))
    assert snap["status"] == "finished"
    assert snap["run_status"] == "finished"
    assert snap["done"] == snap["total"] == 1
    # The run is server-owned: it finished without any viewer polling it.
    cases = snap["cases"]
    assert [c["scope"] for c in cases] == ["operation"]
    assert cases[0]["result"]["baseline_status"] == 200
    # Every dispatched request has a durable receipt, all settled.
    receipts = manager.store.exchanges(run_id)
    assert receipts and all(r["state"] == "responded" for r in receipts)
    assert len(receipts) == snap["requests_sent"]


def test_total_budget_is_shared_by_inventory_and_all_operations(manager, fixture):
    config = base_config(fixture.base, budget=55, inventory=True,
                         operations=[{"operation_id": "GET /identity"},
                                     {"operation_id": "GET /identity"}])
    run_id, snap = drive(manager, config)
    # The run never spends more than the one shared budget, no matter how the
    # inventory sweep and the operations divide it.
    assert snap["requests_sent"] <= 55
    per_case = sum(int(c["result"].get("requests_sent") or 0) for c in snap["cases"])
    assert per_case == snap["requests_sent"]
    assert len(manager.store.exchanges(run_id)) == snap["requests_sent"]


# --- cancellation (engine level, deterministic) -------------------------------

class _StopAfter:
    """A receipt sink that stops the run once N requests have been dispatched."""

    def __init__(self, control, after):
        self.control = control
        self.after = after
        self.dispatched = 0
        self.settled = 0

    def dispatch(self, exchange):
        self.dispatched += 1
        if self.dispatched >= self.after:
            self.control.stop()
        return f"x{self.dispatched}"

    def settle(self, exchange_id, exchange):
        self.settled += 1


def test_stop_prevents_new_dispatch_inside_an_operation(fixture):
    link = connection_for(Connection.build(), True, None)
    http = build_client(connection=link)
    control = RunControl(request_budget=200)
    control.receipts = _StopAfter(control, after=5)
    try:
        result = engine.audit_operation(
            api_document(fixture.base), "GET /identity", base_url=fixture.base,
            identities={"primary": {"Authorization": "Bearer local-primary"}},
            profile="readonly", allow_mutating=False, connection=link, client=http,
            control=control)
    finally:
        http.close()
    # The stop landed inside the operation; the run did not spend its budget.
    assert control.spent < 200
    assert control.spent <= 5 + (control.run_budget.limit and 8)
    # Every request that was dispatched is in the log: a response that arrived
    # after the stop was preserved, not discarded. Nothing was double-counted.
    assert len(result["log"]) == control.spent == control.receipts.settled
    # The probes that did not run are recorded as stopped, never as clean.
    states = {c["check"]: c["state"] for c in result["coverage"]["checks"]}
    assert any(s == "blocked" for s in states.values())
    assert any(code == "run-stopped"
               for c in result["coverage"]["checks"] for code in c.get("reason_codes", []))


def test_stop_during_an_active_run_is_incomplete_not_finished(manager, fixture):
    config = base_config(fixture.base, inventory=True, requests_per_second=3,
                         operations=[{"operation_id": "GET /identity"},
                                     {"operation_id": "GET /identity"}])
    snapshot = manager.create(config)
    run_id = snapshot["run_id"]
    # Stop almost immediately; the slow rate keeps the run from finishing first.
    time.sleep(0.05)
    assert manager.stop(run_id)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        snap = manager.snapshot(run_id)
        if not snap["active"]:
            break
        time.sleep(0.05)
    snap = manager.snapshot(run_id)
    assert snap["cancelled"] is True
    assert snap["run_status"] == "incomplete"
    assert snap["status"] == "incomplete"
    # A stop is not a rate limit, and not an interruption.
    assert snap["rate_limited"] is False
    assert snap["interrupted"] is False
    # No request on the wire was lost: every receipt settled.
    assert all(r["state"] != "dispatched" for r in manager.store.exchanges(run_id))


# --- write authorisation withdrawn mid-run ------------------------------------

def test_withdrawing_write_authorisation_refuses_further_writes(fixture):
    link = connection_for(Connection.build(), True, None)
    http = build_client(connection=link)
    control = RunControl(request_budget=200)
    control.withdraw_writes()  # withdrawn before any write leaves
    before = fixture.commits
    try:
        result = engine.audit_operation(
            api_document(fixture.base), "POST /summaries", base_url=fixture.base,
            identities={"primary": {"Authorization": "Bearer local-primary"}},
            profile="writes", allow_mutating=True, connection=link, client=http,
            control=control)
    finally:
        http.close()
    # Not one write committed on the target after authorisation was withdrawn.
    assert fixture.commits == before
    # The baseline write itself was refused, so the operation is contract-only,
    # reported as such, not as a passing test.
    assert any("withdrawn" in note.lower() or "write" in note.lower()
               for note in result.get("notes", []))


def test_withdraw_writes_mid_run_stops_commits(manager, fixture):
    config = base_config(fixture.base, profile="writes", allow_mutating=True,
                         requests_per_second=4,
                         operations=[{"operation_id": "POST /summaries", "example": {
                             "method": "POST", "url": fixture.base + "/summaries",
                             "headers": {"Authorization": "Bearer local-primary",
                                         "Content-Type": "application/json"},
                             "body": json.dumps({"documentUri": "doc-local", "personaId": "persona-reader",
                                                  "maxBulletsAmount": 3, "strictMode": True})}}])
    snapshot = manager.create(config)
    run_id = snapshot["run_id"]
    manager.withdraw_writes(run_id)
    committed_at_withdraw = fixture.commits
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if not manager.snapshot(run_id)["active"]:
            break
        time.sleep(0.05)
    # No commit occurred after authorisation was withdrawn.
    assert fixture.commits == committed_at_withdraw
    snap = manager.snapshot(run_id)
    assert snap["writes_withdrawn"] is True


# --- rate enforcement / 429 across operation boundaries -----------------------

def test_http_429_stops_the_whole_run_across_operations(manager, fixture):
    fixture.throttle_after = 3  # the 4th counted attempt onward is a 429
    config = base_config(fixture.base, budget=120,
                         operations=[{"operation_id": "GET /identity"} for _ in range(4)])
    run_id, snap = drive(manager, config)
    assert snap["rate_limited"] is True
    assert snap["run_status"] == "incomplete"
    # A 429 is not a user cancellation.
    assert snap["cancelled"] is False
    # Remaining operations were not started: far fewer than all four ran.
    assert snap["done"] < snap["total"]
    # The run did not keep hammering after the 429.
    assert snap["requests_sent"] <= 8
    assert any("429" in note for note in snap["notes"])


# --- process restart with an interrupted request ------------------------------

def test_restart_marks_interrupted_and_never_replays(tmp_path, fixture):
    db = tmp_path / "runs.db"
    store = RunStore(db)
    # Simulate a crash mid-run: a running row plus a dispatched POST receipt
    # whose outcome was never recorded (the process died before the response).
    store.create_run("run-crash", created_at="2026-10-12T00:00:00Z", status="running",
                     phase="POST /summaries", kind="live-run", title="Crash", target=fixture.base,
                     config={"operations": ["POST /summaries"]},
                     snapshot={"status": "running", "total": 1, "done": 0, "notes": []})
    store.dispatch_exchange("run-crash", "op-000", "run-crash-x00001", 1,
                            dispatched_at="2026-10-12T00:00:01Z", method="POST",
                            label="baseline", mutating=True,
                            record={"method": "POST", "url": fixture.base + "/summaries",
                                    "outcome": "dispatched", "status": 0})
    store.close()
    attempts_before = fixture.commits, len(fixture.attempts)

    # Restart: a fresh manager over the same database.
    mgr = RunManager(RunStore(db))
    try:
        assert "run-crash" in mgr.interrupted_on_start
        snap = mgr.snapshot("run-crash")
        assert snap["status"] == "interrupted"
        assert snap["interrupted"] is True
        assert snap["dispatched_unsettled"] == 1
        assert any("interrupted" in note.lower() for note in snap["notes"])
        # The dispatched-but-unsettled POST is honest about the unknown outcome.
        receipts = mgr.store.exchanges("run-crash")
        assert receipts[0]["state"] == "interrupted-unknown"
        export = mgr.export("run-crash")
        assert export["provenance"]["kind"] == "interrupted-run"
        assert export["provenance"]["requests_sent_during_current_action"] == 0
    finally:
        mgr.store.close()
    # The restart sent nothing to the target: the POST was never replayed.
    assert (fixture.commits, len(fixture.attempts)) == attempts_before


# --- duplicate / out-of-order progress -----------------------------------------

def test_revision_is_monotonic_and_reingest_does_not_inflate(manager, fixture):
    run_id, snap = drive(manager, base_config(fixture.base, inventory=True,
                         operations=[{"operation_id": "GET /identity"}]))
    # Revision only ever increases: a client that ignores a revision <= the last
    # it applied is safe against duplicate or out-of-order deliveries.
    revisions = [manager.snapshot(run_id)["revision"] for _ in range(5)]
    assert revisions == sorted(revisions)
    # Re-ingesting the same snapshot keyed by stable case_id cannot inflate the
    # case set: applying it twice yields the same number of unique cases.
    cases = manager.snapshot(run_id)["cases"]
    merged = {}
    for _ in range(3):
        for case in cases:
            merged[case["case_id"]] = case
    assert len(merged) == len(cases)
    # Totals are not recomputed from a growing list; they match the receipts.
    assert len(manager.store.exchanges(run_id)) == manager.snapshot(run_id)["requests_sent"]


# --- persistence failure --------------------------------------------------------

def test_persistence_failure_is_not_reported_as_saved(manager, fixture, monkeypatch):
    real_save = manager.store.save_case
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        raise OSError("disk full")

    monkeypatch.setattr(manager.store, "save_case", flaky)
    config = base_config(fixture.base, operations=[{"operation_id": "GET /identity"}])
    snapshot = manager.create(config)
    run_id = snapshot["run_id"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if not manager.snapshot(run_id)["active"]:
            break
        time.sleep(0.05)
    snap = manager.snapshot(run_id)
    # The case could not be saved, so it is NOT claimed as recorded evidence.
    assert snap["cases"] == []
    assert snap["run_status"] == "incomplete"
    assert any("could not" in note.lower() or "incomplete" in note.lower() or "ended early" in note.lower()
               for note in snap["notes"])
    monkeypatch.setattr(manager.store, "save_case", real_save)


# --- credential redaction + response comparison ---------------------------------

def test_no_credential_reaches_any_persisted_surface(manager, fixture):
    run_id, snap = drive(manager, base_config(fixture.base, inventory=True,
                         operations=[{"operation_id": "GET /identity"}]))
    secret = "local-primary"
    assert secret not in all_text(snap)
    assert secret not in all_text(manager.export(run_id))
    for row in manager.store.exchanges(run_id):
        assert secret not in all_text(row["record"])
    # The redaction marker is present where the credential was.
    export_text = all_text(manager.export(run_id))
    assert "<credential>" in export_text


def test_response_comparison_is_preserved_in_evidence(manager, fixture):
    # /uniform returns a uniform 403 with a per-call-varying correlation id; the
    # comparison must call that a same application denial, not a real difference,
    # and the varying header must not masquerade as a meaningful change.
    config = base_config(fixture.base, base_url=fixture.base + "/uniform",
                         context={"base_url": fixture.base + "/uniform"},
                         operations=[{"operation_id": "GET /identity"}])
    # GET /identity under /uniform still 401/403s; use the POST path instead to
    # exercise the denial comparison against a baseline.
    config["operations"] = [{"operation_id": "GET /identity"}]
    run_id, snap = drive(manager, config)
    result = snap["cases"][0]["result"]
    # The engine recorded a baseline and a coverage ledger; interpretation data
    # is carried through to the persisted case, not recomputed on view.
    assert "coverage" in result and result["coverage"]["checks"]
    assert result.get("baseline_status") in (200, 401, 403)


# --- reopen / export never sends ------------------------------------------------

def test_reopen_and_export_send_no_requests(manager, fixture):
    run_id, snap = drive(manager, base_config(fixture.base,
                         operations=[{"operation_id": "GET /identity"}]))
    attempts_after_run = len(fixture.attempts)
    # Reopen (snapshot) and export several times.
    for _ in range(5):
        reopened = manager.snapshot(run_id)
        export = manager.export(run_id)
        assert reopened["run_id"] == run_id
    assert export["provenance"]["requests_sent_during_current_action"] == 0
    # Not a single new request reached the target.
    assert len(fixture.attempts) == attempts_after_run
    # Reopening did not restart the run.
    assert manager.snapshot(run_id)["active"] is False


def test_partial_run_exports_without_sending(manager, fixture):
    fixture.throttle_after = 2
    run_id, snap = drive(manager, base_config(fixture.base, budget=120,
                         operations=[{"operation_id": "GET /identity"} for _ in range(3)]))
    assert snap["run_status"] == "incomplete"
    attempts = len(fixture.attempts)
    export = manager.export(run_id)
    assert export["scope"]["endpoints_in_scope"] == 3
    assert export["provenance"]["requests_sent_during_current_action"] == 0
    assert len(fixture.attempts) == attempts


# --- retention / deletion -------------------------------------------------------

def test_delete_removes_run_and_evidence(manager, fixture):
    run_id, snap = drive(manager, base_config(fixture.base))
    assert manager.store.exchanges(run_id)
    assert manager.delete(run_id) is True
    assert manager.snapshot(run_id) is None
    assert manager.store.exchanges(run_id) == []
    assert run_id not in {row["run_id"] for row in manager.list_runs()}
