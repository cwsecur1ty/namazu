"""Deterministic local MockTransport boundaries, not API security coverage."""
from __future__ import annotations

import copy
import json
import threading
import time

import httpx
import pytest

from namazu.audit import workspace_execution
from namazu.audit.run_service import RunManager
from namazu.audit.run_store import RunStore
from namazu.audit.transport import Budget, Cancelled, Executor, MutationRefused


def document(target="https://api.localhost/v1", *, schema_type="string", method="get"):
    return {"openapi": "3.0.3", "info": {"title": "Local fixture", "version": "1"},
            "servers": [{"url": target}], "paths": {"/items": {method: {
                "operationId": "sameOperation", "responses": {"200": {"description": "ok",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}}}}},
            "components": {"schemas": {"Item": {"type": "object", "properties": {"value": {"type": schema_type}}}}}}


def operation(cid, *, target="https://api.localhost/v1", identity="shared", token="local-shared-secret", **over):
    item = {"contract_id": cid, "operation_key": f"{cid}::GET /items", "operation_id": "GET /items",
            "snapshot_hash": f"hash-{cid}", "spec": document(target), "base_url": target,
            "identities": {"primary": {"Authorization": f"Bearer {token}"}} if identity else {},
            "identity_ref": identity, "identity_revision": 1 if identity else None,
            "identity_source": "shared profile" if identity else "no identity configured",
            "allowed_scopes": [target] if identity else [], "allow_mutating": False}
    item.update(over)
    return item


def configuration(*operations, **over):
    config = {"workspace": {"id": "workspace-local", "title": "Local workspace", "revision": 1,
                            "contracts": [{"id": cid, "content_hash": f"hash-{cid}"}
                                          for cid in dict.fromkeys(item["contract_id"] for item in operations)],
                            "assignments": {}, "overlap_decisions": [], "reviewed_plan": {"id": "plan-local"}},
              "operations": list(operations), "profile": "passive", "budget": 20,
              "inventory": False, "concurrency": 1}
    config.update(over)
    return config


@pytest.fixture
def local_run(monkeypatch, tmp_path):
    seen = []
    manager = RunManager(RunStore(tmp_path / "workspace-runs.db"))

    def default_response(request):
        seen.append(request)
        return httpx.Response(200, json={"value": "local", "echo": request.headers.get("authorization", "")})

    handler = [default_response]
    monkeypatch.setattr(workspace_execution, "build_client", lambda **_: httpx.Client(
        transport=httpx.MockTransport(lambda request: handler[0](request))))
    yield manager, seen, handler
    for run in manager.list_runs():
        manager.stop(run["run_id"])
    for thread in list(manager._threads.values()):
        thread.join(5)
    manager.store.close()


def finish(manager, config):
    created = manager.create(config)
    return await_finished(manager, created["run_id"])


def await_finished(manager, run_id):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        snapshot = manager.snapshot(run_id)
        if not snapshot["active"]:
            return snapshot, manager.export(run_id)
        time.sleep(0.005)
    raise AssertionError("Local workspace run did not finish")


def test_contract_namespaces_shared_identity_override_and_unassigned_target(local_run):
    manager, seen, _ = local_run
    first = operation("a", target="https://one.localhost/v1", assertions=[
        {"pointer": "/value", "operator": "equals", "expected": "local"}])
    second = operation("b", target="https://two.localhost/v2", assertions=[
        {"pointer": "/value", "operator": "equals", "expected": "different"}])
    third = operation("c", target="https://three.localhost/api", identity=None)
    fourth = operation("d", target="https://four.localhost/api", identity="override", token="local-override-secret",
                       identity_source="contract-specific override", spec=document("https://four.localhost/api", schema_type="integer"))
    snapshot, exported = finish(manager, configuration(first, second, third, fourth))
    assert snapshot["status"] == "finished"
    assert [item.headers.get("authorization") for item in seen] == [
        "Bearer local-shared-secret", "Bearer local-shared-secret", None, "Bearer local-override-secret"]
    results = [case["result"] for case in snapshot["cases"]]
    assert [result["contract_id"] for result in results] == ["a", "b", "c", "d"]
    assert results[0]["baseline_outcome"] == "success"
    assert results[1]["baseline_outcome"] != "success"
    assert results[0]["contract_snapshot"]["document"]["components"]["schemas"]["Item"]["properties"]["value"]["type"] == "string"
    assert results[3]["contract_snapshot"]["document"]["components"]["schemas"]["Item"]["properties"]["value"]["type"] == "integer"
    assert set(exported["contract_snapshots"]) == {item["operation_key"] for item in (first, second, third, fourth)}
    text = json.dumps([snapshot, exported, manager.store.get_run(snapshot["run_id"]), manager.store.exchanges(snapshot["run_id"])])
    assert "local-shared-secret" not in text and "local-override-secret" not in text
    assert len(seen) == exported["scope"]["unique_network_attempts"] == 4


def test_reviewed_identical_reuse_counts_one_attempt_with_two_assessments(local_run):
    manager, seen, _ = local_run
    first, second = operation("a"), operation("b", reuse_from="a::GET /items")
    snapshot, exported = finish(manager, configuration(first, second, budget=1))
    assert snapshot["status"] == "finished"
    assert snapshot["requests_sent"] == len(seen) == len(exported["requests"]) == 1
    assert exported["scope"]["contract_assessments"] == 2
    assert exported["scope"]["reused_assessments"] == 1
    a, b = exported["assessments"]
    assert a["evidence_refs"] == b["evidence_refs"] and a["evidence_refs"]
    assert a["requests_sent"] == 1 and b["requests_sent"] == 0 and b["log"] == []
    assert all(len(finding["assessment_links"]) == 2 for finding in exported["findings"])
    assert manager.export(snapshot["run_id"]) == exported
    assert len(seen) == 1


@pytest.mark.parametrize("change", [
    {"example": {"url": "https://api.localhost/v1/items?value=different"}},
    {"identity_ref": "different-identity"},
    {"identity_revision": 2},
    {"identities": {"primary": {"Authorization": "Bearer another-local-token"}}},
    {"assertions": [{"pointer": "/value", "expected": "local"}]},
    {"example": {"content_type": "application/problem+json", "body": "{}"}},
    {"allow_mutating": True},
])
def test_distinct_inputs_identities_assertions_and_write_context_never_reused(local_run, change):
    manager, seen, _ = local_run
    snapshot, exported = finish(manager, configuration(operation("a"), operation("b", reuse_from="a::GET /items", **change)))
    assert snapshot["requests_sent"] == len(seen) == 2
    assert exported["scope"]["reused_assessments"] == 0


def test_separate_overlap_decision_and_exclusion_are_honest(local_run):
    manager, seen, _ = local_run
    _, exported = finish(manager, configuration(operation("a"), operation("b"), operation("c", excluded=True)))
    assert len(seen) == 2
    assert exported["scope"]["overlap_exclusions"] == 1
    excluded = exported["assessments"][2]
    assert excluded["assessment_status"] == "excluded" and not excluded["evidence_refs"]
    assert excluded["requests_sent"] == 0


def test_redirect_is_one_attempt_and_never_forwards_shared_bearer(local_run):
    manager, seen, handler = local_run

    def redirect(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://unassigned.localhost/stolen"})

    handler[0] = redirect
    snapshot, exported = finish(manager, configuration(operation("a")))
    assert len(seen) == snapshot["requests_sent"] == 1
    assert str(seen[0].url).startswith("https://api.localhost/v1/")
    assert exported["requests"][0]["status"] == 302


@pytest.mark.parametrize("url", [
    "https://api.localhost/v10/items", "https://api.localhost/docs", "https://other.localhost/v1/items",
    "https://api.localhost/v1/%2e%2e/docs", "https://api.localhost/v1/%252e%252e/docs",
])
def test_scope_refusal_never_charges_a_network_attempt(url):
    seen = []
    raw = httpx.Client(transport=httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200)))
    client = workspace_execution.ScopedClient(raw, "https://api.localhost/v1", ["https://api.localhost/v1"])
    budget = Budget(2)
    executor = Executor(client, budget)
    with pytest.raises(MutationRefused):
        executor.send("GET", url, label="scope", headers={"Authorization": "Bearer local-only"})
    assert not seen and budget.spent == 0
    raw.close()


def test_scope_assignment_required_before_run_creation(local_run):
    manager, seen, _ = local_run
    with pytest.raises(ValueError, match="scope assignment"):
        manager.create(configuration(operation("a", allowed_scopes=["https://api.localhost/v2"])))
    assert not seen and not manager.list_runs()


def test_contract_and_run_budget_caps_are_shared(local_run):
    manager, seen, _ = local_run
    first = operation("a")
    another = operation("a", operation_key="a::GET /more", operation_id="GET /more")
    another["spec"]["paths"]["/more"] = another["spec"]["paths"].pop("/items")
    snapshot, exported = finish(manager, configuration(first, another, operation("b"), operation("c"),
                                                       budget=2, per_contract_limits={"a": 1}))
    assert len(seen) == snapshot["requests_sent"] == len(exported["requests"]) == 2
    assert snapshot["contract_requests"] == {"a": 1, "b": 1}
    assert snapshot["status"] == "incomplete"
    assert exported["assessments"][1]["assessment_status"] == "budget-excluded"


def test_per_contract_write_authorization_is_not_shared(local_run):
    manager, seen, _ = local_run
    first = operation("a", operation_key="a::POST /items", operation_id="POST /items",
                      spec=document(method="post"), allow_mutating=True, request_budget=1)
    second = operation("b", operation_key="b::POST /items", operation_id="POST /items",
                       spec=document(method="post"), request_budget=1)
    _, exported = finish(manager, configuration(first, second, profile="writes"))
    assert len(seen) == 1 and seen[0].method == "POST"
    assert exported["assessments"][1]["requests_sent"] == 0


def test_cancel_preserves_inflight_evidence_and_stops_next_contract(local_run):
    manager, seen, handler = local_run
    entered, released = threading.Event(), threading.Event()

    def response(request):
        seen.append(request)
        entered.set()
        assert released.wait(5)
        return httpx.Response(200, json={"value": "local"})

    handler[0] = response
    created = manager.create(configuration(operation("a"), operation("b")))
    assert entered.wait(5)
    assert manager.stop(created["run_id"])
    released.set()
    snapshot, exported = await_finished(manager, created["run_id"])
    assert snapshot["cancelled"] and snapshot["status"] == "incomplete"
    assert snapshot["requests_sent"] == len(seen) == len(exported["requests"]) == 1
    assert exported["requests"][0]["status"] == 200


def test_429_stops_whole_workspace(local_run):
    manager, seen, handler = local_run
    handler[0] = lambda request: seen.append(request) or httpx.Response(429, json={"error": "rate limited"})
    snapshot, exported = finish(manager, configuration(operation("a"), operation("b")))
    assert snapshot["rate_limited"] and snapshot["status"] == "incomplete"
    assert len(seen) == len(exported["requests"]) == 1


def test_revoked_assignment_stops_further_dispatch_in_running_workspace(local_run):
    manager, seen, handler = local_run
    valid = [True]

    def response(request):
        seen.append(request)
        valid[0] = False
        return httpx.Response(200, json={"value": "local"})

    handler[0] = response
    first = operation("a", scope_guard=lambda: valid[0])
    second = operation("b", scope_guard=lambda: valid[0])
    snapshot, exported = finish(manager, configuration(first, second))
    assert len(seen) == len(exported["requests"]) == snapshot["requests_sent"] == 1
    assert exported["assessments"][1]["requests_sent"] == 0


def test_export_json_roundtrip_retains_boundaries_and_no_secrets(local_run):
    manager, seen, _ = local_run
    _, exported = finish(manager, configuration(operation("a"), operation("b", reuse_from="a::GET /items")))
    retained = json.loads(json.dumps(exported))
    assert retained == exported
    assert len(retained["contracts"]) == 2
    assert {item["snapshot_hash"] for item in retained["assessments"]} == {"hash-a", "hash-b"}
    assert retained["workspace"]["reviewed_plan"] == {"id": "plan-local"}
    assert len(seen) == 1


def test_inventory_uses_shared_budget_and_never_carries_contract_identity(local_run):
    manager, seen, _ = local_run
    snapshot, exported = finish(manager, configuration(operation("a"), inventory=True, budget=3))
    assert len(seen) == snapshot["requests_sent"] == len(exported["requests"]) == 3
    assert all("authorization" not in request.headers for request in seen)
    assert exported["scope"]["inventory_requests"] == 3
    assert all(item["identity_ref"] is None for item in exported["requests"])


def test_receipts_redact_other_contracts_credentials_in_response_text(local_run):
    manager, seen, handler = local_run

    def response(request):
        seen.append(request)
        return httpx.Response(200, json={"value": "local", "debug": "local-override-secret"})

    handler[0] = response
    snapshot, exported = finish(manager, configuration(operation("a"),
        operation("b", identity="override", token="local-override-secret")))
    retained = json.dumps([exported, manager.store.exchanges(snapshot["run_id"]), manager.store.get_run(snapshot["run_id"])])
    assert "local-override-secret" not in retained and "local-shared-secret" not in retained


def test_stale_assignment_never_reuses_previous_contract_assessment(local_run):
    manager, seen, handler = local_run
    current = [True]

    def response(request):
        seen.append(request)
        current[0] = False
        return httpx.Response(200, json={"value": "local"})

    handler[0] = response
    _, exported = finish(manager, configuration(operation("a"),
        operation("b", reuse_from="a::GET /items", scope_guard=lambda: current[0])))
    second = exported["assessments"][1]
    assert not second["evidence_reused"] and second["assessment_status"] == "stale-plan"
    assert not second["evidence_refs"] and len(seen) == 1


def test_distinct_findings_on_different_fields_are_retained():
    metadata = {"contract_id": "a", "operation_key": "a::GET /items", "snapshot_hash": "hash-a",
                "target": "https://api.localhost/v1", "identity_ref": None, "identity_revision": None}
    result = {**metadata, "operation_id": "GET /items", "findings": [
        {"id": "same-rule", "title": "Same finding", "endpoint": "GET /items", "parameter": "one"},
        {"id": "same-rule", "title": "Same finding", "endpoint": "GET /items", "parameter": "two"}]}
    run = {"config": {"workspace": {"id": "w", "contracts": [{"id": "a"}]}}, "snapshot": {}}
    exported = workspace_execution.build_export(run, [{"case_id": "a", "scope": "operation", "result": result}], [])
    assert len(exported["findings"]) == 2


def test_failed_dispatch_receipt_is_not_counted_as_a_network_attempt(local_run, monkeypatch):
    manager, seen, _ = local_run

    def fail(*args, **kwargs):
        raise OSError("local fixture persistence failure")

    monkeypatch.setattr(manager.store, "dispatch_exchange", fail)
    snapshot, exported = finish(manager, configuration(operation("a")))
    assert not seen
    assert snapshot["requests_sent"] == exported["scope"]["unique_network_attempts"] == 0
    assert exported["assessments"][0]["error"] == "OSError"


def test_different_media_order_changes_request_and_never_reuses(local_run):
    manager, seen, _ = local_run
    first = operation("a", operation_key="a::POST /items", operation_id="POST /items",
                      spec=document(method="post"), allow_mutating=True, request_budget=1)
    first["spec"]["paths"]["/items"]["post"]["requestBody"] = {
        "required": True, "content": {
            "application/first+json": {"schema": {"type": "string", "example": "local"}},
            "application/second+json": {"schema": {"type": "string", "example": "local"}}}}
    second = copy.deepcopy(first)
    second.update(contract_id="b", operation_key="b::POST /items", snapshot_hash="hash-b", reuse_from=first["operation_key"])
    content = second["spec"]["paths"]["/items"]["post"]["requestBody"]["content"]
    second["spec"]["paths"]["/items"]["post"]["requestBody"]["content"] = dict(reversed(list(content.items())))
    snapshot, exported = finish(manager, configuration(first, second, profile="writes"))
    assert len(seen) == snapshot["requests_sent"] == 2
    assert seen[0].headers["content-type"] != seen[1].headers["content-type"]
    assert exported["scope"]["reused_assessments"] == 0


def test_cancellation_during_workspace_scope_guard_never_dispatches():
    entered, release, cancel = threading.Event(), threading.Event(), threading.Event()
    seen, failures = [], []

    def guard():
        entered.set()
        assert release.wait(5)
        return True

    raw = httpx.Client(transport=httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200)))
    scoped = workspace_execution.ScopedClient(raw, "https://api.localhost", scope_guard=guard)
    budget = Budget(1)
    executor = Executor(scoped, budget, cancel=cancel)

    def dispatch():
        try:
            executor.send("GET", "https://api.localhost/items", label="blocked guard")
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=dispatch)
    worker.start()
    assert entered.wait(5)
    cancel.set()
    release.set()
    worker.join(5)
    raw.close()
    assert not worker.is_alive()
    assert len(failures) == 1 and isinstance(failures[0], Cancelled)
    assert not seen and budget.spent == 0


def test_unselected_document_operations_never_replace_selected_contract(local_run):
    manager, seen, _ = local_run
    first, second = operation("a"), operation("b")
    second["spec"] = copy.deepcopy(first["spec"])
    second["spec"]["components"]["schemas"]["Item"]["properties"]["value"]["type"] = "integer"
    _, exported = finish(manager, configuration(first, second))
    assert len(seen) == 2
    assert len(exported["contract_snapshots"]) == 2
