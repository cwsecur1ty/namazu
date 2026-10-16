"""Explicit OOB preparation and imported mock callbacks, never a live service."""
from __future__ import annotations

import copy
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from namazu import desktop_requests, oob_routes, workspaces
from namazu.audit import oob
from namazu.workspaces import WorkspaceService

NOW = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)


def document():
    return {"openapi": "3.0.3", "info": {"title": "Local callback fixture", "version": "1"},
            "servers": [{"url": "http://api.localhost/v1"}],
            "paths": {"/deliver": {"post": {"operationId": "same", "requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "properties": {"callback": {"type": "string"}}}}}},
                "responses": {"200": {"description": "Local accepted"}}}}}}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    workspace_service = WorkspaceService(tmp_path / "workspaces.db")
    workspace = workspace_service.create("local OOB")
    workspace = workspace_service.import_contracts(workspace["id"], [{"raw_spec": json.dumps(document())}, {"raw_spec": json.dumps(document())}])
    workspace_service.set_profile(workspace["id"], {"id": "reader", "token": "local-secret-for-masking"})
    workspace = workspace_service.assign_identity(workspace["id"], workspace["contracts"][0]["id"], {
        "profile_id": "reader", "allowed_scopes": ["http://api.localhost/v1"]})
    monkeypatch.setattr(workspaces, "_SERVICE", workspace_service)
    attempted, callbacks = [], []
    def target(request):
        attempted.append(request)
        value = json.loads(request.content)["callback"]
        host = httpx.URL(value).host
        marker, session = host.split(".")[:2]
        for protocol in ("dns", "http"):
            callbacks.append({"protocol": protocol, "unique-id": session, "full-id": marker + "." + session,
                              "timestamp": (NOW + timedelta(seconds=2)).isoformat(), "remote-address": "127.0.0.1",
                              "raw-request": "GET / HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer local-secret-for-masking\r\n\r\n",
                              "raw-response": '<script>never executed</script> local-secret-for-masking'})
        return httpx.Response(200, json={"accepted": True})
    manager = desktop_requests.RequestManager(tmp_path / "requests.db", client_factory=lambda: httpx.Client(transport=httpx.MockTransport(target)))
    service = oob.OOBService(tmp_path / "oob.db", workspace_service=workspace_service, request_manager=manager, clock=lambda: NOW)
    yield service, workspace_service, workspace, manager, attempted, callbacks
    manager.stop_all()
    service._db.close()
    manager._db.close()
    workspace_service._conn.close()


def data(workspace, index=0, **changes):
    contract = workspace["contracts"][index]
    return {"workspace_id": workspace["id"], "contract_id": contract["id"], "snapshot_hash": contract["hash"],
            "operation_key": contract["operations"][0]["id"], "callback_base": "https://session123.callback.localhost",
            "callback_scope_confirmed": True, "field": {"location": "body", "pointer": "/callback"}, **changes}


def event(case, **changes):
    return {"protocol": "dns", "unique-id": "session123", "full-id": case["correlation_full_id"],
            "timestamp": (NOW + timedelta(seconds=1)).isoformat(), "remote-address": "127.0.0.1", **changes}


def wait(manager, rid):
    for _ in range(300):
        result = manager.get(rid)
        if result["status"] not in {"pending", "running", "stopping"}:
            return result
        time.sleep(0.01)
    raise AssertionError("Local mock request did not finish")


def test_preparation_is_offline_persistent_scoped_and_does_not_grant_writes(setup):
    service, ws, workspace, manager, attempted, _ = setup
    before = ws.get(workspace["id"])
    case = service.create(data(workspace))
    assert case["status"] == "prepared" and case["requests_sent"] == 0
    assert case["context"]["identity_ref"] == "reader" and case["context"]["identity_revision"] == 1
    assert case["context_current"] and case["can_use_payload"]
    assert not case["execution"]["write_authorized"] and not case["execution"]["automatic_polling"]
    assert not attempted and not manager.list()
    assert ws.get(workspace["id"]) == before
    restored = oob.OOBService(service.path, workspace_service=ws, clock=lambda: NOW)
    assert restored.get(case["id"]) == case
    restored._db.close()


@pytest.mark.parametrize("changes", [
    {"callback_scope_confirmed": False}, {"callback_base": "https://user:secret@callback.localhost"},
    {"callback_base": "https://callback.localhost/?secret=1"}, {"callback_base": "https://callback.localhost/#fragment"},
    {"callback_base": "file:///tmp/callback"}, {"callback_base": "http://127.0.0.1"},
    {"callback_base": "https://callback.localhost/path"}, {"snapshot_hash": "old"},
    {"field": {"location": "header", "name": "Authorization"}}, {"field": {"location": "header", "name": "Host"}},
    {"field": {"location": "body", "pointer": "/password"}}, {"field": {"location": "body", "pointer": "/__proto__/callback"}},
    {"field": {"location": "query", "name": "access_token"}}, {"ttl_seconds": 0},
])
def test_unsafe_or_unreviewed_case_preparation_is_rejected(setup, changes):
    service, _, workspace, _, attempted, _ = setup
    with pytest.raises(ValueError):
        service.create(data(workspace, **changes))
    assert not attempted and not service.list()


def test_mock_dispatch_receipt_link_and_exact_callback_accounting(setup):
    service, _, workspace, manager, attempted, callbacks = setup
    case = service.create(data(workspace))
    request = {key: data(workspace)[key] for key in ("workspace_id", "contract_id", "snapshot_hash", "operation_key")}
    request.update(request={"body": {"callback": case["payload"]}}, allow_mutating=True)
    result = wait(manager, manager.start(request)["request_id"])
    assert result["status"] == "completed" and result["requests_sent"] == len(attempted) == 1
    linked = service.attach_receipt(case["id"], result["request_id"])
    assert linked["status"] == "payload-submitted"
    assert service.attach_receipt(case["id"], result["request_id"])["accounting"]["linked_existing_attempts"] == 1
    imported = service.import_interactions(case["id"], "\n".join(json.dumps(item) for item in [*callbacks, callbacks[0]]))
    assert imported["import"]["matched"] == 2 and imported["import"]["duplicates"] == 1
    assert imported["case"]["accounting"] == {"linked_existing_attempts": 1, "imported_interactions": 2,
                                               "unmatched_interactions": 0, "new_target_requests": 0, "demonstrated_vulnerabilities": 0}
    assert len(attempted) == 1
    for row in imported["case"]["interactions"]:
        assert row["verification"] == "imported-unverified" and row["attribution"] == "not-established"
        assert row["security_impact"] == "not-established" and row["source"]["line"]
        assert row["redacted"] and row["source"]["raw_source_hash"] == imported["import"]["source_hash"]
        assert not row["source"]["raw_source_retained"]
        assert row["content_hash_basis"] == "original-canonical-json"
    exported = json.dumps(service.export(case["id"]))
    assert "local-secret-for-masking" not in exported
    assert "<script>never executed</script>" in exported


def test_same_operation_ids_across_contracts_and_session_only_events_do_not_cross_correlate(setup):
    service, _, workspace, _, _, _ = setup
    a, b = service.create(data(workspace)), service.create(data(workspace, 1))
    assert a["marker"] != b["marker"] and a["context"]["contract_id"] != b["context"]["contract_id"]
    payload = "\n".join(json.dumps(item) for item in [event(a), event(a, **{"full-id": "session123"}),
        event(a, **{"full-id": "unrelated", "raw-response": a["payload"]}), event(a, **{"full-id": a["correlation_full_id"] + ".evil"})])
    imported_a = service.import_interactions(a["id"], payload)
    imported_b = service.import_interactions(b["id"], payload)
    assert imported_a["import"]["matched"] == 1 and imported_a["import"]["unmatched"] == 3
    assert imported_b["import"]["matched"] == 0 and imported_b["import"]["unmatched"] == 4
    assert service.get(a["id"])["accounting"]["imported_interactions"] == 1


def test_late_unknown_and_malformed_interactions_remain_explicit_and_partial(setup):
    service, _, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    rows = [event(case, timestamp=(NOW + timedelta(days=2)).isoformat()), event(case, timestamp="unknown")]
    result = service.import_interactions(case["id"], "\n".join(["malformed bearer secret", *(json.dumps(row) for row in rows)]))
    assert result["import"]["matched"] == 2 and result["import"]["errors"][0]["line"] == 1
    assert [item["correlation_window"] for item in result["case"]["interactions"]] == ["outside", "unknown"]
    assert "malformed bearer secret" not in json.dumps(result) and not attempted


def test_raw_request_matching_requires_exact_host_and_no_conflicting_full_id(setup):
    service, _, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    raw = "GET / HTTP/1.1\r\nHost: " + case["callback_host"] + "\r\n\r\n"
    rows = [event(case, **{"protocol": "http", "full-id": "", "raw-request": raw}),
            event(case, **{"protocol": "http", "full-id": "other-session", "raw-request": raw}),
            event(case, **{"full-id": "", "raw-request": ";" + case["callback_host"] + ". IN AAAA"}),
            event(case, **{"full-id": "", "raw-request": ";" + case["callback_host"] + ".evil IN AAAA"})]
    result = service.import_interactions(case["id"], "\n".join(map(json.dumps, rows)))
    assert result["import"]["matched"] == result["import"]["unmatched"] == 2
    assert not attempted


def test_target_change_disables_payload_but_retains_original_binding(setup):
    service, ws, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    ws.update_contract(workspace["id"], workspace["contracts"][0]["id"], {"target": "http://api.localhost/v2"})
    stale = service.get(case["id"])
    assert not stale["context_current"] and not stale["can_use_payload"]
    assert stale["context"]["target"] == "http://api.localhost/v1" and not attempted


def test_identity_scope_assignment_change_disables_existing_case(setup):
    service, ws, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    ws.assign_identity(workspace["id"], workspace["contracts"][0]["id"], {
        "profile_id": "reader", "allowed_scopes": ["http://api.localhost/"]})
    assert not service.get(case["id"])["can_use_payload"] and not attempted


def test_changes_retirement_and_expiry_invalidate_payload_reuse_without_altering_old_evidence(setup):
    service, ws, workspace, _, _, _ = setup
    case = service.create(data(workspace))
    service.import_interactions(case["id"], json.dumps(event(case)))
    ws.set_profile(workspace["id"], {"id": "reader", "token": "rotated-local-value"})
    stale = service.get(case["id"])
    assert not stale["context_current"] and not stale["can_use_payload"]
    assert stale["context"]["identity_revision"] == 1 and len(stale["interactions"]) == 1
    current = service.create(data(ws.get(workspace["id"])))
    assert service.retire(current["id"])["retired"] and not service.get(current["id"])["can_use_payload"]
    expires = service.create(data(ws.get(workspace["id"]), ttl_seconds=60))
    service.clock = lambda: NOW + timedelta(seconds=61)
    assert not service.get(expires["id"])["can_use_payload"]


def test_receipts_require_exact_field_payload_context_and_dispatch(setup):
    service, _, workspace, manager, _, _ = setup
    case = service.create(data(workspace))
    baseline = {"request_id": "manual", "created_at": NOW.isoformat(), "status": "completed", "context": case["context"],
                "requests_sent": 1, "request": {"body": {"unrelated": case["payload"]}}}
    for index, changes in enumerate(({}, {"requests_sent": 0}, {"context": {**case["context"], "identity_revision": 2}})):
        record = {**copy.deepcopy(baseline), **changes, "request_id": "manual-" + str(index)}
        manager._save(record)
        with pytest.raises(ValueError):
            service.attach_receipt(case["id"], record["request_id"])


def test_exports_restore_as_historical_unverified_without_local_receipt_links(setup):
    service, _, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    service.import_interactions(case["id"], json.dumps(event(case)))
    payload = service.export(case["id"])
    payload["case"]["interactions"][0].update(classification="confirmed-vulnerability", verification="impact-demonstrated")
    payload["case"]["findings"] = [{"confirmed": True}]
    restored = service.restore(payload)
    assert restored["historical"] and restored["retired"] and not restored["can_use_payload"]
    assert restored["interactions"][0]["classification"] == "callback-observation"
    assert restored["interactions"][0]["verification"] == "imported-unverified"
    assert "findings" not in restored and not attempted
    with pytest.raises(ValueError, match="read-only"):
        service.import_interactions(restored["id"], json.dumps(event(case)))


def test_future_storage_refused_without_mutating_original(tmp_path):
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=99")
    original = path.read_bytes()
    with pytest.raises(ValueError, match="unsupported"):
        oob.OOBService(path)
    assert path.read_bytes() == original


def test_routes_are_offline_and_do_not_accept_secret_or_execution_options(setup, monkeypatch):
    service, _, workspace, _, attempted, _ = setup
    monkeypatch.setattr(oob, "_SERVICE", service)
    app = FastAPI()
    app.include_router(oob_routes.router)
    @app.exception_handler(ValueError)
    async def rejected(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=400)
    with TestClient(app) as client:
        created = client.post("/api/oob/cases", json=data(workspace))
        assert created.status_code == 200
        case = created.json()
        assert client.get("/api/oob/cases", params={"workspace_id": workspace["id"]}).json()["cases"][0]["id"] == case["id"]
        assert client.post("/api/oob/cases", json=data(workspace, token="never-accepted", execute=True)).status_code == 422
        imported = client.post(f"/api/oob/cases/{case['id']}/interactions", json={"jsonl": json.dumps(event(case))})
        assert imported.status_code == 200 and imported.json()["requests_sent"] == 0
        exported = client.get(f"/api/oob/cases/{case['id']}/export").json()
        assert client.post("/api/oob/import", json=exported).json()["historical"]
        assert not attempted


def test_failed_storage_write_preserves_existing_evidence_and_returns_safe_error(setup, monkeypatch):
    service, _, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    monkeypatch.setattr(oob, "_SERVICE", service)
    app = FastAPI()
    app.include_router(oob_routes.router)
    service._db.execute("PRAGMA query_only=ON")
    with TestClient(app) as client:
        failed = client.post(f"/api/oob/cases/{case['id']}/retire")
    service._db.execute("PRAGMA query_only=OFF")
    assert failed.status_code == 507 and "preserved" in failed.json()["detail"]
    assert str(service.path) not in failed.text and "local-secret-for-masking" not in failed.text
    assert service.get(case["id"]) == case and not attempted


@pytest.mark.parametrize("change", [{"payload": {}}, {"callback_host": []}, {"field": {"location": "body", "pointer": "bad"}},
                                    {"context": {"identity_ref": {"secret": "value"}}}, {"interactions": ["not a record"]}])
def test_malformed_historical_import_is_rejected_without_losing_live_cases(setup, change):
    service, _, workspace, _, attempted, _ = setup
    case = service.create(data(workspace))
    exported = service.export(case["id"])
    exported["case"].update(change)
    with pytest.raises(ValueError):
        service.restore(exported)
    assert service.list() == [case] and not attempted
