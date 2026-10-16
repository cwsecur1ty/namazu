"""Desktop ordinary requests use local mocks, assigned identities and durable evidence."""
from __future__ import annotations

import copy
import json
import sqlite3
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from namazu import app as app_module
from namazu import desktop_requests, desktop_state, workspaces
from namazu.audit import run_service
from namazu.audit.run_service import RunManager
from namazu.audit.run_store import RunStore
from tests.workspace_fixture_server import document


@pytest.fixture
def setup(tmp_path):
    ws = workspaces.WorkspaceService(tmp_path / "workspaces.db")
    workspaces.set_service(ws)
    audit = RunManager(RunStore(tmp_path / "runs.db"))
    run_service.set_manager(audit)
    state = desktop_state.StateStore(desktop_state.data_paths(tmp_path))
    desktop_state.set_store(state)
    attempts = []
    def target(request):
        attempts.append(request)
        return httpx.Response(200, json={"id": "17", "account_name": "test", "echo": request.headers.get("Authorization", "none")})
    requests = desktop_requests.RequestManager(tmp_path / "requests.db", client_factory=lambda: httpx.Client(transport=httpx.MockTransport(target)))
    desktop_requests.set_manager(requests)
    workspace = ws.create("Request regression")
    workspace = ws.import_contracts(workspace["id"], [{"raw_spec": json.dumps(document("http://127.0.0.1:9138", name))} for name in ("accounts", "orders", "public")])
    wid = workspace["id"]
    ws.set_profile(wid, {"id": "shared", "token": "inert-local-credential"})
    for contract in workspace["contracts"][:2]:
        ws.assign_identity(wid, contract["id"], {"profile_id": "shared", "allowed_scopes": [contract["target"]]})
    workspace = ws.get(wid)
    with TestClient(app_module.app, base_url="http://127.0.0.1") as client:
        yield client, ws, workspace, requests, attempts
    desktop_requests.set_manager(None)
    desktop_state.set_store(None)
    run_service.set_manager(None)
    workspaces.set_service(None)
    audit.store.close()
    ws.close()
    requests._db.close()


def payload(workspace, index=0, **changes):
    contract = workspace["contracts"][index]
    return {"workspace_id": workspace["id"], "contract_id": contract["id"], "snapshot_hash": contract["hash"],
            "operation_key": contract["operations"][0]["id"], "environment_id": "local",
            "request": {"parameters": {"path.id": "17"}}, **changes}


def wait(manager, rid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = manager.get(rid)
        if result["status"] not in desktop_requests.ACTIVE:
            return result
        time.sleep(.01)
    raise AssertionError("Local request did not finish")


def test_preparation_is_offline_and_context_is_contract_bound(setup):
    client, _, workspace, _, attempts = setup
    for index in (0, 1):
        response = client.post("/api/desktop/prepare", json=payload(workspace, index))
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["context"]["contract_id"] == workspace["contracts"][index]["id"]
        assert result["context"]["snapshot_hash"] == workspace["contracts"][index]["hash"]
        assert result["request"]["contract_match"]
        assert "inert-local-credential" not in response.text
    assert not attempts


def test_shared_identity_is_not_sent_to_unassigned_contract_and_history_redacts(setup):
    client, _, workspace, manager, attempts = setup
    for index in (0, 1, 2):
        response = client.post("/api/desktop/requests", json=payload(workspace, index))
        assert response.status_code == 200, response.text
        result = wait(manager, response.json()["request_id"])
        assert result["status"] == "completed", result
        assert result["requests_sent"] == 1
        assert "inert-local-credential" not in json.dumps(result)
    assert [req.headers.get("authorization") for req in attempts] == ["Bearer inert-local-credential", "Bearer inert-local-credential", None]
    assert "inert-local-credential" not in client.get("/api/desktop/requests").text
    assert b"inert-local-credential" not in manager.path.read_bytes()


@pytest.mark.parametrize("draft", [
    {"url": "http://127.0.0.1:9138/outside/17"},
    {"url": "http://127.0.0.1:9999/v1/accounts/widgets/17"},
    {"url": "http://127.0.0.1:9138/v1/accounts/%2e%2e/private"},
    {"url": "http://127.0.0.1:9138/v1/accounts/widgets/17?access_token=secret"},
    {"headers": {"Authorization": "Bearer sneaked"}},
    {"url": "file:///C:/Windows/system.ini"},
    {"url": "http://user:password@127.0.0.1:9138/v1/accounts/widgets/17"},
])
def test_unsafe_or_unreviewed_drafts_never_dispatch(setup, draft):
    client, _, workspace, _, attempts = setup
    response = client.post("/api/desktop/requests", json=payload(workspace, request=draft))
    assert response.status_code == 400, response.text
    assert not attempts


def test_stale_snapshot_and_wrong_operation_contract_are_rejected(setup):
    client, _, workspace, _, attempts = setup
    for changes in ({"snapshot_hash": "old"}, {"operation_key": workspace["contracts"][1]["operations"][0]["id"]}):
        assert client.post("/api/desktop/requests", json=payload(workspace, **changes)).status_code == 400
    assert not attempts


def test_redirect_and_malicious_html_remain_inert_evidence(setup):
    client, _, workspace, manager, attempts = setup
    def target(request):
        attempts.append(request)
        return httpx.Response(302, headers={"location": "http://127.0.0.1:9999/outside", "content-type": "text/html"},
                              text='<script>window.evil=true</script><img src="file:///C:/secret">')
    manager.client_factory = lambda: httpx.Client(transport=httpx.MockTransport(target))
    created = client.post("/api/desktop/requests", json=payload(workspace)).json()
    result = wait(manager, created["request_id"])
    assert len(attempts) == 1
    assert result["result"]["response"]["status"] == 302
    assert "<script>" in result["result"]["response"]["body"]
    assert any("without following" in warning for warning in result["result"]["validation"]["warnings"])


def test_cancel_in_flight_retains_one_received_exchange(setup):
    client, _, workspace, manager, attempts = setup
    entered, release = threading.Event(), threading.Event()
    def target(request):
        attempts.append(request)
        entered.set()
        assert release.wait(3)
        return httpx.Response(200, json={"id": "17"})
    manager.client_factory = lambda: httpx.Client(transport=httpx.MockTransport(target))
    created = client.post("/api/desktop/requests", json=payload(workspace)).json()
    assert entered.wait(2)
    live = client.get("/api/desktop/status").json()
    assert live["active_requests"] == 1 and live["stopping"] == 0
    stopped = client.post(f"/api/desktop/requests/{created['request_id']}/cancel", json={}).json()
    assert stopped["in_flight"] and stopped["cancellation_requested"]
    stopping = client.get("/api/desktop/status").json()
    assert stopping["active_requests"] == 1 and stopping["stopping"] == 1
    assert client.post("/api/desktop/stop", json={}).status_code == 200
    assert len(attempts) == 1
    release.set()
    result = wait(manager, created["request_id"])
    assert result["status"] == "cancelled"
    assert result["requests_sent"] == len(attempts) == 1
    assert result["result"]["response"]["status"] == 200


def test_write_requires_explicit_request_authorization_and_is_not_a_baseline(setup):
    client, ws, workspace, manager, attempts = setup
    draft = payload(workspace, request={"method": "POST", "url": workspace["contracts"][0]["target"] + "/widgets/17", "body": {"local": True}})
    assert client.post("/api/desktop/requests", json=draft).status_code == 400
    assert not attempts
    draft["allow_mutating"] = True
    created = client.post("/api/desktop/requests", json=draft).json()
    result = wait(manager, created["request_id"])
    assert result["result"]["validation"]["valid"] is None
    assert ws.get(workspace["id"])["contracts"][0]["config"] == workspace["contracts"][0]["config"]


def test_assertions_are_observations_not_vulnerabilities(setup):
    client, _, workspace, manager, _ = setup
    draft = payload(workspace, request={"parameters": {"path.id": "17"}, "assertions": {"pointer": "/id", "pointer_equals": "different"}})
    created = client.post("/api/desktop/requests", json=draft).json()
    result = wait(manager, created["request_id"])["result"]
    assert result["assertions"]["valid"] is False
    assert "findings" not in result


def test_failed_initial_persistence_prevents_dispatch(setup, monkeypatch):
    _, _, workspace, manager, attempts = setup
    def fail(_):
        raise OSError("disk full")
    monkeypatch.setattr(manager, "_save", fail)
    with pytest.raises(OSError):
        manager.start(payload(workspace))
    assert not attempts


def test_interrupted_receipts_are_never_replayed(setup):
    _, _, workspace, manager, attempts = setup
    record = {"request_id": "interrupted", "created_at": desktop_requests.now(), "status": "running", "requests_sent": 1, "in_flight": True}
    manager._save(record)
    restored = desktop_requests.RequestManager(manager.path)
    assert restored.get("interrupted")["status"] == "interrupted"
    assert restored.get("interrupted")["requests_sent"] == 1
    assert not attempts
    restored._db.close()


def test_desktop_state_cas_and_secret_free_restore(setup):
    client, _, workspace, _, attempts = setup
    initial = client.get("/api/desktop/state").json()
    state = {"version": 1, "revision": initial["revision"], "state": {"workspaces": {workspace["id"]: {
        "tabs": [{"draft": {"headers": {"Authorization": "Bearer do-not-store"}, "body": {"password": "private"}}, "identityRef": "shared"}]}}}}
    saved = client.put("/api/desktop/state", json=state)
    assert saved.status_code == 200, saved.text
    assert "do-not-store" not in saved.text and '"private"' not in saved.text
    assert client.put("/api/desktop/state", json=copy.deepcopy(state)).status_code == 409
    assert not attempts


@pytest.mark.parametrize("change", ["credential", "target", "assignment", "write-permission"])
def test_changed_scope_is_rechecked_immediately_before_dispatch(setup, change):
    _, ws, workspace, manager, attempts = setup
    entered, release = threading.Event(), threading.Event()
    old_factory = manager.client_factory
    def held_factory():
        entered.set()
        assert release.wait(3)
        return old_factory()
    manager.client_factory = held_factory
    created = manager.start(payload(workspace))
    assert entered.wait(2)
    cid = workspace["contracts"][0]["id"]
    if change == "credential":
        ws.set_profile(workspace["id"], {"id": "shared", "token": "rotated"})
    elif change == "target":
        ws.update_contract(workspace["id"], cid, {"target": "http://127.0.0.1:9138/new"})
    elif change == "assignment":
        ws.assign_identity(workspace["id"], cid, {"remove": True})
    else:
        ws.update_contract(workspace["id"], cid, {"config": {"allow_mutating": True}})
    release.set()
    result = wait(manager, created["request_id"])
    assert result["status"] == "failed"
    assert result["requests_sent"] == 0
    assert not attempts


def test_assertions_check_original_response_before_redaction(setup):
    _, _, workspace, manager, _ = setup
    data = payload(workspace, request={"parameters": {"path.id": "17"}, "assertions": {
        "pointer": "/echo", "pointer_equals": "Bearer inert-local-credential"}})
    result = wait(manager, manager.start(data)["request_id"])
    assert result["result"]["assertions"]["valid"] is True
    assert "inert-local-credential" not in json.dumps(result)


def test_no_undocumented_id_is_invented(setup):
    client, ws, workspace, _, attempts = setup
    doc = document("http://127.0.0.1:9138", "accounts")
    param = doc["paths"]["/widgets/{id}"]["get"]["parameters"][0]
    param.pop("example", None)
    param.get("schema", {}).pop("example", None)
    imported = ws.import_contracts(workspace["id"], [{"raw_spec": json.dumps(doc)}])
    body = payload(imported, 3, request={})
    preview = client.post("/api/desktop/prepare", json=body)
    assert preview.status_code == 200, preview.text
    assert "{id}" in preview.json()["request"]["url"]
    assert client.post("/api/desktop/requests", json=body).status_code == 400
    assert not attempts


def test_desktop_private_capability_and_original_csp(setup, monkeypatch):
    from namazu import desktop_runtime
    client, _, _, _, attempts = setup
    monkeypatch.setattr(desktop_runtime, "_secret", "a" * 64)
    assert client.get("/").status_code == 401
    assert client.get("/api/health").status_code == 401
    headers = {"X-Namazu-Session": "a" * 64}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert client.post("/api/desktop/sample", headers={**headers, "Origin": "https://foreign.invalid"}, json={}).status_code == 403
    assert client.get("/", headers={**headers, "Host": "foreign.invalid"}).status_code == 403
    assert not attempts


def test_future_request_history_is_refused_without_mutation(tmp_path):
    path = tmp_path / "newer.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=99")
    original = path.read_bytes()
    with pytest.raises(ValueError, match="newer"):
        desktop_requests.RequestManager(path)
    assert path.read_bytes() == original


def test_result_save_failure_keeps_visible_evidence_and_durable_unknown_receipt(setup, monkeypatch):
    _, _, workspace, manager, attempts = setup
    original = manager._save
    def save(record):
        if record["status"] not in {"pending", "running"}:
            raise OSError("disk full")
        return original(record)
    monkeypatch.setattr(manager, "_save", save)
    result = wait(manager, manager.start(payload(workspace))["request_id"])
    assert result["persistence_error"]
    assert result["result"]["response"]["status"] == 200
    assert len(attempts) == result["requests_sent"] == 1
    restored = desktop_requests.RequestManager(manager.path)
    assert restored.get(result["request_id"])["status"] == "interrupted"
    restored._db.close()


def test_desktop_oauth_callback_uses_one_use_state_without_exposing_private_api(setup, monkeypatch):
    from namazu import desktop_runtime, oauth
    client, _, _, _, attempts = setup
    monkeypatch.setattr(desktop_runtime, "_secret", "c" * 64)
    headers = {"X-Namazu-Session": "c" * 64}
    redeemed = []
    def token(*args, **kwargs):
        redeemed.append({**kwargs, "form": args[1]})
        return {"access_token": "local-oauth-secret", "token_type": "Bearer"}
    monkeypatch.setattr(oauth, "request_token", token)
    started = client.post("/api/oauth/authorize", headers=headers, json={
        "authorization_endpoint": "http://127.0.0.1:9138/authorize", "token_endpoint": "http://127.0.0.1:9138/token",
        "client_id": "local", "use_pkce": True}).json()
    assert client.get("/oauth/callback", params={"state": "unknown", "code": "local-code"}).status_code == 401
    callback = client.get("/oauth/callback", params={"state": started["state"], "code": "local-code"})
    assert callback.status_code == 200, callback.text
    assert "local-oauth-secret" not in callback.text
    assert "desktop application" in callback.text
    assert client.get("/oauth/callback", params={"state": started["state"], "code": "local-code"}).status_code == 401
    assert len(redeemed) == 1
    assert redeemed[0]["form"]["code_verifier"]
    assert client.post("/api/oauth/collect", json={"session": started["session"]}).status_code == 401
    collected = client.post("/api/oauth/collect", headers=headers, json={"session": started["session"]}).json()
    assert collected["token"]["access_token"] == "local-oauth-secret"
    assert not attempts


def test_cancel_is_responsive_while_dispatch_scope_guard_waits(setup, monkeypatch):
    _, ws, workspace, manager, attempts = setup
    entered, release = threading.Event(), threading.Event()
    original_context = ws.request_context
    def context(*args, **kwargs):
        result = original_context(*args, **kwargs)
        original_guard = result["scope_guard"]
        calls = 0
        def guard():
            nonlocal calls
            calls += 1
            if calls > 1:
                entered.set()
                assert release.wait(3)
            return original_guard()
        result["scope_guard"] = guard
        return result
    monkeypatch.setattr(ws, "request_context", context)
    record = manager.start(payload(workspace))
    assert entered.wait(2)
    started = time.monotonic()
    manager.cancel(record["request_id"])
    assert time.monotonic() - started < .5
    release.set()
    result = wait(manager, record["request_id"])
    assert result["status"] == "cancelled" and result["requests_sent"] == 0
    assert not attempts


def test_invalid_inputs_do_not_reflect_credentials(setup):
    client, _, workspace, _, attempts = setup
    secret = "private-invalid-credential"
    response = client.post("/api/desktop/requests", json=payload(workspace, request={
        "headers": {"Authorization": {"token": secret}}, "method": secret * 10}))
    assert response.status_code == 422
    assert secret not in response.text
    assert all("input" not in error and "ctx" not in error for error in response.json()["detail"])
    assert not attempts
