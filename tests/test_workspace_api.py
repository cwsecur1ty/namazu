"""Workspace HTTP integration; only local fixtures and isolated persistence."""
from __future__ import annotations

import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from namazu import app as app_module
from namazu import workspaces
from namazu.audit import run_service
from namazu.audit.run_service import RunManager
from namazu.audit.run_store import RunStore
from tests.workspace_fixture_server import WorkspaceFixture, document


@pytest.fixture
def workspace_api(tmp_path):
    service = workspaces.WorkspaceService(tmp_path / "workspaces.db")
    manager = RunManager(RunStore(tmp_path / "runs.db"))
    workspaces.set_service(service)
    run_service.set_manager(manager)
    fixture = WorkspaceFixture()
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(app_module.app, base_url="http://127.0.0.1") as client:
            yield client, fixture, service
    finally:
        fixture.shutdown()
        thread.join(timeout=2)
        run_service.set_manager(None)
        workspaces.set_service(None)
        manager.store.close()
        service.close()


def post(client, path, body):
    response = client.post(path, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_import_partial_failure_and_documentation_target_review(workspace_api):
    client, fixture, _service = workspace_api
    workspace = post(client, "/api/workspaces", {"title": "Local workspace"})
    path = "/api/workspaces/" + workspace["id"]
    imported = post(client, path + "/contracts/import", {"items": [
        {"url": fixture.base + "/docs/accounts"},
        {"raw_spec": "not a contract", "filename": "broken.yaml"},
        {"raw_spec": json.dumps(document(fixture.base, "orders")), "filename": "orders.json"},
    ]})
    assert len(imported["contracts"]) == 2
    assert imported["import_errors"]
    assert imported["contracts"][0]["target"] == fixture.base + "/v1/accounts"
    assert all(not entry["credential_present"] for entry in fixture.attempts)
    assert not any("widgets" in entry["path"] for entry in fixture.attempts)
    left, right = imported["contracts"]
    assert left["operations"][0]["id"] != right["operations"][0]["id"]
    assert left["id"] != right["id"]
    assert len(client.get("/api/workspaces").json()["workspaces"]) == 1


def test_workspace_export_restore_is_offline_and_retains_boundaries(workspace_api):
    client, fixture, _service = workspace_api
    workspace = post(client, "/api/workspaces", {"title": "Portable workspace"})
    path = "/api/workspaces/" + workspace["id"]
    imported = post(client, path + "/contracts/import", {"items": [
        {"raw_spec": json.dumps(document(fixture.base, name)), "filename": name + ".json"}
        for name in ("accounts", "orders")
    ]})
    before = len(fixture.attempts)
    exported = client.get(path + "/export").json()
    restored = post(client, "/api/workspaces/import", exported)
    assert len(restored["contracts"]) == 2
    assert [c["hash"] for c in restored["contracts"]] == [c["hash"] for c in imported["contracts"]]
    assert len(fixture.attempts) == before


def wait_run(client, run_id):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        snapshot = client.get("/api/runs/" + run_id).json()
        if not snapshot["active"]:
            return snapshot
        time.sleep(0.02)
    raise AssertionError("Local workspace run did not finish")


def test_shared_identity_assignments_override_and_unassigned_run(workspace_api):
    client, fixture, _service = workspace_api
    workspace = post(client, "/api/workspaces", {"title": "Scoped identities"})
    path = "/api/workspaces/" + workspace["id"]
    imported = post(client, path + "/contracts/import", {"items": [
        {"raw_spec": json.dumps(document(fixture.base, name)), "filename": name + ".json"}
        for name in ("accounts", "orders", "public")
    ]})
    contracts = imported["contracts"]
    post(client, path + "/profiles", {"id": "shared", "name": "Shared local reader", "token": "local-shared"})
    for contract in contracts[:2]:
        response = client.put(path + "/contracts/" + contract["id"] + "/identity", json={
            "profile_id": "shared", "allowed_scopes": [contract["target"]]})
        assert response.status_code == 200, response.text
    for contract in contracts:
        response = client.patch(path + "/contracts/" + contract["id"], json={"config": {"budget": 3}})
        assert response.status_code == 200, response.text
    plan = post(client, path + "/plan", {"budget": 9, "requests_per_second": 100, "inventory": False})
    assert plan["ready"], plan
    assert not fixture.attempts
    created = post(client, path + "/runs", {"plan_id": plan["id"]})
    snapshot = wait_run(client, created["run_id"])
    assert 0 < snapshot["requests_sent"] <= 9
    assert len(fixture.attempts) == snapshot["requests_sent"]
    for prefix in ("/v1/accounts", "/v2/orders"):
        assert any(r["path"].startswith(prefix) and r["identity"] == "shared" for r in fixture.attempts)
    assert any(r["path"].startswith("/public/") for r in fixture.attempts)
    assert all(not r["credential_present"] for r in fixture.attempts if r["path"].startswith("/public/"))
    exported = client.get(path + "/export").json()
    serialized = json.dumps(exported)
    assert "local-shared" not in serialized
    assert len(exported["saved_runs"]) == 1

    post(client, path + "/profiles", {"id": "override", "name": "Orders reader", "token": "local-override"})
    overridden = client.put(path + "/contracts/" + contracts[1]["id"] + "/identity", json={
        "override": True, "profile_id": "override", "allowed_scopes": [contracts[1]["target"]]}).json()
    assert overridden["contracts"][1]["identity"]["source"] == "contract-specific override"
    assert overridden["contracts"][0]["identity"]["profile_id"] == "shared"
    plan = post(client, path + "/plan", {"budget": 3, "requests_per_second": 100,
                                         "contract_ids": [contracts[1]["id"]]})
    before = len(fixture.attempts)
    run = post(client, path + "/runs", {"plan_id": plan["id"]})
    wait_run(client, run["run_id"])
    assert any(r["identity"] == "override" for r in fixture.attempts[before:])
    assert not any(r["identity"] == "shared" for r in fixture.attempts[before:])


def test_stale_plan_rejected_before_requests_after_target_or_rotation(workspace_api):
    client, fixture, _service = workspace_api
    workspace = post(client, "/api/workspaces", {"title": "Review invalidation"})
    path = "/api/workspaces/" + workspace["id"]
    imported = post(client, path + "/contracts/import", {"items": [
        {"raw_spec": json.dumps(document(fixture.base, "accounts"))}]})
    contract = imported["contracts"][0]
    post(client, path + "/profiles", {"id": "reader", "token": "local-shared"})
    assert client.put(path + "/contracts/" + contract["id"] + "/identity", json={
        "profile_id": "reader", "allowed_scopes": [contract["target"]]}).status_code == 200
    plan = post(client, path + "/plan", {"budget": 3})
    post(client, path + "/profiles", {"id": "reader", "token": "local-override"})
    assert client.post(path + "/runs", json={"plan_id": plan["id"]}).status_code == 400
    plan = post(client, path + "/plan", {"budget": 3})
    client.patch(path + "/contracts/" + contract["id"], json={"target": fixture.base + "/v2/orders"})
    assert client.post(path + "/runs", json={"plan_id": plan["id"]}).status_code == 400
    changed = post(client, path + "/plan", {"budget": 3})
    assert not changed["ready"]
    assert not fixture.attempts
