"""The /api/runs HTTP surface: create, poll, stop, withdraw, export, delete.

Drives the FastAPI app with a run manager pointed at an isolated store, against
the real-socket fixture server. Confirms the request model, the endpoints and
the no-replay guarantees hold through the HTTP boundary.
"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from namazu import app as app_module
from namazu.audit import run_service
from namazu.audit.run_service import RunManager
from namazu.audit.run_store import RunStore
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
def client(tmp_path):
    mgr = RunManager(RunStore(tmp_path / "runs.db"))
    run_service.set_manager(mgr)
    with TestClient(app_module.app, base_url="http://127.0.0.1") as test_client:
        yield test_client
    run_service.set_manager(None)
    mgr.store.close()


def _payload(base, **over):
    body = {
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
    body.update(over)
    return body


def _settle(client, run_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snap = client.get(f"/api/runs/{run_id}").json()
        if not snap["active"] and snap["status"] in ("finished", "incomplete", "interrupted"):
            return snap
        time.sleep(0.05)
    raise AssertionError("run did not settle")


def test_create_poll_and_export(client, fixture):
    created = client.post("/api/runs", json=_payload(fixture.base))
    assert created.status_code == 200
    run_id = created.json()["run_id"]
    snap = _settle(client, run_id)
    assert snap["status"] == "finished"
    assert snap["done"] == 1

    listed = client.get("/api/runs").json()["runs"]
    assert any(row["run_id"] == run_id for row in listed)

    # Export and reopen send nothing to the target.
    attempts = len(fixture.attempts)
    export = client.get(f"/api/runs/{run_id}/export").json()
    assert export["provenance"]["requests_sent_during_current_action"] == 0
    client.get(f"/api/runs/{run_id}")
    assert len(fixture.attempts) == attempts
    assert "local-primary" not in export["requests"][0]["request_headers"].get("Authorization", "")


def test_unknown_run_is_404(client):
    assert client.get("/api/runs/does-not-exist").status_code == 404
    assert client.post("/api/runs/does-not-exist/stop", json={}).status_code == 409


def test_delete_run(client, fixture):
    run_id = client.post("/api/runs", json=_payload(fixture.base)).json()["run_id"]
    _settle(client, run_id)
    assert client.request("DELETE", f"/api/runs/{run_id}", json={}).status_code == 200
    assert client.get(f"/api/runs/{run_id}").status_code == 404


def test_writes_profile_requires_authorisation(client, fixture):
    body = _payload(fixture.base, profile="writes", allow_mutating=False,
                    operations=[{"operation_id": "POST /summaries"}])
    created = client.post("/api/runs", json=body)
    assert created.status_code == 400
    assert "authori" in created.json()["detail"].lower()
