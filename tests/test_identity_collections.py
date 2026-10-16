"""Identity inheritance and cancellation use official local Bruno fixtures only."""
from __future__ import annotations

import json
import socket
import threading

import httpx
import pytest

from namazu import desktop_requests, identity_profiles, oauth, workspaces
from tests.test_identity_profiles import configure, settled
from tests.test_request_collections import finished, operation, payload, source_files


@pytest.fixture
def local(tmp_path, monkeypatch):
    def deny(*_args, **_kwargs):
        raise AssertionError("This regression permits only in-memory mock targets")
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny)
    service = workspaces.WorkspaceService(tmp_path / "workspaces.db")
    monkeypatch.setattr(workspaces, "service", lambda: service)
    workspace = service.create("Identity inheritance")
    imported = service.import_bruno_collection(workspace["id"], {"files": source_files(), "environment": "Local"})
    workspace = imported["workspace"]
    collection = workspace["request_collections"][0]
    for name in ("shared", "environment", "request"):
        service.set_profile(workspace["id"], {"id": name, "name": name, "token": "local-" + name + "-credential"})
    attempts = []
    def target(request):
        attempts.append(request)
        return httpx.Response(200, json={"ok": True, "echo": request.headers.get("authorization")})
    manager = desktop_requests.RequestManager(tmp_path / "requests.db",
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(target)))
    yield service, workspace, collection, manager, attempts
    manager.stop_all()
    for _stop, thread in list(manager._tasks.values()):
        thread.join(4)
    manager._db.close()
    service.close()


def bind(service, workspace, collection, profile, kind="shared", source=None, **changes):
    assignment = {"contract_id": collection["id"], "kind": kind,
                  "allowed_scopes": ["http://127.0.0.1:9876/echo"]}
    if kind == "environment":
        assignment["environment"] = "Local"
    if source:
        assignment["operation_key"] = operation(collection, source)["id"]
    assignment.update(changes)
    return identity_profiles.assign(service, workspace["id"], profile, [assignment])


def context(service, workspace, collection, source, **kwargs):
    return service.request_context(workspace["id"], collection["id"], collection["hash"],
                                   operation(collection, source)["id"], **kwargs)


def test_shared_environment_request_and_anonymous_precedence(local):
    service, workspace, collection, manager, attempts = local
    first, second = "Nested folder/Same request.bru", "Other folder/Same request.bru"
    bind(service, workspace, collection, "shared")
    shared = context(service, workspace, collection, first)
    assert shared["identity_ref"] == "shared"
    bind(service, workspace, collection, "environment", "environment")
    assert not shared["scope_guard"]()
    environment = context(service, workspace, collection, first)
    assert environment["identity_ref"] == "environment" and environment["identity_source"] == "environment assignment"
    bind(service, workspace, collection, "request", "request", first)
    assert not environment["scope_guard"]()
    assert context(service, workspace, collection, first)["identity_ref"] == "request"
    assert context(service, workspace, collection, second)["identity_ref"] == "environment"
    bind(service, workspace, collection, "request", "anonymous", second)
    assert context(service, workspace, collection, second)["identities"] == {}
    for source in (first, second):
        result = finished(manager, manager.start(payload(workspace, collection, source)))
        assert result["status"] == "completed", result
        dump = json.dumps(result)
        for secret in ("local-shared-credential", "local-environment-credential", "local-request-credential"):
            assert secret not in dump, dump
    assert [item.headers.get("authorization") for item in attempts] == ["Bearer local-request-credential", None]
    bind(service, workspace, collection, "request", "request", first, remove=True)
    assert context(service, workspace, collection, first)["identity_ref"] == "environment"
    bind(service, workspace, collection, "environment", "environment", remove=True)
    assert context(service, workspace, collection, first)["identity_ref"] == "shared"


def test_same_environment_name_in_another_collection_is_not_assigned(local):
    service, workspace, collection, _manager, attempts = local
    files = source_files()
    manifest = next(item for item in files if item["path"] == "bruno.json")
    manifest["content"] = json.dumps({**json.loads(manifest["content"]), "name": "Separate collection"})
    created = service.import_bruno_collection(workspace["id"], {"files": files, "environment": "Local"})
    other = next(item for item in created["workspace"]["request_collections"] if item["id"] != collection["id"])
    bind(service, workspace, collection, "environment", "environment")
    source = "Nested folder/Same request.bru"
    assert context(service, workspace, collection, source)["identity_ref"] == "environment"
    assert context(service, workspace, other, source, require_credential=False)["identity_ref"] is None
    with pytest.raises(ValueError, match="map a local identity"):
        context(service, workspace, other, source)
    assert not attempts


def test_rotation_removal_and_scope_change_revoke_old_request_contexts(local):
    service, workspace, collection, _manager, attempts = local
    source = "Nested folder/Same request.bru"
    bind(service, workspace, collection, "shared")
    original = context(service, workspace, collection, source)
    service.set_profile(workspace["id"], {"id": "shared", "token": "rotated-collection-credential"})
    assert not original["scope_guard"]()
    rotated = context(service, workspace, collection, source)
    assert rotated["identity_revision"] != original["identity_revision"]
    bind(service, workspace, collection, "shared", allowed_scopes=["http://127.0.0.1:9876"])
    assert not rotated["scope_guard"]()
    widened = context(service, workspace, collection, source)
    bind(service, workspace, collection, "shared", remove=True)
    assert not widened["scope_guard"]()
    assert not attempts


def test_draft_outside_assigned_base_path_never_dispatches(local):
    service, workspace, collection, manager, attempts = local
    bind(service, workspace, collection, "shared")
    draft = payload(workspace, collection, "Nested folder/Same request.bru", request={"url": "http://127.0.0.1:9876/private"})
    result = finished(manager, manager.start(draft))
    assert result["requests_sent"] == 0 and result["status"] == "failed"
    assert not attempts
    assert "local-shared-credential" not in json.dumps(result)


def test_collection_assignment_never_authorizes_writes(local):
    service, workspace, collection, manager, attempts = local
    bind(service, workspace, collection, "shared")
    row = context(service, workspace, collection, "04-json-null.bru")
    assert row["allow_mutating"] is False
    with pytest.raises(ValueError, match="authorize"):
        manager.start(payload(workspace, collection, "04-json-null.bru"))
    assert not attempts


def test_export_restore_retains_assignments_without_credentials(local):
    service, workspace, collection, _manager, attempts = local
    source = "Nested folder/Same request.bru"
    bind(service, workspace, collection, "shared")
    bind(service, workspace, collection, "environment", "environment")
    bind(service, workspace, collection, "request", "request", source)
    exported = service.export(workspace["id"])
    encoded = json.dumps(exported)
    assert all("local-" + name + "-credential" not in encoded for name in ("shared", "environment", "request"))
    restored = service.restore(exported)
    restored_collection = restored["request_collections"][0]
    row = context(service, restored, restored_collection, source, require_credential=False)
    assert row["identity_ref"] == "request" and row["identities"] == {}
    with pytest.raises(ValueError, match="available identity"):
        context(service, restored, restored_collection, source)
    assert not attempts


def test_failed_batch_assignment_is_atomic(local):
    service, workspace, collection, _manager, attempts = local
    before = service.get(workspace["id"])
    with pytest.raises(ValueError, match="request"):
        identity_profiles.assign(service, workspace["id"], "shared", [
            {"contract_id": collection["id"], "kind": "shared", "allowed_scopes": ["http://127.0.0.1:9876/echo"]},
            {"contract_id": collection["id"], "kind": "request", "operation_key": "another-contract::request.bru", "allowed_scopes": ["http://127.0.0.1:9876/echo"]},
        ])
    assert service.get(workspace["id"]) == before
    assert not attempts


def test_cancel_before_acquisition_commit_prevents_identity_request(local, monkeypatch):
    service, workspace, _collection, _manager, attempts = local
    wid, profile = configure(service, workspace_id=workspace["id"])
    acquisitions = identity_profiles.manager(service)
    reached, release = threading.Event(), threading.Event()
    mutex = threading.RLock()
    class GatedLock:
        def __enter__(self):
            if threading.current_thread().name == "namazu-explicit-token" and not reached.is_set():
                reached.set()
                assert release.wait(3)
            mutex.acquire()
            return self

        def __exit__(self, *_args):
            mutex.release()
    acquisitions.lock = GatedLock()
    token_attempts = []
    def request_token(*_args, **_kwargs):
        token_attempts.append(True)
        return {"access_token": "not-to-be-adopted", "token_type": "Bearer"}
    monkeypatch.setattr(oauth, "request_token", request_token)
    job = acquisitions.start(wid, profile)
    try:
        assert reached.wait(2)
        stopped = acquisitions.stop(wid, job["id"])
        assert stopped["attempts"] == 0
    finally:
        release.set()
    result = settled(acquisitions, wid, job)
    assert result["state"] == "cancelled"
    assert not token_attempts and result["attempts"] == 0
    assert not attempts


def test_config_rotation_discards_inflight_token_result(local, monkeypatch):
    service, workspace, _collection, _manager, attempts = local
    wid, profile = configure(service, workspace_id=workspace["id"])
    acquisitions = identity_profiles.manager(service)
    entered, release = threading.Event(), threading.Event()
    def request_token(*_args, **_kwargs):
        entered.set()
        assert release.wait(3)
        return {"access_token": "stale-inflight-value", "token_type": "Bearer"}
    monkeypatch.setattr(oauth, "request_token", request_token)
    job = acquisitions.start(wid, profile)
    try:
        assert entered.wait(2)
        configure(service, workspace_id=wid, id=profile, client_secret="replacement-client-secret")
    finally:
        release.set()
    result = settled(acquisitions, wid, job)
    assert result["state"] == "cancelled"
    selected = next(item for item in service.get(wid)["profiles"] if item["id"] == profile)
    assert not selected["credential_available"]
    assert "stale-inflight-value" not in json.dumps(service.export(wid))
    assert not attempts
