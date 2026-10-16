"""Bruno definitions use explicit local identity mapping and one mock exchange."""
from __future__ import annotations

import copy
import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest

from namazu import desktop_requests, workspaces
from tests.workspace_fixture_server import document

FIXTURES = Path(__file__).parent / "fixtures/bruno/comprehensive/collection"


def source_files():
    return [{"path": path.relative_to(FIXTURES).as_posix(), "content": path.read_text(encoding="utf-8")}
            for path in FIXTURES.rglob("*") if path.suffix == ".bru" or path.name == "bruno.json"]


@pytest.fixture
def setup(tmp_path, monkeypatch):
    def deny(*_args, **_kwargs):
        raise AssertionError("Only the in-memory mock transport is allowed")
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny)
    service = workspaces.WorkspaceService(tmp_path / "workspaces.db")
    monkeypatch.setattr(workspaces, "service", lambda: service)
    workspace = service.create("Collection boundary regression")
    imported = service.import_bruno_collection(workspace["id"], {"files": source_files(), "environment": "Local"})
    collection = imported["workspace"]["request_collections"][0]
    attempts = []
    def target(request):
        attempts.append(request)
        return httpx.Response(200, json={"authorization": request.headers.get("authorization"), "ok": True})
    manager = desktop_requests.RequestManager(tmp_path / "requests.db", client_factory=lambda: httpx.Client(transport=httpx.MockTransport(target)))
    yield service, imported["workspace"], collection, manager, attempts
    manager.stop_all()
    for _stop, thread in list(manager._tasks.values()):
        thread.join(4)
    manager._db.close()
    service.close()


def operation(collection, source):
    return next(row for row in collection["operations"] if row["local_id"] == source)


def payload(workspace, collection, source, **changes):
    return {"workspace_id": workspace["id"], "contract_id": collection["id"],
            "snapshot_hash": collection["hash"], "operation_key": operation(collection, source)["id"],
            "request": {}, **changes}


def assign(service, workspace, collection, source, profile="shared", token="local-bearer-value"):
    service.set_profile(workspace["id"], {"id": profile, "token": token})
    row = operation(collection, source)
    return service.assign_identity(workspace["id"], collection["id"], {
        "operation_key": row["id"], "profile_id": profile, "allowed_scopes": [row["target"] + "/echo"]})


def finished(manager, record):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        result = manager.get(record["request_id"])
        if result["status"] not in desktop_requests.ACTIVE:
            return result
        time.sleep(.01)
    raise AssertionError("Mock request did not settle")


def test_collection_identity_folder_names_idempotency_and_no_audit_contract(setup):
    service, workspace, collection, _manager, attempts = setup
    assert collection["response_contract"] is False and collection["operation_count"] == 36
    assert not workspace["contracts"]
    assert len({row["id"] for row in collection["operations"]}) == 36
    same = [row for row in collection["operations"] if row["summary"] == "Same request"]
    assert len(same) == 3 and len({row["tags"][0] for row in same}) == 3
    duplicate = service.import_bruno_collection(workspace["id"], {"files": source_files(), "environment": "Local"})
    assert duplicate["duplicate"] and duplicate["collection_id"] == collection["id"]
    assert len(duplicate["workspace"]["request_collections"]) == 1
    assert not service.plan(workspace["id"])["operations"]
    assert not attempts


@pytest.mark.parametrize("source", ["04-json-null.bru", "05-json-false.bru", "06-json-zero.bru", "07-json-string.bru",
                                    "22-json-escapes.bru", "33-empty-text-mode.bru", "10-form.bru", "08-text.bru", "09-xml.bru", "11-no-body.bru"])
def test_definition_bodies_reach_mock_without_scalar_or_empty_body_loss(setup, source):
    service, workspace, collection, manager, attempts = setup
    assign(service, workspace, collection, source)
    original = operation(collection, source)["request_definition"]["request"]
    draft = payload(workspace, collection, source, allow_mutating=True)
    _row, built, preview = desktop_requests.prepare(draft)
    assert built["has_body"] == original["has_body"]
    assert preview["context"]["response_contract"] is False
    assert not attempts
    result = finished(manager, manager.start(draft))
    assert result["status"] == "completed", result
    assert result["requests_sent"] == len(attempts) == 1
    assert result["result"]["validation"]["valid"] is None
    assert not result["result"].get("findings")
    if original["body_mode"] == "json":
        assert json.loads(attempts[0].content) == json.loads(original["body"])
        assert type(json.loads(attempts[0].content)) is type(json.loads(original["body"]))
    else:
        assert attempts[0].content == (original["body"] or "").encode("utf-8")
    if original["has_body"]:
        assert attempts[0].headers["content-type"] == original["content_type"]
    assert collection["config"] == service.get(workspace["id"])["request_collections"][0]["config"] == {"allow_mutating": False}


def test_authentication_is_explicit_per_request_and_does_not_change_noauth(setup):
    service, workspace, collection, manager, attempts = setup
    assign(service, workspace, collection, "Nested folder/Same request.bru")
    assign(service, workspace, collection, "01-request-auth-override.bru", "override", "different-local-bearer")
    with pytest.raises(ValueError, match="map a local identity"):
        manager.start(payload(workspace, collection, "Other folder/Same request.bru"))
    for source in ("Nested folder/Same request.bru", "01-request-auth-override.bru", "02-no-auth.bru"):
        result = finished(manager, manager.start(payload(workspace, collection, source)))
        assert result["status"] == "completed", result
        assert "local-bearer" not in json.dumps(result)
    assert [row.headers.get("authorization") for row in attempts] == ["Bearer local-bearer-value", "Bearer different-local-bearer", None]
    assert "local-bearer" not in json.dumps(service.export(workspace["id"]))
    with pytest.raises(ValueError, match="select the Bruno request"):
        service.assign_identity(workspace["id"], collection["id"], {"profile_id": "shared", "allowed_scopes": [collection["target"]]})


@pytest.mark.parametrize("change", ["rotation", "revocation", "scope"])
def test_pending_request_identity_changes_prevent_dispatch(setup, change):
    service, workspace, collection, manager, attempts = setup
    source = "01-request-auth-override.bru"
    assign(service, workspace, collection, source)
    entered, release = threading.Event(), threading.Event()
    old_factory = manager.client_factory
    def held_factory():
        entered.set()
        assert release.wait(3)
        return old_factory()
    manager.client_factory = held_factory
    record = manager.start(payload(workspace, collection, source))
    assert entered.wait(2)
    key = operation(collection, source)["id"]
    if change == "rotation":
        service.set_profile(workspace["id"], {"id": "shared", "token": "rotated-value"})
    elif change == "revocation":
        service.assign_identity(workspace["id"], collection["id"], {"operation_key": key, "remove": True})
    else:
        service.assign_identity(workspace["id"], collection["id"], {
            "operation_key": key, "profile_id": "shared", "allowed_scopes": [collection["target"]]})
    release.set()
    result = finished(manager, record)
    assert result["status"] == "failed" and result["requests_sent"] == 0
    assert not attempts


def test_unsupported_sources_credentials_and_unreviewed_destinations_fail_closed(setup):
    service, workspace, collection, manager, attempts = setup
    for source in ("20-inert-script.bru", "21-graphql.bru", "28-owned-file.bru", "29-owned-multipart.bru", "19-unresolved-query.bru"):
        with pytest.raises(ValueError, match="cannot be sent faithfully"):
            desktop_requests.prepare(payload(workspace, collection, source))
    source = "02-no-auth.bru"
    for draft in ({"headers": {"Authorization": "Bearer pasted-secret"}}, {"headers": {"X-Api-Key": "pasted-secret"}},
                  {"url": "http://127.0.0.1:1/elsewhere"}, {"url": collection["target"] + "/echo?access_token=pasted-secret"}):
        with pytest.raises(ValueError):
            manager.start(payload(workspace, collection, source, request=draft))
    with pytest.raises(ValueError, match="snapshot changed"):
        desktop_requests.prepare(payload(workspace, collection, source, snapshot_hash="stale"))
    assert not attempts


@pytest.mark.parametrize("header", ["X-Api-Key: fixture-api-key", "Authorization: Basic Zm9vOmJhcg==", "Authorization: {{opaque}}"])
def test_bearer_mapping_never_substitutes_other_header_authentication(setup, header):
    service, workspace, _collection, manager, attempts = setup
    source = "meta {\n  name: Header authentication\n  type: http\n}\nget {\n  url: http://127.0.0.1:9919/echo\n  body: none\n  auth: none\n}\nheaders {\n  " + header + "\n}\n"
    imported = service.import_bruno_collection(workspace["id"], {"files": [{"path": "header.bru", "content": source}]})
    collection = next(row for row in imported["workspace"]["request_collections"] if row["id"] == imported["collection_id"])
    assign(service, workspace, collection, "header.bru")
    with pytest.raises(ValueError, match="authentication"):
        manager.start(payload(workspace, collection, "header.bru"))
    assert not attempts


def test_literal_bearer_header_can_be_explicitly_mapped_without_importing_value(setup):
    service, workspace, _collection, manager, attempts = setup
    source = "meta {\n  name: Bearer header\n  type: http\n}\nget {\n  url: http://127.0.0.1:9919/echo\n  body: none\n  auth: none\n}\nheaders {\n  Authorization: Bearer imported-local-token\n}\n"
    imported = service.import_bruno_collection(workspace["id"], {"files": [{"path": "header.bru", "content": source}]})
    collection = next(row for row in imported["workspace"]["request_collections"] if row["id"] == imported["collection_id"])
    assert "imported-local-token" not in json.dumps(imported)
    with pytest.raises(ValueError, match="map a local identity"):
        manager.start(payload(workspace, collection, "header.bru"))
    assign(service, workspace, collection, "header.bru")
    result = finished(manager, manager.start(payload(workspace, collection, "header.bru")))
    assert result["status"] == "completed" and len(attempts) == 1
    assert attempts[0].headers["authorization"] == "Bearer local-bearer-value"


def test_newly_known_secret_in_definition_is_not_dispatched_as_redacted_placeholder(setup):
    service, workspace, _collection, manager, attempts = setup
    source = "meta {\n  name: Echo\n  type: http\n}\npost {\n  url: http://127.0.0.1:9919/echo\n  body: text\n  auth: none\n}\nbody:text {\n  formerly-unlabelled-value\n}\n"
    imported = service.import_bruno_collection(workspace["id"], {"files": [{"path": "echo.bru", "content": source}]})
    collection = next(row for row in imported["workspace"]["request_collections"] if row["id"] == imported["collection_id"])
    service.set_profile(workspace["id"], {"id": "newly-recognised", "token": "formerly-unlabelled-value"})
    assert "formerly-unlabelled-value" not in json.dumps(service.export(workspace["id"]))
    with pytest.raises(ValueError, match=r"snapshot|redact|faithful|credential"):
        manager.start(payload(workspace, collection, "echo.bru", allow_mutating=True))
    assert not attempts


def test_collection_redirect_keeps_one_receipt_and_no_out_of_scope_credential(setup):
    service, workspace, collection, manager, attempts = setup
    source = "01-request-auth-override.bru"
    assign(service, workspace, collection, source)
    def redirected(request):
        attempts.append(request)
        return httpx.Response(302, headers={"location": "http://127.0.0.1:1/collector"}, text="redirect evidence")
    manager.client_factory = lambda: httpx.Client(transport=httpx.MockTransport(redirected))
    result = finished(manager, manager.start(payload(workspace, collection, source)))
    assert result["status"] == "completed" and result["requests_sent"] == len(attempts) == 1
    assert result["result"]["response"]["status"] == 302
    assert result["result"]["validation"]["valid"] is None
    assert any("without following" in warning for warning in result["result"]["validation"]["warnings"])


def test_import_assignment_and_send_leave_openapi_controls_unchanged(setup):
    service, workspace, collection, manager, attempts = setup
    workspace = service.import_contracts(workspace["id"], [{"raw_spec": json.dumps(document("http://127.0.0.1:9920", "accounts"))}])
    contract = workspace["contracts"][0]
    service.update_contract(workspace["id"], contract["id"], {"config": {
        "examples": {contract["operations"][0]["id"]: {"parameters": {"path.id": "kept"}}},
        "allow_mutating": True}})
    before = service.get(workspace["id"])["contracts"][0]
    assign(service, workspace, collection, "01-request-auth-override.bru")
    result = finished(manager, manager.start(payload(workspace, collection, "01-request-auth-override.bru")))
    assert result["status"] == "completed" and len(attempts) == 1
    after = service.get(workspace["id"])["contracts"][0]
    assert after == before
    plan = service.plan(workspace["id"])
    assert {row["contract_id"] for row in plan["operations"]} == {contract["id"]}


def test_export_restore_retains_separate_definitions_references_and_requires_new_credential(setup):
    service, workspace, collection, _manager, attempts = setup
    source = "01-request-auth-override.bru"
    assign(service, workspace, collection, source)
    exported = service.export(workspace["id"])
    restored = service.restore(copy.deepcopy(exported))
    saved = restored["request_collections"][0]
    assert saved["id"] == collection["id"] and saved["hash"] == collection["hash"]
    assert [{key: value for key, value in row.items() if key != "identity"} for row in saved["operations"]] == [
        {key: value for key, value in row.items() if key != "identity"} for row in collection["operations"]]
    assert not operation(saved, source)["identity"]["credential_available"]
    assert not restored["contracts"]
    assert saved["request_assignments"][operation(collection, source)["id"]]["profile_id"] == "shared"
    desktop_requests.prepare(payload(restored, saved, source))
    with pytest.raises(ValueError, match="available identity"):
        desktop_requests.prepare(payload(restored, saved, source), dispatch=True)
    assert "local-bearer-value" not in json.dumps(exported)
    assert not attempts


def test_collection_mutation_rejected_and_removal_invalidates_pending_context(setup):
    service, workspace, collection, _manager, attempts = setup
    source = "02-no-auth.bru"
    row, _built, _preview = desktop_requests.prepare(payload(workspace, collection, source))
    for patch in ({"target": "http://127.0.0.1:1/new"}, {"config": {"allow_mutating": True}},
                  {"raw_spec": json.dumps(document("http://127.0.0.1:2", "accounts"))}):
        with pytest.raises(ValueError, match=r"collection|definition"):
            service.update_contract(workspace["id"], collection["id"], patch)
    assert row["scope_guard"]()
    removed = service.remove_contract(workspace["id"], collection["id"])
    assert not removed["request_collections"] and not row["scope_guard"]()
    assert not attempts


def test_restore_rebuilds_operation_rows_and_hash_from_saved_definition_material(setup):
    service, workspace, collection, _manager, attempts = setup
    exported = json.loads(json.dumps(service.export(workspace["id"])))
    saved = exported["workspace"]["request_collections"][0]
    saved["operations"][0]["request_definition"]["request"]["url"] = "http://127.0.0.1:1/tampered"
    restored = service.restore(exported)["request_collections"][0]
    assert restored["operations"][0]["request_definition"]["request"]["url"] != "http://127.0.0.1:1/tampered"
    assert restored["hash"] == collection["hash"]
    exported["workspace"]["request_collections"][0]["material"]["requests"][0]["request"]["url"] = "http://127.0.0.1:2/reviewed-new-definition"
    rebuilt = service.restore(exported)["request_collections"][0]
    assert rebuilt["hash"] != collection["hash"] and rebuilt["recorded_hash"] == collection["hash"]
    assert not attempts


@pytest.mark.parametrize("source", ["20-inert-script.bru", "21-graphql.bru", "28-owned-file.bru", "29-owned-multipart.bru"])
def test_restored_unsupported_definition_cannot_enable_itself_by_removing_blockers(setup, source):
    service, workspace, collection, manager, attempts = setup
    exported = json.loads(json.dumps(service.export(workspace["id"])))
    saved = exported["workspace"]["request_collections"][0]
    row = next(item for item in saved["material"]["requests"] if item["id"] == source)
    row.update(can_prepare=True, blockers=[])
    restored = service.restore(exported)
    current = restored["request_collections"][0]
    with pytest.raises(ValueError, match="cannot be sent faithfully"):
        manager.start(payload(restored, current, source, allow_mutating=True))
    assert not operation(current, source)["request_definition"]["can_prepare"]
    assert not attempts
