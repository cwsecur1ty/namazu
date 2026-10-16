"""Named OAuth identities against deterministic mock transports; no remote I/O."""
import json
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from namazu import identity_profiles as identities
from namazu import oauth
from namazu.workspaces import WorkspaceService


@pytest.fixture
def service(tmp_path):
    value = WorkspaceService(tmp_path / "workspaces.db")
    yield value
    value.close()


def configure(service, **changes):
    wid = changes.pop("workspace_id", None) or service.create("Local identities")["id"]
    body = identities.IdentityInput(name="Local client", endpoint="http://127.0.0.1:9087/token", client_id="client + café",
                                    client_secret="local-secret&=雪", scope="orders:read inventory:read").model_dump()
    body.update(changes)
    return wid, identities.save(service, wid, body)["profile_id"]


def mock_issuer(monkeypatch, handler):
    calls = []
    def wrapped(request):
        calls.append(request)
        return handler(request)
    monkeypatch.setattr(oauth, "connection_for", lambda *a, **k: SimpleNamespace(open=lambda: httpx.Client(transport=httpx.MockTransport(wrapped))))
    return calls


def settled(manager, wid, job):
    deadline = time.monotonic() + 3
    while (result := manager.get(wid, job["id"]))["state"] in {"requesting", "stopping"}:
        if time.monotonic() > deadline:
            raise AssertionError("Acquisition did not settle")
        time.sleep(0.005)
    return result


def test_configuration_is_offline_and_exact_form_is_explicit(service, monkeypatch):
    calls = mock_issuer(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "local-access-xyz", "token_type": "Bearer", "expires_in": 300, "scope": "orders:read"}))
    wid, pid = configure(service)
    profile = service.get(wid)["profiles"][0]
    assert profile["configuration_available"] and not profile["credential_available"] and not calls
    assert profile["oauth_config"]["client_id"] == "client + café"
    manager = identities.manager(service)
    result = settled(manager, wid, manager.start(wid, pid))
    assert result["state"] == "completed" and result["attempts"] == result["responses"] == 1
    request = calls[0]
    assert request.method == "POST" and str(request.url) == "http://127.0.0.1:9087/token"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert "authorization" not in request.headers
    assert parse_qs(request.content.decode(), keep_blank_values=True) == {"grant_type": ["client_credentials"], "scope": ["orders:read inventory:read"], "client_id": ["client + café"], "client_secret": ["local-secret&=雪"]}
    profile = service.get(wid)["profiles"][0]
    assert profile["credential_available"] and profile["acquisition"]["scope"] == "orders:read"
    assert profile["acquisition"]["policy"] == "explicit-only"
    exported = json.dumps(service.export(wid), ensure_ascii=False)
    persisted = service.path.read_bytes()
    assert "local-access-xyz" not in exported and "local-secret" not in exported
    assert b"local-access-xyz" not in persisted and b"local-secret" not in persisted
    assert len(calls) == 1


@pytest.mark.parametrize("body,expected", [
    ({"error": "invalid_client", "error_description": "echo-secret"}, "invalid_client"),
    ({"error": "invalid_scope", "error_description": "echo-secret"}, "invalid_scope"),
    ({"error": "unsupported_grant_type"}, "unsupported_grant_type"),
    ({"access_token": ""}, "missing-access-token"),
    ({"access_token": 47}, "missing-access-token"),
    ({"access_token": "a", "token_type": "DPoP"}, "unsupported-token-type"),
    ({"access_token": "a", "expires_in": "never"}, "malformed-expiry"),
    ({"access_token": "a", "expires_in": True}, "malformed-expiry"),
])
def test_safe_errors_do_not_adopt_tokens_or_echo_response(service, monkeypatch, body, expected):
    calls = mock_issuer(monkeypatch, lambda request: httpx.Response(400 if body.get("error") else 200, json=body))
    wid, pid = configure(service)
    manager = identities.manager(service)
    result = settled(manager, wid, manager.start(wid, pid))
    assert result["state"] == "failed" and result["code"] == expected
    assert "echo-secret" not in json.dumps(result) and not service.get(wid)["profiles"][0]["credential_available"]
    assert len(calls) == 1 and result["responses"] == 1


@pytest.mark.parametrize("kind,code,responses", [("timeout", "timeout", 0), ("html", "malformed-response", 1), ("redirect", "redirect-refused", 1)])
def test_timeout_malformed_and_redirect_are_bounded(service, monkeypatch, kind, code, responses):
    def handler(request):
        if kind == "timeout":
            raise httpx.ReadTimeout("echo-local-secret", request=request)
        if kind == "redirect":
            return httpx.Response(307, headers={"Location": "https://unassigned.invalid/steal"})
        return httpx.Response(200, text="<html>echo-local-secret</html>")
    calls = mock_issuer(monkeypatch, handler)
    wid, pid = configure(service)
    manager = identities.manager(service)
    result = settled(manager, wid, manager.start(wid, pid))
    assert result["code"] == code and result["responses"] == responses
    assert len(calls) == 1 and "echo-local-secret" not in json.dumps(result)


def test_concurrent_gets_coalesce_and_cancel_discards_inflight_result(service, monkeypatch):
    began, release = threading.Event(), threading.Event()
    def handler(request):
        began.set()
        assert release.wait(3)
        return httpx.Response(200, json={"access_token": "cancelled-access"})
    calls = mock_issuer(monkeypatch, handler)
    wid, pid = configure(service)
    manager = identities.manager(service)
    first = manager.start(wid, pid)
    assert began.wait(3)
    second = manager.start(wid, pid)
    assert first["id"] == second["id"]
    manager.stop(wid, first["id"])
    release.set()
    result = settled(manager, wid, first)
    assert result["state"] == "cancelled" and result["attempts"] == result["responses"] == 1
    assert len(calls) == 1 and not service.get(wid)["profiles"][0]["credential_available"]


def test_expiry_reacquisition_rotation_and_restoration(service, monkeypatch):
    expiry = [0]
    calls = mock_issuer(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "rotated-access-" + str(len(expiry)), "expires_in": expiry[-1]}))
    wid, pid = configure(service)
    plan = service.plan(wid, {})
    manager = identities.manager(service)
    settled(manager, wid, manager.start(wid, pid))
    assert service.get(wid)["profiles"][0]["acquisition"]["state"] == "expired"
    assert not service.get(wid)["profiles"][0]["credential_available"]
    assert next(p for p in service.get(wid)["plans"] if p["id"] == plan["id"])["status"] == "invalidated"
    expiry.append(600)
    settled(manager, wid, manager.start(wid, pid))
    assert service.get(wid)["profiles"][0]["credential_available"] and len(calls) == 2
    configure(service, workspace_id=wid, id=pid, client_secret="replacement-secret")
    assert not service.get(wid)["profiles"][0]["credential_available"] and len(calls) == 2
    restored = service.restore(service.export(wid))
    assert restored["profiles"][0]["oauth_config"]["grant"] == "client_credentials"
    assert not restored["profiles"][0]["configuration_available"] and len(calls) == 2


def test_body_and_basic_auth_are_distinct_and_empty_scope_is_encoded(service, monkeypatch):
    calls = mock_issuer(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "basic-token"}))
    wid, pid = configure(service, credential_placement="basic", scope="", client_id="simple", client_secret="private")
    manager = identities.manager(service)
    settled(manager, wid, manager.start(wid, pid))
    assert calls[0].headers["authorization"].startswith("Basic ")
    assert parse_qs(calls[0].content.decode(), keep_blank_values=True) == {"grant_type": ["client_credentials"], "scope": [""]}


def test_two_contract_assignments_leave_third_anonymous_and_override_wins(service, monkeypatch):
    mock_issuer(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "shared-token"}))
    wid, pid = configure(service)
    documents = [{"raw_spec": {"openapi": "3.0.3", "info": {"title": name, "version": "1"}, "servers": [{"url": f"http://127.0.0.1:{port}/v1"}], "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}}}} for name, port in [("A", 9011), ("B", 9012), ("C", 9013)]]
    workspace = service.import_contracts(wid, documents)
    contracts = workspace["contracts"]
    identities.assign(service, wid, pid, [{"contract_id": c["id"], "allowed_scopes": [c["target"]]} for c in contracts[:2]])
    manager = identities.manager(service)
    settled(manager, wid, manager.start(wid, pid))
    rows = []
    for c in contracts:
        rows.append(service.request_context(wid, c["id"], c["hash"], c["operations"][0]["id"]))
    assert [bool(row["identities"]) for row in rows] == [True, True, False]
    assert all(not row["allow_mutating"] for row in rows)
    service.set_profile(wid, {"name": "Override", "token": "override-token"})
    override = service.get(wid)["profiles"][-1]
    service.assign_identity(wid, contracts[0]["id"], {"profile_id": override["id"], "override": True, "allowed_scopes": [contracts[0]["target"]]})
    row = service.request_context(wid, contracts[0]["id"], contracts[0]["hash"], contracts[0]["operations"][0]["id"])
    assert row["identity_ref"] == override["id"]
    identities.assign(service, wid, pid, [{"contract_id": contracts[1]["id"], "remove": True}])
    row = service.request_context(wid, contracts[1]["id"], contracts[1]["hash"], contracts[1]["operations"][0]["id"])
    assert row["identities"] == {}
    with pytest.raises(ValueError, match="inside"):
        identities.assign(service, wid, pid, [{"contract_id": contracts[2]["id"], "allowed_scopes": ["http://127.0.0.1:9999"]}])
