"""Configured opaque credential names preserve wire inputs and mask all evidence."""
import json

import httpx
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit import authz, inputs
from namazu.audit.engine import audit_inventory, audit_operation, audit_plan
from namazu.audit.identity import same_principal, strip_credentials
from namazu.audit.model import Exchange
from namazu.audit.reporting import assess_saved_audit
from namazu.audit.transport import Budget, Executor
from namazu.discovery import Connection
from namazu.runner import execute_request, prepare_request

SECRET = "local-workspace-credential"
BASE = "http://127.0.0.1:9876"
HEADERS = {"X-Workspace": SECRET, "Accept": "application/json"}


def document():
    return {"openapi": "3.0.3", "info": {"title": "Local custom credential", "version": "1"},
            "servers": [{"url": BASE}], "paths": {"/items": {"post": {
                "parameters": [{"in": "header", "name": "X-Workspace", "required": True,
                                "schema": {"type": "string", "example": "example"}}],
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
                    "document": {"type": "string", "example": "local-document"},
                    "enabled": {"type": "boolean", "example": True}}}}}},
                "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object"}}}},
                              "403": {"description": "denied"}}}}}}


def test_single_request_masks_configured_key_and_echoes_without_changing_wire():
    seen = []
    body = {"document": "local-document", "echo": SECRET}

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"document": "local-document", "echo": request.headers["X-Workspace"]},
                              headers={"X-Observed": SECRET, "X-Workspace": SECRET})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(document(), "POST /items", body=body, headers=HEADERS,
                                 credential_names=["X-Workspace"], allow_mutating=True, client=client)
    assert len(seen) == 1
    assert seen[0].headers["X-Workspace"] == SECRET
    assert json.loads(seen[0].content) == body
    assert result["request"]["headers"]["x-workspace"] == "<credential>"
    assert result["request"]["headers"]["accept"] == "application/json"
    assert result["response"]["status"] == 200
    assert result["validation"]["valid"] is True
    assert SECRET not in json.dumps(result)
    assert result["credential_names"] == ["x-workspace"]


def test_prepare_masks_preview_without_network_and_retains_schema_validation():
    result = prepare_request(document(), "POST /items", headers=HEADERS, body={"document": SECRET},
                             credential_names=["X-Workspace"])
    assert SECRET not in json.dumps(result)
    assert result["headers"]["Accept"] == "application/json"
    assert result["body"]["document"] == "<credential>"
    assert result["request_validation"]["valid"] is True


def test_declared_and_configured_names_are_combined_for_single_request_preview():
    spec = document()
    spec["components"] = {"securitySchemes": {"documented": {"type": "apiKey", "in": "header", "name": "X-Declared"}}}
    result = prepare_request(spec, "POST /items", headers={**HEADERS, "X-Declared": "declared-secret"},
                             credential_names=["X-Workspace"])
    assert result["credential_names"] == ["x-declared", "x-workspace"]
    assert "declared-secret" not in json.dumps(result)
    assert SECRET not in json.dumps(result)


def test_custom_credential_parameter_is_preserved_in_plan_and_every_input_probe():
    identities = {"primary": {"headers": HEADERS}}
    plan = audit_plan(document(), "POST /items", identities=identities, profile="writes", allow_mutating=True,
                      request_budget=5, credential_names=["X-Workspace"])
    protected = [row for row in plan["test_plan"]["probes"] if row.get("field_pointer") == "/header/X-Workspace"]
    assert protected
    assert all("credential-preserved" in row.get("missing_prerequisites", []) for row in protected)
    assert SECRET not in json.dumps(plan)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(403, json={"detail": "denied", "echo": SECRET})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_operation(document(), "POST /items", identities=identities, profile="writes", allow_mutating=True,
                                 request_budget=5, credential_names=["X-Workspace"], client=client)
    assert result["requests_sent"] == len(seen) == 5
    assert all(request.headers["X-Workspace"] == SECRET for request in seen)
    assert SECRET not in json.dumps(result)
    assert result["credential_names"] == ["x-workspace"]
    assert all(row["request_headers"]["x-workspace"] == "<credential>" for row in result["log"])


def test_inventory_masks_custom_credential_echoes_and_keeps_typed_counts():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(404, json={"echo": request.headers["X-Workspace"], "valid": True})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_inventory(document(), identities={"primary": {"headers": {"X-Workspace": "true"}}},
                                 credential_names=["X-Workspace"], budget=3, client=client)
    assert result["requests_sent"] == len(seen) == 3
    assert all(request.headers["X-Workspace"] == "true" for request in seen)
    assert all(json.loads(row["response_body"]) == {"echo": "<credential>", "valid": True} for row in result["log"])


def test_live_masked_header_difference_does_not_become_same_denial():
    count = 0

    def handler(_request):
        nonlocal count
        count += 1
        return httpx.Response(403, json={"detail": "denied"}, headers={"X-Workspace": f"response-key-{count}"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_operation(document(), "POST /items", identities={"primary": {"headers": HEADERS}},
                                 credential_names=["X-Workspace"], profile="writes", allow_mutating=True,
                                 request_budget=3, client=client)
    assert "response-key-" not in json.dumps(result)
    assert all(row["comparison_before_import_redaction"]["equivalent"] is False for row in result["log"][1:])
    assert all(row["comparison_before_import_redaction"]["meaningful_header_names"] == ["x-workspace"] for row in result["log"][1:])
    compared = [probe["exchange"]["comparison_before_import_redaction"] for probe in result["probes"]
                if probe.get("exchange", {}).get("comparison_before_import_redaction")]
    assert compared and all(item["equivalent"] is False for item in compared)
    assessed = assess_saved_audit({"findings": [], "requests": result["log"], "coverage": {
        "baselines": [{"endpoint": result["endpoint"], "status": 403, "exchange": result["baseline"]}],
        "probes": result["probes"]}})
    assert assessed["request_accounting"]["endpoint"].get("same-denial", 0) == 0
    assert assessed["request_accounting"]["endpoint"]["comparison-discrepancy"] == 2


def test_local_routes_forward_explicit_names_to_prepare_run_audit_and_inventory(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(403, json={"echo": SECRET, "detail": "denied"})

    monkeypatch.setattr(Connection, "open", lambda _self: httpx.Client(transport=httpx.MockTransport(handler)))
    with TestClient(app, base_url="http://127.0.0.1") as client:
        request = {"spec": document(), "operation_id": "POST /items", "credential_names": ["X-Workspace"],
                   "headers": HEADERS, "allow_mutating": True}
        preview = client.post("/api/prepare", json=request)
        assert preview.status_code == 200
        assert not seen
        run = client.post("/api/run", json=request)
        assert run.status_code == 200
        audit = client.post("/api/audit", json={"spec": document(), "operation_id": "POST /items", "profile": "writes",
                           "credential_names": ["X-Workspace"], "identities": {"primary": {"headers": HEADERS}},
                           "allow_mutating": True, "request_budget": 1})
        assert audit.status_code == 200
        inventory = client.post("/api/audit/inventory", json={"spec": document(), "credential_names": ["X-Workspace"],
                                  "identities": {"primary": {"headers": HEADERS}}, "budget": 1})
        assert inventory.status_code == 200
        assert all(SECRET not in result.text for result in (preview, run, audit, inventory))
        assert all(request.headers["X-Workspace"] == SECRET for request in seen)


def test_anonymous_control_removes_custom_and_standard_credentials_without_false_finding():
    seen = []
    headers = {**HEADERS, "Authorization": "Bearer another-local-credential"}

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"document": "private"}) if request.headers.get("X-Workspace") == SECRET else httpx.Response(401, json={"detail": "unauthorized"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(3))
        executor.redacted_names = {"x-workspace"}
        baseline = executor.send("GET", BASE + "/orders/1", headers=headers, label="baseline")
        findings, anonymous = authz._anonymous_replay(executor, baseline, "GET /orders/1", True, True, headers)
    assert seen[0].headers["X-Workspace"] == SECRET
    assert "X-Workspace" not in seen[1].headers
    assert "Authorization" not in seen[1].headers
    assert seen[1].headers["Accept"] == "application/json"
    assert anonymous.status == 401
    assert not findings


def test_same_custom_credential_cannot_supply_a_distinct_second_identity_or_write():
    names = {"x-workspace"}
    assert same_principal(HEADERS, {"x-workspace": SECRET}, names)
    assert same_principal(HEADERS, {"x-workspace": "other-private-key"}, names) is None
    assert strip_credentials(HEADERS, names) == {"Accept": "application/json"}
    seen, notes = [], []
    with httpx.Client(transport=httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200, json={}))) as client:
        executor = Executor(client, Budget(2), allow_mutating=True)
        executor.redacted_names = names
        baseline = Exchange(label="baseline", method="GET", url=BASE + "/orders/1", status=200, body='{"document":"private"}')
        assert not authz._cross_identity(executor, baseline, "GET /orders/1", {"x-workspace": SECRET}, HEADERS, True, notes=notes)
        assert not inputs.write_authorization(executor, built={"method": "POST", "url": BASE + "/orders/1", "body": {}},
                                              endpoint="POST /orders/1", base_headers=HEADERS, identity_b={"x-workspace": SECRET}, notes=notes)
    assert not seen
    assert any("same credential" in note for note in notes)


def test_metadata_and_generated_markers_are_not_global_secret_sources():
    from namazu.runner import redact_evidence

    value = {"summary": {"authentication": 1}, "evidence": {"original": "1", "signature": "Python traceback",
              "error_signature": "getaddrinfo", "token_algorithm": "RS256", "key_encoding": "PKCS#1 PEM",
              "sent_value": "Bearer namazu.invalid.credential"},
             "probe": {"request_headers": {"Cookie": "filter='"}}, "note": "The target's marker is namazu.invalid.credential"}
    result = redact_evidence(value, sources=[{"headers": {"Authorization": "Bearer private-source"}}])
    assert result["evidence"] == value["evidence"]
    assert result["summary"] == value["summary"]
    assert result["note"] == value["note"]
    assert result["probe"]["request_headers"]["Cookie"] == "<credential>"
