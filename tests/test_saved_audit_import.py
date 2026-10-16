"""Imported evidence is masked offline before UI state or exports receive it."""
import copy
import json

from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit.importing import sanitise_saved_audit
from namazu.audit.provenance import attach_snapshot_integrity
from namazu.audit.reporting import assess_saved_audit
from tests.ux_fixture_server import old_mixed_report


def record(**changes):
    return {"label": "baseline", "endpoint": "POST /local", "method": "POST", "url": "http://127.0.0.1/local",
            "request_headers": {"Authorization": "Bearer primary-secret-value", "Cookie": "sid=cookie-secret-value"},
            "request_body": '{"document":"example","password":"body-secret-value"}',
            "status": 403, "response_headers": {"content-type": "application/json"},
            "response_body": '{"detail":"denied"}', "error": "", **changes}


def export():
    baseline = record()
    return {"findings": [], "requests": [baseline], "coverage": {"baselines": [
        {"endpoint": "POST /local", "status": 403, "positive_control": False, "exchange": baseline}], "probes": []}}


def test_import_route_never_sends_requests_and_redacts_echoes_everywhere(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Opening a saved audit must be offline")
    monkeypatch.setattr("namazu.audit.transport.build_client", blocked)
    monkeypatch.setattr("namazu.audit.transport.Executor.send", blocked)
    monkeypatch.setattr("namazu.oauth.request_token", blocked)
    payload = export()
    secrets = ["primary-secret-value", "cookie-secret-value", "body-secret-value", "custom-key-value", "response-cookie-value"]
    payload["security_schemes"] = {"local": {"type": "apiKey", "in": "header", "name": "X-Team"}}
    payload["requests"][0]["request_headers"]["X-Team"] = "custom-key-value"
    payload["requests"][0]["response_headers"]["Set-Cookie"] = "sid=response-cookie-value; Path=/; HttpOnly"
    payload["requests"][0]["response_body"] = json.dumps({"detail": " ".join(secrets)})
    payload["readiness"] = {"configuration": {"request": {"headers": {"X-Team": "custom-key-value"}},
                                              "note": " ".join(secrets)}}
    payload["findings"] = [{"detail": " ".join(secrets), "assessment": {"category": "contract", "verification": "observed"}}]
    payload["contract_snapshots"] = {"POST /local": attach_snapshot_integrity({"operation": {
        "method": "POST", "path": "/local", "responses": {"403": {"description": "body-secret-value"}}}})}
    before = copy.deepcopy(payload)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post("/api/audit/import", json=payload)
    assert response.status_code == 200
    saved = response.json()
    assert all(secret not in response.text for secret in secrets)
    assert saved["requests"][0]["request_headers"]["X-Team"] == "<credential>"
    assert saved["readiness"]["configuration"]["request"]["headers"]["X-Team"] == "<credential>"
    assert saved["import_review"]["requests_sent"] == 0
    assert saved["import_review"]["contract"]["operations"][0]["hash_status"] == "mismatch"
    assert saved["contract_snapshots"]["POST /local"]["integrity"] == before["contract_snapshots"]["POST /local"]["integrity"]
    assert payload == before


def test_custom_query_credentials_and_har_header_entries_are_masked():
    payload = export()
    payload["spec"] = {"components": {"securitySchemes": {"custom": {"type": "apiKey", "in": "query", "name": "ticket"}}}}
    payload["requests"][0]["url"] += "?ticket=custom-query-value"
    payload["readiness"] = {"configuration": {"request": {"headers": [{"name": "Authorization", "value": "Bearer har-secret-value"}]},
                                              "description": "custom-query-value har-secret-value"}}
    result = json.dumps(sanitise_saved_audit(payload))
    assert "custom-query-value" not in result
    assert "har-secret-value" not in result


def test_masking_different_response_credentials_cannot_create_a_same_denial_claim():
    payload = export()
    baseline = payload["requests"][0]
    baseline["response_headers"]["set-cookie"] = "session=first-response-secret; HttpOnly"
    changed = record(label="changed field", response_headers={"content-type": "application/json",
                                                               "set-cookie": "session=second-response-secret; HttpOnly"})
    payload["requests"].append(changed)
    payload["coverage"]["probes"] = [{"family": "schema-inputs", "field_pointer": "/body/document",
                                       "status": "request-sent", "reason_code": "request-sent", "exchange": copy.deepcopy(changed)}]
    result = sanitise_saved_audit(payload)
    marker = result["requests"][1]["comparison_before_import_redaction"]
    assert marker["equivalent"] is False
    assert marker["meaningful_header_names"] == ["set-cookie"]
    assert result["coverage"]["probes"][0]["exchange"]["comparison_before_import_redaction"] == marker
    assert result["requests"][0]["response_headers"] == result["requests"][1]["response_headers"]
    assert assess_saved_audit(result)["request_accounting"]["endpoint"]["comparison-discrepancy"] == 1
    twice = sanitise_saved_audit(result)
    assert twice["requests"][1]["comparison_before_import_redaction"]["equivalent"] is False
    assert "first-response-secret" not in json.dumps(result)
    assert "second-response-secret" not in json.dumps(result)


def test_import_preserves_accounting_classification_and_unknown_fields():
    payload = old_mixed_report()
    payload["future_extension"] = {"opaque_record": [1, True, "retained"]}
    result = sanitise_saved_audit(payload)
    assert result["future_extension"] == payload["future_extension"]
    assert len(result["requests"]) == 141
    count = assess_saved_audit(result)["request_accounting"]["endpoint"]
    assert [count[key] for key in ["same-denial", "validation-observation", "edge-block", "incomplete-test"]] == [39, 28, 15, 6]
    assert result["coverage"]["checks"] == payload["coverage"]["checks"]


def test_short_credential_does_not_corrupt_typed_evidence_or_receipt_status():
    payload = export()
    payload["requests"][0]["request_headers"]["Authorization"] = "Bearer true"
    payload["requests"][0]["response_body"] = '{"enabled":true,"detail":"true"}'
    payload["coverage"]["probes"] = [{"status": "request-sent", "classification": "same-denial", "request_sent": True,
                                       "reason_code": "downstream-handling-unknown"}]
    result = sanitise_saved_audit(payload)
    assert json.loads(result["requests"][0]["response_body"]) == {"enabled": True, "detail": "<credential>"}
    assert result["coverage"]["probes"] == payload["coverage"]["probes"]
    assert result["coverage"]["baselines"][0]["positive_control"] is False


def test_numeric_body_credential_is_masked_without_changing_response_status():
    payload = export()
    payload["requests"][0]["request_body"] = '{"password":123456,"document":"example"}'
    payload["requests"][0]["response_body"] = '{"detail":"123456 was rejected","status":403}'
    result = sanitise_saved_audit(payload)
    assert json.loads(result["requests"][0]["request_body"])["password"] == "<credential>"
    assert "123456" not in result["requests"][0]["response_body"]
    assert result["requests"][0]["status"] == 403
