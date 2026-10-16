"""End-to-end audit regressions, exclusively on in-process local mock targets."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit import engine
from namazu.audit.transport import Budget, Executor, MutationRefused, Pace
from namazu.spec import parse_spec

BASE = "http://127.0.0.1:8765"
SECRET = 'local-secret-quote"-93427'


def specification():
    return parse_spec({
        "openapi": "3.1.0", "info": {"title": "Local denied baseline", "version": "1"},
        "servers": [{"url": BASE}],
        "components": {"securitySchemes": {"credential": {
            "type": "apiKey", "in": "header", "name": "X-Customer"}}},
        "paths": {"/widgets": {"post": {
            "security": [{"credential": []}],
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object", "properties": {
                    "enabled": {"type": "boolean"},
                    "quantity": {"type": "integer", "minimum": 1, "maximum": 5},
                    "label": {"type": "string", "minLength": 2, "maxLength": 8},
                    "server_id": {"type": "integer", "readOnly": True},
                }}}}},
            "responses": {"201": {"description": "Created", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"response_only": {"type": "string"}}}}}},
                          "403": {"description": "Denied"}},
        }}},
    }, BASE)


def options(**extra):
    return {"profile": "writes", "allow_mutating": True,
            "identities": {"primary": {"headers": {
                "Authorization": "Bearer local-bearer-93427", "X-Customer": SECRET,
                "Cookie": "session=local-session-93427; preference=saved", "X-Keep": "untouched"}}},
            "example": {"body": {"enabled": True, "quantity": 3, "label": "saved",
                                   "password": SECRET}}, **extra}


def audit(handler=None, **extra):
    seen = []

    def local(request):
        seen.append(request)
        return handler(request) if handler else httpx.Response(403, json={"detail": "Not entitled"})

    with httpx.Client(transport=httpx.MockTransport(local)) as client:
        result = engine.audit_operation(specification(), "POST /widgets", client=client, **options(**extra))
    return result, seen


def check(result, name):
    return next(row for row in result["coverage"]["checks"] if row["check"] == name)


def test_uniform_denial_has_per_field_receipts_and_honest_family_coverage():
    result, seen = audit()
    probes = [row for row in result["probes"] if row.get("id") and row["request_sent"]]
    assert probes
    assert {row["status"] for row in probes} == {"same-denial-as-baseline"}
    assert {row["field_pointer"] for row in result["field_coverage"]} >= {
        "/enabled", "/quantity", "/label", "/server_id"}
    assert "/response_only" not in {row["field_pointer"] for row in result["field_coverage"]}
    assert all(row["requests_sent"] for row in result["field_coverage"]
               if row["field_pointer"] in ("/enabled", "/quantity", "/label", "/server_id"))
    assert check(result, "schema-inputs")["state"] == "inconclusive"
    assert check(result, "access-bypass")["state"] != "completed"
    assert check(result, "access-bypass")["requests"] == 0
    missing = check(result, "write-authorization")["reason_codes"]
    assert "missing-second-identity" in missing and "positive-control-required" in missing
    breakdown = result["request_breakdown"]
    assert breakdown["inventory"] == 0
    assert breakdown["schema_inputs"] == len(probes)
    assert breakdown["baseline"] == 1
    assert sum(value for name, value in breakdown.items() if name != "total") == len(seen) == result["requests_sent"]
    assert len(result["log"]) == len(seen)
    assert not any(row["id"].startswith("input.") for row in result["findings"])


def test_schema_requests_preserve_credentials_and_unmodified_fields_and_export_redacts_echoes():
    def handler(request):
        return httpx.Response(403, json={"detail": "Denied " + SECRET,
                                         "opaque_echo": SECRET}, headers={"X-Echo": SECRET})

    result, seen = audit(handler)
    baseline = json.loads(seen[0].content)
    for probe in (row for row in result["probes"] if row.get("id") and row["request_sent"]):
        exchange = probe["exchange"]
        request = next(row for row in result["log"] if row["label"] == exchange["label"])
        actual = seen[request["seq"] - 1]
        payload = json.loads(actual.content)
        changed = {key for key in baseline.keys() | payload.keys() if baseline.get(key) != payload.get(key)}
        assert changed == {probe["field_pointer"][1:]}
        assert payload["password"] == SECRET
        for header in ("authorization", "x-customer", "cookie", "x-keep"):
            assert actual.headers[header] == seen[0].headers[header]
        assert exchange["response_body"] and exchange["request_body"]
    exported = json.dumps(result)
    for value in (SECRET, json.dumps(SECRET)[1:-1], "local-bearer-93427", "local-session-93427"):
        assert value not in exported


def test_budget_exhaustion_is_recorded_for_every_unsent_case():
    result, seen = audit(request_budget=6)
    assert len(seen) == result["requests_sent"] == 6
    assert result["request_budget"] == 6
    assert result["request_breakdown"]["schema_inputs"] == 5
    assert any(row["status"] == "budget-exhausted" for row in result["probes"])
    assert check(result, "schema-inputs")["state"] == "budget-exhausted"
    assert all(row["status"] != "planned" for row in result["probes"])


def test_expected_denial_never_unlocks_success_dependent_checks():
    result, _ = audit(expectation={"status": "403", "negative": True})
    assert result["baseline_outcome"] == "success"
    assert result["baseline_verdict"]["positive_control"] is False
    for family in ("authorization", "credential-handling", "jwt", "write-authorization"):
        assert check(result, family)["state"] == "blocked"
        assert check(result, family)["requests"] == 0


def test_plan_api_sends_nothing_including_oauth_and_records_budget(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Planning must not acquire tokens or send target requests")

    monkeypatch.setattr(engine.identity_resolver, "resolve", forbidden)
    monkeypatch.setattr(Executor, "send", forbidden)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post("/api/audit/plan", json={"spec": specification(),
            "operation_id": "POST /widgets", **options(request_budget=8,
                identities={"primary": {"oauth": {"token_endpoint": BASE + "/token"}}})})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["target_requests_sent"] == 0
    assert result["request_budget"] == 8
    assert result["test_plan"]["budgeted_requests"] <= 7
    assert result["test_plan"]["supplemental_probes"]
    cross = next(row for row in result["test_plan"]["supplemental_checks"] if row["check"] == "cross-identity")
    assert "second-identity" in cross["missing_prerequisites"]


def test_profile_permission_and_scope_are_enforced_before_target_requests():
    result, seen = audit(profile="readonly")
    assert not seen and result["requests_sent"] == 0
    assert all(not row.get("request_sent") for row in result["probes"])
    with pytest.raises(ValueError, match="selected target origin"):
        audit(example={"url": "http://outside.test/widgets"})
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("out of scope"))) as client:
        executor = Executor(client, Budget(5), scope_url=BASE)
        with pytest.raises(MutationRefused, match="origin"):
            executor.send("GET", "http://outside.test/", label="blocked")
        assert executor.budget.spent == 0


def test_target_rate_limit_stops_campaign_without_retrying():
    result, seen = audit(lambda _: httpx.Response(429, headers={"Retry-After": "60"}))
    assert len(seen) == 1
    schema = [row for row in result["probes"] if row.get("id")]
    assert schema and not any(row["request_sent"] for row in schema)
    assert any("rate-limit" in row["reason_code"] for row in schema)


def test_shared_pacing_honors_configured_rate_without_real_sleep(monkeypatch):
    from namazu.audit import transport
    clock = [10.0]
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(transport.time, "sleep", sleep)
    pace = Pace(2)
    pace.wait()
    pace.wait()
    assert slept == [0.5]


def test_transport_failure_blocks_field_cases_with_receipts():
    def broken(_):
        raise httpx.ConnectError("local fixture failed")

    result, seen = audit(broken)
    assert len(seen) == 1
    assert result["baseline_outcome"] == "transport-failure"
    assert result["field_coverage"]
    assert all(row["status"] == "blocked-prerequisite" for row in result["probes"]
               if row.get("id") and row.get("planned_requests"))


def test_inventory_budget_and_custom_credentials_are_reported_separately():
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(404, text="missing " + SECRET))) as client:
        result = engine.audit_inventory(specification(), base_url=BASE, client=client,
                                        identities=options()["identities"], budget=6, concurrency=1)
    assert result["request_breakdown"] == {"inventory": result["requests_sent"],
        "baseline": 0, "schema_inputs": 0, "other_endpoint_tests": 0, "total": result["requests_sent"]}
    assert result["requests_sent"] <= 6
    serialized = json.dumps(result)
    assert SECRET not in serialized and json.dumps(SECRET)[1:-1] not in serialized


def test_inventory_stops_on_target_rate_limit():
    seen = []

    def limited(request):
        seen.append(request)
        return httpx.Response(429, headers={"Retry-After": "60"})

    with httpx.Client(transport=httpx.MockTransport(limited)) as client:
        result = engine.audit_inventory(specification(), base_url=BASE, client=client, concurrency=1)
    assert len(seen) == 1
    assert result["coverage"]["checks"][-1]["state"] == "blocked"
