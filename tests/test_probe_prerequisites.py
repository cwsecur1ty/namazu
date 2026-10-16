"""Local mock regressions for individual probe gates and execution receipts."""
import json

import httpx
import pytest

from namazu.audit import authz, bypass, engine, inputs, jwtlab, posture, probes
from namazu.audit.model import Exchange
from namazu.audit.transport import Budget, Executor

BASE = "http://127.0.0.1:8765"
HEADERS = {"Authorization": "Bearer do-not-export-this", "Cookie": "session=private"}


def baseline(method="POST", status=403, body='{"detail":"not entitled"}'):
    return Exchange(label="baseline", method=method, url=f"{BASE}/items?filter=ok",
                    request_headers={**HEADERS, "Content-Type": "application/json"},
                    request_body='{"name":"example","enabled":true,"count":3}',
                    status=status, body=body, headers={"content-type": "text/plain; charset=utf-8"})


def test_uniform_denial_records_sent_and_blocked_probes_without_validation_claim():
    saved = baseline()
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(403, text=saved.body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(80), allow_mutating=True)
        findings, fields = inputs.body_injection(executor, baseline=saved, endpoint="POST /items",
                                                base_headers=HEADERS, max_fields=3)
    assert not findings
    assert set(fields) == {"name", "count"}
    observed = [r for r in executor.probe_results if r["request_sent"]]
    assert observed and all(r["status"] == "same-denial" for r in observed)
    assert all("unknown" in r["reason"] for r in observed)
    blocked = [r for r in executor.probe_results if r["check"] == "sql-boolean"]
    assert len(blocked) == 2
    assert all("successful-positive-control" in r["missing_prerequisites"] for r in blocked)
    assert all(request.headers["authorization"] == HEADERS["Authorization"] for request in sent)
    assert all(request.headers["cookie"] == HEADERS["Cookie"] for request in sent)
    original = json.loads(saved.request_body)
    assert all(sum(value != json.loads(request.content)[key] for key, value in original.items()) == 1
               for request in sent)


def test_field_error_before_entitlement_is_a_lead_and_control_is_recorded():
    saved = baseline()

    def handler(request):
        if json.loads(request.content)["name"] == "'":
            return httpx.Response(500, text="SQLSTATE[42000]: parser rejected this input")
        return httpx.Response(403, text=saved.body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(20), allow_mutating=True)
        findings = probes.run(executor, "sql-error", lambda: inputs._sql_error(
            executor, saved, "POST /items", inputs.BodyPoint(["name"]), HEADERS),
            family="body-injection", baseline=saved, endpoint="POST /items",
            field=inputs.BodyPoint(["name"]))
    assert len(findings) == 1
    assert "lead" in findings[0].detail
    assert "does not establish which server layer" in findings[0].detail
    assert executor.probe_results[0]["status"] == "field-response-observed"
    assert executor.probe_results[0]["requests"] == 2


@pytest.mark.parametrize("check,payload,error", [
    (inputs._sql_error, "'", "SQLSTATE[42000]: parser error"),
    (inputs._nosql, "[$ne]", "MongoServerError: parser error"),
    (inputs._ldap_error, "*)(|(objectClass=*", "LDAPException: invalid filter"),
])
def test_a_failed_paired_control_does_not_produce_an_injection_finding(check, payload, error):
    saved = baseline()

    def handler(request):
        if json.loads(request.content)["name"] == payload:
            return httpx.Response(500, text=error)
        raise httpx.ConnectError("local mock control unavailable")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(10), allow_mutating=True)
        assert check(executor, saved, "POST /items", inputs.BodyPoint(["name"]), HEADERS) == []


def test_early_return_from_post_bypass_is_blocked_with_no_completed_probes():
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("must not send"))) as client:
        executor = Executor(client, Budget(10), allow_mutating=True)
        assert bypass.probe(executor, baseline=baseline(), endpoint="POST /items", headers=HEADERS) == []
    assert len(executor.probe_results) == 2
    assert all(r["status"] == "blocked-prerequisite" and not r["request_sent"]
               and "read-only-method" in r["missing_prerequisites"] for r in executor.probe_results)


def test_bypass_response_differences_are_leads_without_an_authorized_control():
    saved = baseline("GET")
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"other": "route"}))) as client:
        executor = Executor(client, Budget(30))
        findings = bypass.probe(executor, baseline=saved, endpoint="GET /items", headers=HEADERS)
        findings += authz._method_tampering(executor, saved, "GET /items", HEADERS)
    assert findings
    assert all(f.confidence == "possible" and f.category == "informational" for f in findings)
    assert all(f.evidence["signal_only"] for f in findings)


def test_a_sibling_budget_decline_does_not_mark_this_probe_exhausted():
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))) as client:
        executor = Executor(client, Budget(1))
        sibling = executor.branch()
        with probes.track(executor, "first", family="input-handling", baseline=baseline("GET", 200)):
            executor.send("GET", BASE, label="single funded request")
            assert not sibling.affordable(1)
    assert executor.probe_results[0]["status"] == "request-sent"
    assert executor.budget_declines == 0 and sibling.budget_declines == 1


def test_denied_authorization_lists_every_missing_prerequisite_but_runs_cors_and_methods():
    saved = baseline("GET")
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(403, text=saved.body))) as client:
        executor = Executor(client, Budget(10))
        authz.probe(executor, baseline=saved, endpoint="GET /items", operation={},
                    identity_a=HEADERS, identity_b=None, base_headers=HEADERS)
    cross = next(r for r in executor.probe_results if r["family"] == "cross-identity")
    assert cross["missing_prerequisites"] == ["successful-positive-control", "second-identity"]
    assert next(r for r in executor.probe_results if r["check"] == "cors-reflection")["request_sent"]
    assert next(r for r in executor.probe_results if r["check"] == "method-tampering")["request_sent"]


def test_expected_denial_and_failed_success_expectation_are_not_positive_controls():
    saved = baseline()
    saved.positive_control = False
    assert not probes.successful(saved)
    saved.status = 200
    assert not probes.successful(saved)


def test_jwt_replay_requires_success_while_offline_analysis_remains_available():
    token = jwtlab.forge_hmac({"sub": "alice"}, "secret")
    identity = {"Authorization": f"Bearer {token}"}
    assert jwtlab.analyze(token)["cracked_secret"] == "secret"
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("must not send"))) as client:
        executor = Executor(client, Budget(10))
        assert authz._jwt_replay(executor, baseline("GET"), "GET /items", identity, identity) == []
    assert executor.budget.spent == 0


def test_recovered_signing_key_is_redacted_from_offline_and_replay_findings():
    signing_key = "your-256-bit-secret"
    token = jwtlab.forge_hmac({"sub": "alice", "role": "user"}, signing_key)
    identity = {"Authorization": f"Bearer {token}"}
    offline = engine._supplied_token_findings(identity, "GET /items")
    assert any(item.id == "jwt.weak-secret" for item in offline)
    assert signing_key not in json.dumps([item.to_dict() for item in offline])
    saved = baseline("GET", 200, '{"private":"resource"}')
    saved.request_headers = identity
    anonymous = baseline("GET", 401, '{"detail":"credential required"}')

    def handler(request):
        supplied = request.headers["authorization"].split(" ", 1)[1]
        return httpx.Response(200, json={"private": "resource"}) if jwtlab.verify_hmac(
            supplied, signing_key) else httpx.Response(401, json={"detail": "invalid signature"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(10))
        replay = authz._jwt_replay(executor, saved, "GET /items", identity, identity, anonymous)
    assert any(item.id == "jwt.forged-token-accepted" for item in replay)
    assert signing_key not in json.dumps([item.to_dict() for item in replay])


def test_denied_posture_keeps_trace_but_blocks_success_dependent_resource_comparisons():
    saved = baseline("GET")
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(403, text=saved.body))) as client:
        executor = Executor(client, Budget(10))
        posture.review(executor, baseline=saved, endpoint="GET /items", headers=HEADERS,
                       operation={"parameters": [{"in": "query", "name": "limit"}]},
                       base_url=saved.url, do_rate_limit=True)
    sent = [r["check"] for r in executor.probe_results if r["request_sent"]]
    assert sent == ["trace"]
    for check in ("pagination-bound", "bounded-rate-observation"):
        assert "successful-positive-control" in next(
            r["missing_prerequisites"] for r in executor.probe_results if r["check"] == check)


def test_probe_budget_redaction_and_execution_error_are_separate():
    saved = baseline()
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(403, text=saved.body))) as client:
        executor = Executor(client, Budget(1), allow_mutating=True)
        inputs.body_injection(executor, baseline=saved, endpoint="POST /items", base_headers=HEADERS)
    assert executor.budget.spent == 1
    assert any(r["status"] == "budget-exhausted" for r in executor.probe_results)
    serialized = json.dumps(executor.probe_results)
    assert HEADERS["Authorization"] not in serialized
    assert HEADERS["Cookie"] not in serialized
    with httpx.Client(transport=httpx.MockTransport(lambda _: (_ for _ in ()).throw(httpx.ConnectError("mock")))) as client:
        executor = Executor(client, Budget(2))
        probes.run(executor, "local-error", lambda: executor.send("GET", BASE, label="local mock"),
                   family="input-handling", baseline=saved)
    assert executor.probe_results[0]["status"] == "execution-error"


def test_credentials_are_not_selected_as_input_fields():
    saved = baseline("GET")
    saved.url += "&access_token=secret"
    fields = inputs.points(saved, documented_cookie=[{"name": "session"}, {"name": "filter"}],
                           documented_header=[{"name": "Authorization"}, {"name": "X-Filter"}])
    assert not {"session", "Authorization", "access_token"} & {str(field) for field in fields}
    saved.request_body = '{"name":"example","password":"credential"}'
    assert [str(field) for field in inputs._body_points(saved, 10)] == ["name"]
    fields = inputs.points(saved, documented_header=[{"name": "X-Customer-Access"}],
                           credential_names=["x-customer-access"])
    assert "X-Customer-Access" not in fields
    saved.request_body = '{"name":"example","opaqueCredential":"credential"}'
    assert [str(field) for field in inputs._body_points(saved, 10, ["opaqueCredential"])] == ["name"]


def test_legacy_body_battery_only_mutates_writable_request_schema_pointers():
    saved = baseline()
    original = {"name": "example", "id": "read-only-id", "responseOnly": "response-field",
                "extra": "saved-baseline-extra", "nested": {"a/b": "writable"}}
    saved.request_body = json.dumps(original)
    allowed = {"/name", "/nested/a~1b"}
    assert {probes.pointer(point) for point in inputs._body_points(
        saved, 10, allowed_body_pointers=allowed)} == allowed
    assert inputs._body_points(saved, 10, allowed_body_pointers=[]) == []
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(403, text=saved.body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(50), allow_mutating=True)
        executor.writable_body_pointers = allowed
        inputs.body_injection(executor, baseline=saved, endpoint="POST /items",
                              base_headers=HEADERS, max_fields=10)
    assert seen
    assert all(body["id"] == original["id"] and body["responseOnly"] == original["responseOnly"]
               and body["extra"] == original["extra"] for body in seen)
    assert {row["field_pointer"] for row in executor.probe_results} <= allowed


def test_legacy_mass_assignment_changes_one_writable_property_per_saved_request():
    original = {"role": "user", "nested": {"is_admin": False}, "owner": "readonly",
                "unchanged": 12}
    built = {"method": "PATCH", "url": BASE + "/items/1", "body": original,
             "has_body": True, "content_type": "application/json"}
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=bodies[-1])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        executor = Executor(client, Budget(10), allow_mutating=True)
        executor.writable_body_pointers = {"/role", "/nested/is_admin"}
        findings = inputs.mass_assignment(executor, built=built, endpoint="PATCH /items/1",
                                          base_headers=HEADERS, properties=["role", "nested.is_admin", "owner"])
    assert bodies == [{**original, "role": "admin"}, {**original, "nested": {"is_admin": True}}]
    assert len(findings) == 2
    skipped = next(row for row in executor.probe_results if row["field_pointer"] == "/owner")
    assert skipped["status"] == "blocked-prerequisite"
    assert "writable-request-schema-property" in skipped["missing_prerequisites"]


def test_write_with_the_same_identity_records_a_missing_distinct_identity():
    built = {"method": "PATCH", "url": BASE + "/items/1", "body": {"name": "saved"},
             "has_body": True, "content_type": "application/json"}
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("must not send"))) as client:
        executor = Executor(client, Budget(10), allow_mutating=True)
        assert inputs.write_authorization(executor, built=built, endpoint="PATCH /items/1",
                                          base_headers=HEADERS, identity_b=HEADERS) == []
    assert executor.probe_results[0]["status"] == "blocked-prerequisite"
    assert "distinct-second-identity-required" in executor.probe_results[0]["missing_prerequisites"]


def test_supplemental_probe_plan_is_deterministic_and_has_no_credentials():
    saved = baseline()
    kwargs = {"endpoint": "POST /items", "fields": [inputs.BodyPoint(["name"])], "budget": 40}
    planned = inputs.battery_plan(saved, **kwargs)
    assert planned == inputs.battery_plan(saved, **kwargs)
    assert all(p["field_pointer"] == "/name" and p["request_count_kind"] == "upper-bound"
               and p["conditional"] and p["budget"] == 40 for p in planned)
    assert HEADERS["Authorization"] not in json.dumps(planned)
