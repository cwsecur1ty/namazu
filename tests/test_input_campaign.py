"""Local MockTransport fixtures for denied-baseline parameter campaigns."""
import copy
import json
from urllib.parse import parse_qs

import httpx
import pytest

from namazu.audit.campaign import _body_text, execute_campaign, plan_campaign
from namazu.audit.transport import Budget, Executor
from namazu.spec import build_request, parse_spec

BASE = "http://127.0.0.1:8765"
SECRET = "local-fixture-credential-93427"


def document():
    return {
        "openapi": "3.1.0", "info": {"title": "Local campaign fixture", "version": "1"},
        "servers": [{"url": BASE}],
        "components": {
            "schemas": {
                "Input": {"allOf": [
                    {"$ref": "#/components/schemas/Flags"},
                    {"type": "object", "required": ["quantity", "label"], "properties": {
                        "quantity": {"type": "integer", "minimum": 1, "maximum": 5},
                        "price": {"type": "number", "exclusiveMinimum": 0, "multipleOf": 0.5},
                        "label": {"type": "string", "minLength": 2, "maxLength": 8},
                        "choice": {"oneOf": [{"type": "string", "maxLength": 4}, {"type": "integer", "maximum": 10}]},
                        "profile": {"$ref": "#/components/schemas/Profile"},
                        "items": {"type": "array", "minItems": 1, "maxItems": 3, "items": {"$ref": "#/components/schemas/Item"}},
                        "server_id": {"type": "integer", "readOnly": True},
                        "password": {"type": "string"},
                    }},
                ]},
                "Flags": {"type": "object", "properties": {"enabled": {"type": "boolean"}, "optional": {"type": ["string", "null"]}}},
                "Profile": {"type": "object", "properties": {"a/b~c": {"type": "boolean"}}},
                "Item": {"type": "object", "properties": {"count": {"type": "integer", "minimum": 0}}},
            },
            "securitySchemes": {"opaque": {"type": "apiKey", "in": "query", "name": "opaque"}},
        },
        "paths": {"/widgets": {"post": {
            "security": [{"opaque": []}],
            "parameters": [{"in": "query", "name": "opaque", "schema": {"type": "string"}}],
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Input"}}}},
            "responses": {"201": {"description": "Created", "content": {"application/json": {"schema": {
                "type": "object", "properties": {"response_only": {"type": "string"}},
            }}}}},
        }}},
    }


def setup(schema=None, *, budget=1000, enabled=True, allow_mutating=True, body=None):
    doc = document()
    if schema is not None:
        doc["paths"]["/widgets"]["post"]["requestBody"]["content"]["application/json"]["schema"] = schema
    parsed = parse_spec(doc, BASE)
    operation = parsed["operations"][0]
    saved_body = body if body is not None else {
        "enabled": True, "optional": "saved", "quantity": 3, "price": 2.5,
        "label": "saved", "choice": "yes", "profile": {"a/b~c": False},
        "items": [{"count": 2}], "password": SECRET,
    }
    built = build_request(parsed, operation["id"], base_url=BASE, body=saved_body,
                          parameters={"query.opaque": SECRET},
                          headers={"Authorization": f"Bearer {SECRET}", "X-Keep": "saved-header"})
    plan = plan_campaign(parsed, operation, built, enabled=enabled, allow_mutating=allow_mutating, budget=budget)
    return parsed, operation, built, plan


@pytest.fixture(params=["uniform-denial", "validation-before-denial", "one-input-error", "success-boundaries"])
def local_target(request):
    """Four deterministic applications; no network sockets or external targets."""
    mode = request.param

    def handler(req):
        payload = json.loads(req.content)
        if mode == "validation-before-denial" and not isinstance(payload.get("enabled"), bool):
            return httpx.Response(422, json={"field": "enabled", "detail": "enabled must be boolean"})
        if mode == "one-input-error" and payload.get("quantity") == "invalid-type":
            return httpx.Response(500, json={"detail": "Unexpected internal error"})
        if mode == "success-boundaries":
            value = payload.get("quantity")
            if type(value) is not int or not 1 <= value <= 5:
                return httpx.Response(422, json={"field": "quantity", "detail": "quantity must be an integer from 1 to 5"})
            return httpx.Response(201, json={"created": True})
        return httpx.Response(403, json={"detail": "Not entitled"})

    return mode, handler


def run(plan, built, handler, *, budget=None):
    seen = []

    def capture(request):
        seen.append(request)
        return handler(request)

    with httpx.Client(transport=httpx.MockTransport(capture)) as client:
        executor = Executor(client, Budget(budget or plan.budget + 1), allow_mutating=True)
        baseline = executor.send(built["method"], built["url"], label="baseline", headers=built["headers"],
                                 body=_body_text(built), content_type=built["content_type"], identity="primary")
        result = execute_campaign(executor, plan, baseline)
        return result, seen, executor


def test_plan_covers_request_fields_types_refs_and_compositions_only():
    _, _, _, plan = setup()
    fields = {field["field_pointer"]: field for field in plan.fields}
    assert {"/enabled", "/optional", "/quantity", "/price", "/label", "/choice", "/profile/a~1b~0c", "/items/0/count"} <= fields.keys()
    assert "/response_only" not in fields
    assert fields["/server_id"]["category"] == "read-only-negative"
    for pointer in ["/enabled", "/quantity", "/price", "/label"]:
        mutations = {probe["mutation"] for probe in plan.probes if probe["field_pointer"] == pointer}
        assert "omission" in mutations
        assert "null-disallowed" in mutations
        assert any(mutation.startswith("wrong-type-") for mutation in mutations)
    assert any(probe["field_pointer"] == "/optional" and probe["mutation"] == "null-allowed" for probe in plan.probes)
    assert {probe["mutation"] for probe in plan.probes if probe["field_pointer"] == "/quantity"} >= {"minimum-below", "minimum-at", "maximum-at", "maximum-above"}
    assert {probe["mutation"] for probe in plan.probes if probe["field_pointer"] == "/choice"} >= {"maxLength-above", "maximum-above"}
    assert [probe["mutation"] for probe in plan.probes if probe["field_pointer"] == "/server_id"] == ["read-only-property-submission"]
    public = plan.to_dict()
    assert public["budget"] == 1000
    assert public["planned_requests"] == len(plan.requests)
    assert all("prerequisite" in probe and "planned_requests" in probe for probe in public["probes"])
    assert SECRET not in json.dumps(public)


def test_denied_and_successful_baseline_regression_fixtures(local_target):
    mode, handler = local_target
    _, _, built, plan = setup(schema={"type": "object", "properties": {
        "enabled": {"type": "boolean"}, "quantity": {"type": "integer", "minimum": 1, "maximum": 5},
    }}, body={"enabled": True, "quantity": 3})
    result, seen, _ = run(plan, built, handler)
    sent = [probe for probe in result["probes"] if probe["request_sent"]]
    assert len(seen) == 1 + len(sent)
    assert result["request_breakdown"]["inventory"] == 0
    assert result["request_breakdown"]["endpoint_tests"] == len(sent)
    assert all(field["requests_sent"] for field in result["field_coverage"] if field["location"] == "body")
    if mode == "uniform-denial":
        assert {probe["status"] for probe in sent} == {"same-denial-as-baseline"}
        assert {probe["reason_code"] for probe in sent} == {"downstream-handling-unknown"}
        assert all("not a validation pass" in probe["observation"] for probe in sent)
    elif mode == "validation-before-denial":
        specific = [probe for probe in sent if probe["status"] == "field-specific-response-observed"]
        assert specific
        assert {probe["field_pointer"] for probe in specific} == {"/enabled"}
        assert all(probe["response_status"] == 422 for probe in specific)
        assert any(probe["status"] == "same-denial-as-baseline" for probe in sent)
    elif mode == "one-input-error":
        errors = [probe for probe in sent if probe["response_status"] == 500]
        assert len(errors) == 1
        assert errors[0]["field_pointer"] == "/quantity"
        assert errors[0]["reason_code"] == "unexpected-error-response-lead"
        assert errors[0]["status"] == "request-sent"
    else:
        boundaries = [probe for probe in sent if probe["field_pointer"] == "/quantity" and probe["mutation"] in {"minimum-below", "maximum-above"}]
        assert boundaries and all(probe["response_status"] == 422 for probe in boundaries)
        assert all(probe["status"] == "field-specific-response-observed" for probe in boundaries)
        assert any(probe["response_status"] == 201 for probe in sent)


def test_single_field_changes_preserve_saved_values_credentials_and_record_exact_requests():
    _, _, built, plan = setup()
    saved = copy.deepcopy(built)
    result, seen, _ = run(plan, built, lambda request: httpx.Response(403, json={"detail": "Not entitled"}))
    sent = [probe for probe in result["probes"] if probe["request_sent"]]
    assert built == saved
    assert len(sent) == len(seen) - 1
    requests = {(request.method, str(request.url), request.content) for request in seen}
    assert len(requests) == len(seen), "Baseline and mutations must not be repeated"
    for probe, request in zip(sent, seen[1:], strict=True):
        assert request.headers["authorization"] == f"Bearer {SECRET}"
        assert request.headers["x-keep"] == "saved-header"
        assert request.url.params["opaque"] == SECRET
        payload = json.loads(request.content)
        assert payload["password"] == SECRET
        token = probe["field_pointer"].split("/")[1].replace("~1", "/").replace("~0", "~")
        for key, value in saved["body"].items():
            if key != token:
                assert payload[key] == value
        assert probe["exchange"]["method"] == request.method
        assert "response_body" in probe["exchange"]
    serialized = json.dumps(result)
    assert SECRET not in serialized
    assert all(not probe["request_sent"] for probe in result["probes"] if probe["field_pointer"] in {"/password", "/query/opaque"})


def test_bounded_budget_does_not_claim_unsent_checks_completed():
    _, _, built, plan = setup(budget=5)
    result, seen, executor = run(plan, built, lambda request: httpx.Response(403, json={"detail": "Denied"}), budget=4)
    assert len(seen) == executor.budget.spent == 4
    assert result["request_breakdown"]["endpoint_tests"] == 3
    exhausted = [probe for probe in result["probes"] if probe["status"] == "budget-exhausted"]
    assert exhausted and all(not probe["request_sent"] for probe in exhausted)
    assert len({probe["field_pointer"] for probe in result["probes"] if probe["request_sent"]}) == 3
    assert not any(probe["status"] == "completed" for probe in result["probes"])


@pytest.mark.parametrize("enabled,write_permission,reason", [
    (False, True, "profile-disallows-input-probes"),
    (True, False, "write-permission-required"),
])
def test_missing_prerequisites_are_planned_and_do_not_send(enabled, write_permission, reason):
    _, _, built, plan = setup(enabled=enabled, allow_mutating=write_permission)
    assert not plan.requests
    result, seen, _ = run(plan, built, lambda request: httpx.Response(403))
    assert len(seen) == 1
    assert all(probe["status"] == "blocked-prerequisite" for probe in result["probes"])
    assert all(reason in probe["missing_prerequisites"] for probe in result["probes"])


def test_unresolved_schema_absent_parent_and_size_limits_are_explicit():
    _, _, _, plan = setup(schema={"type": "object", "properties": {
        "missing": {"$ref": "#/components/schemas/DoesNotExist"},
        "nested": {"type": "object", "properties": {"child": {"type": "boolean"}}},
        "huge": {"type": "string", "maxLength": 1000000000},
    }}, body={"huge": "ok"})
    assert any(probe["field_pointer"] == "/missing" and probe["reason_code"] == "unresolved-schema-reference" for probe in plan.probes)
    assert all(probe["status"] == "blocked-prerequisite" for probe in plan.probes if probe["field_pointer"] == "/nested/child")
    assert any(probe["reason_code"] == "bounded-string-limit" for probe in plan.probes)
    assert max(len(item["body"] or "") for item in plan.requests.values()) < 1000


def test_http_429_stops_remaining_mutations_without_retries():
    _, _, built, plan = setup()
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(403 if calls == 1 else 429, headers={"Retry-After": "30"})

    result, seen, _ = run(plan, built, handler)
    assert len(seen) == 2
    assert any(probe["reason_code"] == "rate-limit-observed" for probe in result["probes"])


def test_transport_error_is_not_a_field_response_or_completed_check():
    _, _, built, plan = setup(budget=2)
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise httpx.ConnectError("local fixture disconnected")
        return httpx.Response(403)

    result, _, _ = run(plan, built, handler)
    errors = [probe for probe in result["probes"] if probe["status"] == "execution-error"]
    assert len(errors) == 2
    assert all(probe["reason_code"] == "transport-error" for probe in errors)


def test_plan_is_deterministic_and_duplicate_mutations_reference_the_original():
    _, _, _, first = setup()
    _, _, _, second = setup()
    assert first.to_dict() == second.to_dict()
    duplicates = [probe for probe in first.probes if probe["reason_code"] == "duplicate-request"]
    assert duplicates and all(probe["duplicate_of"] in first.requests for probe in duplicates)
    unchanged = [probe for probe in first.probes if probe["reason_code"] == "unchanged-baseline"]
    assert unchanged and all(probe["planned_requests"] == 0 for probe in unchanged)


def test_form_fields_preserve_saved_encoding_other_fields_and_credentials():
    doc = document()
    schema = {"type": "object", "properties": {
        "enabled": {"type": "boolean"}, "quantity": {"type": "integer", "minimum": 1, "maximum": 4},
        "label": {"type": "string", "minLength": 2, "maxLength": 8}, "password": {"type": "string"},
    }}
    doc["paths"]["/widgets"]["post"]["requestBody"]["content"] = {"application/x-www-form-urlencoded": {"schema": schema}}
    parsed = parse_spec(doc, BASE)
    operation = parsed["operations"][0]
    built = build_request(parsed, operation["id"], body=f"enabled=true&quantity=3&label=saved%20one&password={SECRET}",
                          content_type="application/x-www-form-urlencoded", headers={"Authorization": f"Bearer {SECRET}"})
    plan = plan_campaign(parsed, operation, built, allow_mutating=True, budget=100)
    result, seen, _ = run(plan, built, lambda request: httpx.Response(403, text="Denied"))
    sent = [probe for probe in result["probes"] if probe["request_sent"]]
    assert {probe["field_pointer"] for probe in sent} == {"/enabled", "/quantity", "/label"}
    baseline_values = parse_qs(seen[0].content.decode(), keep_blank_values=True)
    for probe, request in zip(sent, seen[1:], strict=True):
        field = probe["field_pointer"][1:]
        values = parse_qs(request.content.decode(), keep_blank_values=True)
        for name, value in baseline_values.items():
            if name != field:
                assert values[name] == value
        if field != "label":
            assert b"label=saved%20one" in request.content
    assert SECRET not in json.dumps(result)
    assert _body_text({"has_body": True, "content_type": "application/x-www-form-urlencoded", "body": {"enabled": True, "count": 3}}) == "enabled=true&count=3"


@pytest.mark.parametrize("style", ["deepObject", "form"])
def test_structured_query_fields_and_repeated_arrays_keep_siblings(style):
    doc = document()
    doc["paths"] = {"/search": {"get": {
        "parameters": [
            {"name": "filter", "in": "query", "style": style, "explode": True, "schema": {
                "type": "object", "properties": {"enabled": {"type": "boolean"}, "count": {"type": "integer", "minimum": 1}}}},
            {"name": "tags", "in": "query", "schema": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
        ], "responses": {"200": {"description": "OK"}},
    }}}
    parsed = parse_spec(doc, BASE)
    operation = parsed["operations"][0]
    built = build_request(parsed, operation["id"], parameters={"query.filter": {"enabled": True, "count": 2}, "query.tags": ["a", "b"]})
    built["url"] += f"&opaque={SECRET}&untouched=a%2Fb"
    plan = plan_campaign(parsed, operation, built, budget=100)
    result, seen, _ = run(plan, built, lambda request: httpx.Response(403, text="Denied"))
    sent = [probe for probe in result["probes"] if probe["request_sent"]]
    assert {probe["field_pointer"] for probe in sent} >= {"/query/filter/enabled", "/query/filter/count", "/query/tags/0", "/query/tags/1"}
    for probe, request in zip(sent, seen[1:], strict=True):
        assert f"opaque={SECRET}" in str(request.url)
        assert "untouched=a%2Fb" in str(request.url)
        params = request.url.params
        if probe["field_pointer"] == "/query/filter/enabled":
            assert params["filter[count]" if style == "deepObject" else "count"] == "2"
            assert params.get_list("tags") == ["a", "b"]
        if probe["field_pointer"] == "/query/tags/0" and probe["mutation"] != "omission":
            assert params.get_list("tags")[-1] == "b"
    assert SECRET not in json.dumps(result)


def test_allof_nullability_intersects_and_anyof_nullability_unions():
    _, _, _, plan = setup(schema={"type": "object", "properties": {
        "strict": {"allOf": [{"type": ["string", "null"]}, {"type": "string"}]},
        "nullable": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "real": {"allOf": [{"type": "number"}, {"type": "number", "minimum": 1.5}]},
    }}, body={"strict": "yes", "nullable": "yes", "real": 2.25})
    assert next(probe for probe in plan.probes if probe["field_pointer"] == "/strict" and probe["mutation"].startswith("null-"))["mutation"] == "null-disallowed"
    assert next(probe for probe in plan.probes if probe["field_pointer"] == "/nullable" and probe["mutation"].startswith("null-"))["mutation"] == "null-allowed"
    assert not any(probe["field_pointer"] == "/real" and probe["mutation"] == "wrong-type-number" for probe in plan.probes)


def test_saved_additional_properties_are_request_fields_and_root_readonly_propagates():
    _, _, _, plan = setup(schema={"type": "object", "properties": {
        "extras": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
    }}, body={"extras": {"first": 1, "second": 2}})
    pointers = {field["field_pointer"] for field in plan.fields}
    assert {"/extras/first", "/extras/second"} <= pointers
    _, _, _, readonly = setup(schema={"type": "object", "readOnly": True, "properties": {
        "server_count": {"type": "integer"},
    }}, body={})
    assert all(field["read_only"] for field in readonly.fields if field["location"] == "body")
    assert {probe["mutation"] for probe in readonly.probes if probe["location"] == "body"} == {"read-only-property-submission"}


def test_changed_numeric_denial_is_not_hidden_by_volatile_value_normalization():
    _, _, built, plan = setup(schema={"type": "object", "properties": {
        "quantity": {"type": "integer", "minimum": 1000000000},
    }}, body={"quantity": 1000000000})
    result, _, _ = run(plan, built, lambda request: httpx.Response(403, json={"quantity": json.loads(request.content).get("quantity"), "detail": "Denied"}))
    changed = next(probe for probe in result["probes"] if probe["mutation"] == "minimum-above")
    assert changed["status"] == "field-specific-response-observed"
    assert changed["reason_code"] == "field-response-difference-lead"


def test_unredacted_evidence_preserves_exact_wire_bodies():
    _, _, built, plan = setup(schema={"type": "object", "properties": {"enabled": {"type": "boolean"}}}, body={"enabled": True})
    result, seen, _ = run(plan, built, lambda request: httpx.Response(403, content=b'{"detail":   "Denied"}'))
    sent = [probe for probe in result["probes"] if probe["request_sent"]]
    for probe, request in zip(sent, seen[1:], strict=True):
        assert probe["exchange"]["request_body"] == request.content.decode()
        assert probe["exchange"]["response_body"] == '{"detail":   "Denied"}'


def test_same_property_across_root_alternatives_keeps_both_types_and_boundaries():
    _, _, _, plan = setup(schema={"oneOf": [
        {"type": "object", "properties": {"choice": {"type": "integer", "maximum": 3}}},
        {"type": "object", "properties": {"choice": {"type": "string", "maxLength": 4}}},
    ]}, body={"choice": 2})
    field = next(field for field in plan.fields if field["field_pointer"] == "/choice")
    assert field["types"] == ["integer", "string"]
    cases = {probe["mutation"] for probe in plan.probes if probe["field_pointer"] == "/choice"}
    assert {"maximum-above", "maxLength-above"} <= cases
    assert "wrong-type-string" not in cases


def test_stable_validation_header_change_is_a_lead_despite_identical_denial_body():
    _, _, built, plan = setup(schema={"type": "object", "properties": {
        "enabled": {"type": "boolean"},
    }}, body={"enabled": True})

    def handler(request):
        enabled = json.loads(request.content).get("enabled")
        headers = {"X-Validation-Field": "enabled"} if not isinstance(enabled, bool) else {}
        return httpx.Response(403, headers=headers, json={"detail": "Denied"})

    result, _, _ = run(plan, built, handler)
    omission = next(probe for probe in result["probes"] if probe["field_pointer"] == "/enabled" and probe["mutation"] == "omission")
    assert omission["status"] == "field-specific-response-observed"
    assert omission["reason_code"] == "field-response-difference-lead"
    assert "processing layer" in omission["observation"]


def test_volatile_headers_do_not_turn_uniform_denial_into_a_lead():
    _, _, built, plan = setup(schema={"type": "object", "properties": {
        "enabled": {"type": "boolean"},
    }}, body={"enabled": True})
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        return httpx.Response(403, json={"detail": "Denied"}, headers={
            "Date": f"Thu, 08 Oct 2026 12:00:{count:02d} GMT",
            "X-Request-Id": f"request-{count}", "X-Correlation-ID": f"correlation-{count}",
        })

    result, _, _ = run(plan, built, handler)
    sent = [probe for probe in result["probes"] if probe["request_sent"]]
    assert sent
    assert {probe["status"] for probe in sent} == {"same-denial-as-baseline"}


def test_arbitrarily_named_credential_in_form_is_preserved_and_redacted():
    doc = document()
    doc["paths"]["/widgets"]["post"]["requestBody"]["content"] = {
        "application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {
            "opaque": {"type": "string"}, "enabled": {"type": "boolean"},
        }}},
    }
    parsed = parse_spec(doc, BASE)
    operation = parsed["operations"][0]
    built = build_request(parsed, operation["id"], body=f"opaque={SECRET}&enabled=true",
                          content_type="application/x-www-form-urlencoded")
    plan = plan_campaign(parsed, operation, built, allow_mutating=True)
    result, seen, _ = run(plan, built, lambda request: httpx.Response(403, text=f"Credential {SECRET} is not entitled"))
    assert all(parse_qs(request.content.decode())["opaque"] == [SECRET] for request in seen)
    assert all(not probe["request_sent"] for probe in result["probes"] if probe["field_pointer"] == "/opaque")
    assert SECRET not in json.dumps(result)
