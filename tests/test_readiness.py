"""Offline baseline and follow-up planning, without contacting any API."""
import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit import readiness
from namazu.audit.baseline import Expectation, check, classify
from namazu.audit.model import Exchange


def request():
    return {"method": "POST", "url": "http://127.0.0.1/reports/summary",
            "headers": {"Authorization": "Bearer local-fixture-secret", "Content-Type": "application/json"},
            "body": '{"document":"test-report","persona":"reader","limit":10}'}


def assertions():
    return [{"purpose": "resource", "pointer": "/document", "operator": "equals", "expected": "test-report"},
            {"purpose": "content", "pointer": "/summary", "operator": "contains", "expected": "fixture summary"}]


def exchange(**changes):
    source = request()
    return {"method": source["method"], "url": source["url"], "request_headers": source["headers"],
            "request_body": source["body"], "identity_ref": "primary", "status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_body": '{"document":"test-report","summary":"fixture summary for this resource"}', **changes}


def prepared_input(**changes):
    return {"request": request(), "identity_ref": "primary", "expectation": {"status": "200"},
            "assertions": assertions(), "recorded_response": exchange(), **changes}


def plan_input(**changes):
    return {"prepared": readiness.prepare(prepared_input()), "baseline_exchange": exchange(),
            "identity_refs": ["primary", "secondary"], "scope_urls": ["http://127.0.0.1/reports"],
            "profile": "writes", "allow_mutating": True, "budget": 6, "requests_per_second": 2,
            "permission_matrix": [{"kind": "entitlement", "identity_ref": "secondary", "expect": "deny",
                "assertions": assertions(), "identity_control": prepared_input(identity_ref="secondary",
                    recorded_response=exchange(identity_ref="secondary"))}], **changes}


def codes(prepared):
    return {item["code"] for item in prepared["missing_prerequisites"]}


def test_preparation_requires_business_assertions_and_preserves_redaction():
    result = readiness.prepare(prepared_input())
    assert result["positive_control"]
    assert result["requests_sent"] == 0
    assert "local-fixture-secret" not in json.dumps(result)
    assert result["request"]["headers"]["Authorization"] == "<credential>"
    bare = readiness.prepare(prepared_input(assertions=[]))
    assert not bare["positive_control"]
    assert {"resource-assertion-missing", "content-assertion-missing"} <= codes(bare)


def test_explicit_custom_credential_names_persist_without_masking_nonsecret_headers():
    data = prepared_input(credential_names=["X-Workspace"])
    data["request"]["headers"] = {"X-Workspace": "local-workspace-credential", "Accept": "application/json"}
    data["recorded_response"]["request_headers"] = dict(data["request"]["headers"])
    data["configuration"] = {"schema": {"properties": {"X-Workspace": {"type": "string", "description": "A schema field"}}}}
    prepared = readiness.prepare(data)
    assert prepared["positive_control"]
    assert prepared["credential_names"] == ["x-workspace"]
    assert prepared["configuration"]["credential_names"] == ["x-workspace"]
    assert prepared["request"]["headers"] == {"X-Workspace": "<credential>", "Accept": "application/json"}
    assert prepared["configuration"]["schema"] == data["configuration"]["schema"]
    assert "local-workspace-credential" not in json.dumps(prepared)


def test_custom_credential_assertions_are_rejected_without_echoing_the_value():
    data = prepared_input(credential_names=["X-Workspace"])
    data["request"]["headers"]["X-Workspace"] = "local-workspace-credential"
    data["assertions"][0]["expected"] = "local-workspace-credential"
    with pytest.raises(ValueError, match="non-secret marker") as caught:
        readiness.prepare(data)
    assert "local-workspace-credential" not in str(caught.value)
    data["assertions"] = [{"purpose": "resource", "pointer": "/X-Workspace", "expected": "public-looking-value"}]
    with pytest.raises(ValueError, match="not a credential assertion"):
        readiness.prepare(data)


def test_followup_inherits_custom_names_and_redacts_new_replay_credentials_and_echoes():
    source = prepared_input(credential_names=["X-Workspace"])
    source["request"]["headers"]["X-Workspace"] = "local-workspace-credential"
    source["recorded_response"]["request_headers"]["X-Workspace"] = "local-workspace-credential"
    prepared = readiness.prepare(source)
    retry = exchange(status=0, error="ReadTimeout")
    retry["request_headers"] = {"X-Workspace": "different-local-credential", "Accept": "application/json"}
    retry["request_body"] = '{"document":"test-report","echo":"different-local-credential"}'
    data = plan_input(prepared=prepared, permission_matrix=[], incomplete_cases=[retry])
    data.pop("baseline_exchange")
    result = readiness.plan(data)
    assert result["credential_names"] == ["x-workspace"]
    assert result["configuration"]["credential_names"] == ["x-workspace"]
    assert "different-local-credential" not in json.dumps(result)
    assert "local-workspace-credential" not in json.dumps(result)
    case = result["cases"][0]
    assert case["request"]["headers"]["Accept"] == "application/json"
    assert case["request"]["headers"]["X-Workspace"] == "<credential>"
    assert "redacted-request-values" in case["reason_codes"]
    assert result["requests_sent"] == 0


@pytest.mark.parametrize("changes,code", [
    ({"recorded_response": exchange(status=403, response_body='{"detail":"Not entitled"}')}, "positive-http-response-missing"),
    ({"expectation": {"status": "403", "negative": True}, "recorded_response": exchange(status=403)}, "expected-denial-is-not-positive-control"),
    ({"recorded_response": exchange(response_body='{"document":"other","summary":"fixture summary"}')}, "business-assertion-failed"),
    ({"recorded_response": exchange(identity_ref="secondary")}, "recorded-identity-mismatch"),
    ({"recorded_response": exchange(request_body='{"document":"other"}')}, "recorded-request-mismatch"),
    ({"recorded_response": exchange(request_headers={})}, "recorded-headers-mismatch"),
    ({"recorded_response": exchange(body_truncated=True)}, "response-incomplete"),
    ({"recorded_response": exchange(status=0, error="timeout")}, "successful-response-missing"),
])
def test_denial_wrong_resource_truncation_or_unrelated_receipt_never_unlocks(changes, code):
    result = readiness.prepare(prepared_input(**changes))
    assert not result["positive_control"]
    assert code in codes(result)


def test_placeholder_warning_is_qualified_and_does_not_invent_replacement_values():
    source = request()
    source["body"] = '{"document":"string","persona":"your-persona","enabled":true,"count":0}'
    result = readiness.prepare(prepared_input(request=source, recorded_response={}))
    assert {item["pointer"] for item in result["warnings"]} == {"/body/document", "/body/persona"}
    assert all("may be legitimate" in item["detail"] for item in result["warnings"])
    assert result["request"]["body"] == source["body"]
    assert "second test identity" in result["owner_request"]


@pytest.mark.parametrize("kind", ["raw", "json", "har"])
def test_known_good_import_formats_are_offline_and_redacted(kind):
    source = request()
    if kind == "raw":
        source = "POST /reports/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer local-fixture-secret\r\n\r\n{\"password\":\"body-secret\"}"
    elif kind == "json":
        source = json.dumps(source)
    else:
        source = {"log": {"entries": [{"request": {"method": "POST", "url": request()["url"],
                  "headers": [{"name": "Authorization", "value": "Bearer local-fixture-secret"}],
                  "postData": {"text": '{"password":"body-secret"}'}}}]}}
    result = readiness.parse_request(source, base_url="http://127.0.0.1")
    assert result["method"] == "POST"
    assert "local-fixture-secret" not in json.dumps(result)
    assert "body-secret" not in json.dumps(result)


def test_import_does_not_guess_request_from_multi_entry_har_or_scheme():
    with pytest.raises(ValueError, match="exactly one"):
        readiness.parse_request({"log": {"entries": [{}, {}]}})
    with pytest.raises(ValueError, match="explicit base URL"):
        readiness.parse_request("POST /reports HTTP/1.1\nHost: example.invalid\n\n{}")


def test_followup_requires_explicit_permissions_distinct_identity_and_controls():
    data = plan_input()
    data["permission_matrix"][0].pop("expect")
    data["permission_matrix"][0].pop("identity_control")
    data["permission_matrix"][0]["assertions"] = []
    result = readiness.plan(data)
    case = result["cases"][0]
    assert case["status"] == "blocked-prerequisite"
    assert {"explicit-permission-required", "second-identity-positive-control-required",
            "resource-and-content-assertions-required"} <= set(case["reason_codes"])
    assert result["budget"]["planned"] == 0
    denied = readiness.plan(plan_input(baseline_exchange=exchange(status=403)))
    assert "successful-business-baseline-required" in denied["cases"][0]["reason_codes"]


@pytest.mark.parametrize("permission", ["allow", "deny"])
def test_cross_identity_access_is_not_assumed_forbidden(permission):
    data = plan_input()
    data["permission_matrix"][0]["expect"] = permission
    result = readiness.plan(data)
    assert result["cases"][0]["status"] == "planned"
    assert result["cases"][0]["expected_permission"] == permission
    assert result["budget"]["planned"] == 1
    assert result["requests_sent"] == 0


def test_cache_sequence_counts_priming_and_comparison_and_budget_deduplicates():
    data = plan_input(budget=2)
    row = data["permission_matrix"][0]
    row["kind"] = "cache-isolation"
    data["permission_matrix"].append(copy.deepcopy(row))
    data["incomplete_cases"] = [exchange(status=0, error="ReadTimeout")]
    result = readiness.plan(data)
    assert len(result["cases"]) == 2
    assert result["budget"]["planned"] == 2
    assert [step["identity_ref"] for step in result["cases"][0]["sequence"]] == ["primary", "secondary"]
    assert result["cases"][1]["status"] == "budget-exhausted"


def test_cache_priming_also_requires_primary_identity_still_configured():
    data = plan_input(identity_refs=["secondary"])
    data["permission_matrix"][0]["kind"] = "cache-isolation"
    result = readiness.plan(data)
    assert "local-identity-not-configured" in result["cases"][0]["reason_codes"]
    assert result["budget"]["planned"] == 0


@pytest.mark.parametrize("changes,reason", [
    ({"profile": "readonly"}, "write-permission-required"),
    ({"allow_mutating": False}, "write-permission-required"),
    ({"scope_urls": ["http://127.0.0.1/other"]}, "out-of-scope"),
    ({"identity_refs": ["primary"]}, "local-identity-not-configured"),
])
def test_plan_respects_explicit_scope_writes_and_local_identity(changes, reason):
    result = readiness.plan(plan_input(**changes))
    assert reason in result["cases"][0]["reason_codes"]
    assert result["budget"]["planned"] == 0


def test_timeout_replay_is_new_attempt_can_be_planned_without_positive_control():
    data = plan_input(baseline_exchange=exchange(status=403), permission_matrix=[], replay_attempts=99,
                      incomplete_cases=[exchange(status=0, error="ReadTimeout")])
    result = readiness.plan(data)
    assert result["cases"][0]["status"] == "planned"
    assert result["budget"]["planned"] == 5
    assert "new attempt" in result["cases"][0]["prerequisite"]
    assert "positive-http-response-missing" in codes(result)
    assert "permission-matrix-missing" in codes(result)


def test_duplicate_timeout_requests_share_one_retry_and_retain_every_evidence_reference():
    data = plan_input(permission_matrix=[], incomplete_cases=[
        exchange(status=0, error="ReadTimeout", evidence_pointer="/request_log/81"),
        exchange(status=0, error="ReadTimeout", evidence_pointer="/request_log/88", identity_ref="Identity A"),
    ])
    result = readiness.plan(data)
    assert len(result["cases"]) == 1
    case = result["cases"][0]
    assert result["budget"]["planned"] == case["planned_request_count"] == 1
    assert case["source_evidence"] == "/request_log/81"
    assert case["source_evidence_refs"] == ["/request_log/81", "/request_log/88"]
    assert case["request_sent"] is False


def test_all_missing_prerequisites_remain_visible():
    data = plan_input(identity_refs=["primary"], permission_matrix=[], baseline_exchange=exchange(status=403))
    result = readiness.plan(data)
    assert {"positive-http-response-missing", "second-identity-missing", "permission-matrix-missing"} <= codes(result)
    assert result["summary"] == {"cases": 0, "planned": 0, "blocked": 0, "budget_exhausted": 0}


def test_redacted_query_credentials_block_replay_and_identity_aliases_do_not_create_second_identity():
    source = exchange(status=0, error="ReadTimeout", url="http://127.0.0.1/reports/summary?api_key=query-secret")
    result = readiness.plan(plan_input(incomplete_cases=[source], identity_refs=["primary", "Identity A"], permission_matrix=[]))
    assert "second-identity-missing" in codes(result)
    assert "redacted-request-values" in result["cases"][0]["reason_codes"]
    assert "query-secret" not in json.dumps(result)


def test_exported_identity_a_alias_can_plan_incomplete_replay_with_primary_configured():
    source = exchange(status=0, error="ReadTimeout", identity_ref="Identity A")
    result = readiness.plan(plan_input(incomplete_cases=[source], permission_matrix=[]))
    assert result["cases"][0]["status"] == "planned"


def test_routes_do_not_construct_clients_resolve_credentials_or_send_requests(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline planning must not perform target or OAuth IO")
    monkeypatch.setattr("namazu.audit.transport.build_client", forbidden)
    monkeypatch.setattr("namazu.audit.identity.resolve", forbidden)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        prepared = client.post("/api/readiness/prepare", json=prepared_input())
        planned = client.post("/api/readiness/plan", json=plan_input())
    assert prepared.status_code == planned.status_code == 200
    assert prepared.json()["requests_sent"] == planned.json()["requests_sent"] == 0
    assert "local-fixture-secret" not in prepared.text + planned.text


def test_browser_summary_never_turns_planned_requests_into_completed_coverage():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    path = Path("namazu/static/readiness.js").resolve()
    script = f"const m=require({json.dumps(str(path))});process.stdout.write(JSON.stringify(m.reportSummary({json.dumps({'plan': readiness.plan(plan_input())})})));"
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True)
    summary = json.loads(result.stdout)
    assert summary["planned_requests"] == 1
    assert summary["requests_sent"] == 0


def test_explicit_business_assertions_survive_saved_baseline_and_live_check():
    prepared = readiness.prepare(prepared_input())
    expected = Expectation.from_dict(prepared["expectation"])
    assert expected.business_assertions == assertions()
    assert expected.asserted()
    success, _ = check(expected, readiness._response(exchange()))
    assert success
    success, failures = check(expected, readiness._response(exchange(response_body='{}')))
    assert not success
    assert len(failures) == 2
    assert Expectation.from_dict(expected.to_dict()).business_assertions == assertions()
    verdict = classify(Exchange(label="baseline", method="POST", url=request()["url"],
                                status=200, body="{}"), expectation=expected)
    assert not verdict.positive_control


def test_business_assertions_keep_json_pointer_empty_keys_and_value_types():
    expected = Expectation(business_assertions=[{"purpose": "resource", "pointer": "/data//id",
                                               "operator": "equals", "expected": "resource"}])
    assert check(expected, readiness._response(exchange(response_body='{"data":{"":{"id":"resource"}}}')))[0]
    assert not check(expected, readiness._response(exchange(response_body='{"data":{"id":"resource"}}')))[0]
    expected.business_assertions = [{"pointer": "/enabled", "expected": 1}]
    assert not check(expected, readiness._response(exchange(response_body='{"enabled":true}')))[0]


def test_absence_only_assertions_do_not_prove_business_success_or_boundary_controls():
    absent = [{"purpose": purpose, "pointer": "/" + purpose, "operator": "absent"}
              for purpose in ("resource", "content")]
    prepared = readiness.prepare(prepared_input(assertions=absent, recorded_response=exchange(response_body='{}')))
    assert not prepared["positive_control"]
    assert {"resource-assertion-missing", "content-assertion-missing"} <= codes(prepared)
    data = plan_input()
    data["permission_matrix"][0]["assertions"] = absent
    assert "resource-and-content-assertions-required" in readiness.plan(data)["cases"][0]["reason_codes"]


def test_preparation_and_plan_configuration_never_persist_credentials_or_echoes():
    configuration = {"permission_matrix": plan_input()["permission_matrix"],
                     "constraints": [{"field_pointer": "/body/limit", "mutation": "maximum+1",
                                      "expected_handling": "reject", "request": request()}]}
    configuration["permission_matrix"][0]["identity_control"]["recorded_response"]["response_headers"] = {"Set-Cookie": "session=another-local-secret"}
    configuration["permission_matrix"][0]["identity_control"]["recorded_response"]["response_body"] = "echo local-fixture-secret"
    prepared = readiness.prepare(prepared_input(configuration=configuration))
    serialised = json.dumps(prepared)
    assert "local-fixture-secret" not in serialised
    assert "another-local-secret" not in serialised
    assert prepared["configuration"]["permission_matrix"][0]["identity_control"]["request"]["headers"]["Authorization"] == "<credential>"
    planned = readiness.plan(plan_input(**configuration))
    assert "local-fixture-secret" not in json.dumps(planned)
    assert "another-local-secret" not in json.dumps(planned)


def test_constraints_change_only_named_field_preserving_all_other_values():
    changed = request()
    changed["body"] = '{"document":"test-report","persona":"reader","limit":11}'
    item = {"field_pointer": "/body/limit", "mutation": "maximum+1", "expected_handling": "reject", "request": changed}
    data = plan_input(permission_matrix=[], constraints=[item])
    assert readiness.plan(data)["cases"][0]["status"] == "planned"
    changed["body"] = '{"document":"other","persona":"reader","limit":11}'
    assert "single-field-change-required" in readiness.plan(data)["cases"][0]["reason_codes"]


def test_persona_options_require_application_defined_boundary():
    data = plan_input()
    data["permission_matrix"][0]["kind"] = "persona-options"
    assert "application-boundary-definition-required" in readiness.plan(data)["cases"][0]["reason_codes"]


def test_readiness_mount_import_and_summary_never_send_and_edits_invalidate_saved_review():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    from tests.test_audit_results_view import DOM

    path = Path("namazu/static/readiness.js").resolve()
    fixture = {"prepared": readiness.prepare(prepared_input()), "configuration": {}}
    script = DOM + f"const readiness=require({json.dumps(str(path))}); const initial={json.dumps(fixture)};" + r"""
Object.defineProperty(Element.prototype, 'childNodes', {get(){return this.children;}});
const container = new Element('div'); let calls = 0;
readiness.mount(container, {initial, api(){calls++; throw new Error('Must remain offline');}, context:()=>({})});
const buttons = byTag(container,'button'); const use = buttons.find(n=>n.textContent==='Use as saved baseline');
const before = use.disabled; byTag(container,'textarea')[0].fire('input');
process.stdout.write(JSON.stringify({calls,before,after:use.disabled,text:container.textContent}));
"""
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True)
    value = json.loads(result.stdout)
    assert value["calls"] == 0
    assert value["before"] is False and value["after"] is True
    assert "no target requests" in value["text"]


def test_browser_persists_only_server_sanitised_configuration():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    from tests.test_audit_results_view import DOM

    path = Path("namazu/static/readiness.js").resolve()
    prepared = readiness.prepare(prepared_input(configuration={"permission_matrix": plan_input()["permission_matrix"], "constraints": []}))
    script = DOM + f"const readiness=require({json.dumps(str(path))}); const prepared={json.dumps(prepared)};" + r"""
Object.defineProperty(Element.prototype, 'childNodes', {get(){return this.children;}});
const container = new Element('div'); let saved;
readiness.mount(container, {api:async()=>prepared, onChange:value=>{saved=value;},context:()=>({})});
const matrix=all(container,n=>n.tagName==='label' && n.textContent.startsWith('Permission matrix'))[0].children[1];
matrix.value='[{"request":{"headers":{"Authorization":"Bearer browser-only-secret"}}}]';
byTag(container,'button').find(n=>n.textContent==='Review baseline readiness').fire('click');
setImmediate(()=>process.stdout.write(JSON.stringify({saved,text:matrix.value})));
"""
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True)
    assert "browser-only-secret" not in result.stdout
    assert json.loads(result.stdout)["saved"]["configuration"] == prepared["configuration"]


@pytest.mark.parametrize("kind", ["raw", "query", "har", "cookie", "form"])
def test_imported_credential_echoes_are_redacted_everywhere(kind):
    source = request()
    secret = "fixture-echo-credential"
    record = exchange(response_body=json.dumps({"document": "test-report", "summary": "fixture summary", "detail": secret}))
    if kind == "raw":
        source = f"POST http://127.0.0.1/reports/summary HTTP/1.1\nAuthorization: Bearer {secret}\nContent-Type: application/json\n\n{request()['body']}"
        # The source is the only place the raw credential exists; the retained
        # exchange has already redacted its header.
        record["request_headers"] = readiness.parse_request(source)["headers"]
    elif kind == "query":
        source["url"] += "?api_key=" + secret
        record["url"] = readiness.parse_request(source)["url"]
    elif kind == "cookie":
        source["headers"]["Cookie"] = "session=" + secret
        record["request_headers"] = readiness.parse_request(source)["headers"]
    elif kind == "form":
        source["body"] = "password=" + secret
        record["request_body"] = readiness.parse_request(source)["body"]
    else:
        source = {"request": {"method": "POST", "url": request()["url"],
                  "headers": [{"name": "Authorization", "value": "Bearer " + secret}],
                  "postData": {"text": request()["body"]}}}
        record["request_headers"] = readiness.parse_request(source)["headers"]
    result = readiness.prepare(prepared_input(request=source, recorded_response=record))
    assert secret not in json.dumps(result)
    assert "<credential>" in result["recorded_response"]["response_body"]


@pytest.mark.parametrize("path", ["/reports/../outside", "/reports/%2e%2e/outside", "/reports/%252e%252e/outside",
                                  "/reports/%2f../outside", "/reports/..\\outside"])
def test_scope_rejects_dot_segments_before_an_http_client_can_normalise_them(path):
    record = exchange(status=0, error="ReadTimeout", url="http://127.0.0.1" + path)
    result = readiness.plan(plan_input(permission_matrix=[], incomplete_cases=[record]))
    assert "out-of-scope" in result["cases"][0]["reason_codes"]
    assert result["budget"]["planned"] == 0


@pytest.mark.parametrize("marker", ["<credential>", "[redacted]", "[Filtered]", {"id": "<redacted>"}])
def test_redacted_markers_cannot_be_positive_business_assertions(marker):
    checks = assertions()
    checks[0]["expected"] = marker
    with pytest.raises(ValueError, match="redacted value"):
        readiness.prepare(prepared_input(assertions=checks))
    expected = Expectation(status="200", business_assertions=checks)
    assert not check(expected, readiness._response(exchange(response_body=json.dumps({"document": marker, "summary": "fixture summary"}))))[0]


def test_a_credential_echo_cannot_be_used_as_a_positive_resource_marker():
    checks = assertions()
    checks[0]["expected"] = "local-fixture-secret"
    with pytest.raises(ValueError, match="redacted value"):
        readiness.prepare(prepared_input(assertions=checks))


def test_excerpt_only_receipt_is_incomplete_even_without_truncation_flag():
    record = exchange()
    record["body_excerpt"] = record.pop("response_body")
    record["body_length"] = len(record["body_excerpt"]) + 100
    result = readiness.prepare(prepared_input(recorded_response=record))
    assert not result["positive_control"]
    assert "response-incomplete" in codes(result)
    assert result["recorded_response"]["body_truncated"]
    # Export/import must not promote the excerpt to a complete response.
    assert not readiness.prepare(result)["positive_control"]


@pytest.mark.parametrize("variation", [None, "identical", "whitespace"])
def test_persona_boundary_plan_needs_an_explicit_meaningful_variation(variation):
    data = plan_input()
    row = data["permission_matrix"][0]
    row.update(kind="persona-options", boundary_definition="The owner defines persona isolation")
    if variation:
        row["request"] = request()
        if variation == "whitespace":
            row["request"]["body"] = json.dumps(json.loads(row["request"]["body"]), indent=2)
    result = readiness.plan(data)
    assert "explicit-boundary-variation-required" in result["cases"][0]["reason_codes"]
    row["request"] = request()
    row["request"]["body"] = '{"document":"test-report","persona":"reviewer","limit":10}'
    assert "explicit-boundary-variation-required" not in readiness.plan(data)["cases"][0]["reason_codes"]


def test_short_credential_echo_is_redacted_without_changing_json_structure():
    source = request()
    source["headers"]["Authorization"] = "Bearer abc"
    record = exchange(request_headers=source["headers"], response_body=json.dumps({
        "document": "test-report", "summary": "fixture summary", "diagnostic": "echo=abc; abc-inline",
        "abc_field": True, "number": 123}))
    result = readiness.prepare(prepared_input(request=source, recorded_response=record))
    body = json.loads(result["recorded_response"]["response_body"])
    assert body["diagnostic"] == "echo=<credential>; <credential>-inline"
    assert body["abc_field"] is True
    assert body["number"] == 123
    checks = assertions()
    checks[0]["expected"] = "abc"
    with pytest.raises(ValueError, match="redacted value"):
        readiness.prepare(prepared_input(request=source, recorded_response=record, assertions=checks))


def test_numeric_short_credentials_do_not_mutate_json_numbers_or_keys():
    source = request()
    source["headers"]["Authorization"] = "Bearer 0"
    record = exchange(request_headers=source["headers"], response_body=json.dumps({
        "document": "test-report", "summary": "fixture summary", "echo": "token=0", "number": 0,
        "0": False}))
    result = readiness.prepare(prepared_input(request=source, recorded_response=record))
    body = json.loads(result["recorded_response"]["response_body"])
    assert body["echo"] == "token=<credential>"
    assert body["number"] == 0 and body["0"] is False
