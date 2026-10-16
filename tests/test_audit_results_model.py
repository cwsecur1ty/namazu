"""Run the browser's pure results model against local receipts, never live targets."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

MODULE = Path("namazu/static/audit-results.js").resolve()


def node(script, payload):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    source = (f"const model = require({json.dumps(str(MODULE))});\n"
              "const fs = require('fs'); const input = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
              + script)
    result = subprocess.run(["node", "-e", source], input=json.dumps(payload),
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def build(audit):
    return node("process.stdout.write(JSON.stringify(model.buildResults(input)));", audit)


def exchange(body='{"error":"Not entitled"}', *, status=403, headers=None, **extra):
    return {"label": "mutation", "method": "POST", "url": "http://127.0.0.1:9876/widgets",
            "request_headers": {"Authorization": "<redacted>"}, "request_body": '{"enabled":null}',
            "status": status, "response_headers": headers or {"content-type": "application/json"},
            "response_body": body, "truncated": False, "error": "", **extra}


def plan_case(identifier="one", pointer="/enabled", mutation="null-disallowed", **extra):
    return {"id": identifier, "operation": "createWidget", "location": "body",
            "field_pointer": pointer, "mutation": mutation, "status": "planned",
            "planned_requests": 1, "prerequisite": "saved request and HTTP response",
            "missing_prerequisites": [], **extra}


def receipt(plan, captured=None, **extra):
    return {**plan, "request_sent": captured is not None, "status": "same-denial-as-baseline",
            **({"exchange": captured} if captured else {}), **extra}


def audit_fixture(planned=None, probes=None, baseline=None):
    return {"running": False, "requests": 53,
            "plans": [{"endpoint": "POST /widgets", "operation_id": "createWidget",
                       "test_plan": {"operation": "createWidget", "probes": planned or []}}],
            "probes": probes or [], "baselines": [{"endpoint": "POST /widgets",
                                                        "exchange": baseline or exchange(label="baseline")}],
            "requestBreakdown": {"inventory": 50, "baseline": 1, "schema_inputs": 2,
                                 "other_endpoint_tests": 0}, "fieldCoverage": [], "log": []}


def first_field(result):
    return result["operations"][0]["fields"][0]


def equivalent(left, right, protected=()):
    result = node("const [a,b] = input.exchanges.map(ex => model.canonicalResponse(ex, input.protected));"
                  "process.stdout.write(JSON.stringify({same:a.comparable && b.comparable && a.key===b.key,a,b}));",
                  {"exchanges": [left, right], "protected": protected})
    return result


def test_uniform_denials_group_with_original_exchanges_and_no_validation_claim():
    plans = [plan_case("one"), plan_case("two", mutation="wrong-type-number")]
    baseline = exchange('{"error":"Not entitled","timestamp":"2026-10-08T12:00:00Z","requestId":"base"}')
    changes = [exchange(json.dumps({"requestId": f"request-{i}", "timestamp": f"2026-10-08T12:0{i}:00Z",
                                   "error": "Not entitled"}),
                        headers={"content-type": "application/json", "date": f"Thu, 08 Oct 2026 12:0{i}:00 GMT",
                                 "x-correlation-id": str(i)}, label=f"probe-{i}") for i in range(2)]
    audit = audit_fixture(plans, [receipt(plan, captured) for plan, captured in zip(plans, changes, strict=True)], baseline)
    audit["log"] = [{**changes[0], "key": "2", "endpoint": "POST /widgets"}]
    original = copy.deepcopy(audit)
    result = build(audit)
    assert audit == original
    field = first_field(result)
    assert len(field["groups"]) == 1
    assert len(field["groups"][0]["cases"]) == 2
    assert {case["comparison"] for case in field["cases"]} == {"same-denial"}
    assert all("downstream handling unknown" in case["interpretation"] for case in field["cases"])
    assert all("does not establish" in case["uncertainty"] for case in field["cases"])
    assert field["cases"][0]["evidence"][0]["logKey"] == "2"
    assert [case["exchanges"][0] for case in field["cases"]] == changes
    assert result["summary"]["plannedCases"] == result["summary"]["executedCases"] == 2
    assert result["summary"]["requestBreakdown"]["inventory"] == 50
    assert result["summary"]["totalRequests"] == 53
    assert "findings" not in result


@pytest.mark.parametrize(("left", "right"), [
    ('{"field":"enabled","message":"must be boolean"}', '{"field":"quantity","message":"must be integer"}'),
    ('{"resourceId":"550e8400-e29b-41d4-a716-446655440000"}', '{"resourceId":"550e8400-e29b-41d4-a716-446655440001"}'),
    ('{"resourceId":9007199254740992}', '{"resourceId":9007199254740993}'),
    ('{"code":true}', '{"code":1}'),
    ('{"code":"1"}', '{"code":1}'),
    ('{"data":{"timestamp":"first"}}', '{"data":{"timestamp":"second"}}'),
    ('{"data":{"metadata":{"requestId":"one"}}}', '{"data":{"metadata":{"requestId":"two"}}}'),
    ('[{"timestamp":"first"}]', '[{"timestamp":"second"}]'),
    ('{"requestId":{"error":"one"}}', '{"requestId":{"error":"two"}}'),
    ('{"timestamp":false}', '{"timestamp":null}'),
    ('{"errors":["a","b"]}', '{"errors":["b","a"]}'),
    ('{"x":1,"x":2}', '{"x":2}'),
    ('request 2026-10-08 id 0123456789abcdef number 12345', 'request 2026-10-09 id 0123456789abcdee number 12346'),
    ('prefix' + 'x' * 12000 + 'A', 'prefix' + 'x' * 12000 + 'B'),
])
def test_meaningful_response_differences_are_not_discarded(left, right):
    assert equivalent(exchange(left), exchange(right))["same"] is False


@pytest.mark.parametrize("header", ["location", "www-authenticate", "set-cookie", "x-validation-error",
                                    "retry-after", "age", "server-timing", "content-type", "content-length"])
def test_meaningful_headers_remain_part_of_comparison(header):
    assert not equivalent(exchange(headers={header: "one"}), exchange(headers={header: "two"}))["same"]


def test_explicit_envelope_metadata_ignored_but_mutated_metadata_named_field_protected():
    one = exchange('{"metadata":{"request_id":"one","timestamp":123},"error":"Denied"}')
    two = exchange('{"error":"Denied","metadata":{"timestamp":456,"request_id":"two"}}')
    assert equivalent(one, two)["same"]
    assert not equivalent(one, two, protected=["request_id"])["same"]
    plans = [plan_case(pointer="/timestamp")]
    result = build(audit_fixture(plans, [receipt(plans[0], exchange('{"timestamp":"new"}'))],
                                exchange('{"timestamp":"old"}')))
    assert first_field(result)["cases"][0]["comparison"] == "different"


def test_verified_content_length_ignores_only_derived_size():
    left, right = '{"requestId":"a","message":"é"}', '{"requestId":"longer","message":"é"}'
    assert equivalent(exchange(left, headers={"content-length": str(len(left.encode()))}),
                      exchange(right, headers={"content-length": str(len(right.encode()))}))["same"]
    assert not equivalent(exchange(left, headers={"content-length": "999"}),
                          exchange(right, headers={"content-length": "998"}))["same"]


def test_validation_rejections_are_observations_and_unexpected_errors_remain_leads():
    plans = [plan_case("one"), plan_case("two", mutation="wrong-type-number"),
             plan_case("three", "/quantity", "wrong-type-string")]
    probes = [receipt(plans[0], exchange()), receipt(plans[1], exchange('{"field":"enabled","error":"boolean required"}', status=422),
                                                  status="field-specific-response-observed"),
              receipt(plans[2], exchange('{"error":"Unexpected internal error"}', status=500), status="request-sent")]
    result = build(audit_fixture(plans, probes))
    assert len(first_field(result)["groups"]) == 2
    assert result["summary"]["sameDenialCases"] == 1
    assert result["summary"]["responseDifferenceCases"] == 1
    assert result["summary"]["validationObservationCases"] == 1
    validation = first_field(result)["cases"][1]
    assert validation["comparison"] == "validation-observation"
    assert "not automatically a security lead" in validation["uncertainty"]
    changed = [case for field in result["operations"][0]["fields"] for case in field["cases"] if case["comparison"] == "different"]
    assert all("lead for review" in case["interpretation"] for case in changed)
    assert all("security impact are not established" in case["uncertainty"] for case in changed)
    assert result["summary"]["errorCases"] == 0  # An HTTP 500 is a response, not a client execution error.


@pytest.mark.parametrize("damage", ["truncated", "excerpt-only", "missing-headers", "transport-error"])
def test_incomplete_evidence_never_groups_as_equivalent(damage):
    capture = exchange()
    if damage == "truncated":
        capture["truncated"] = True
    elif damage == "excerpt-only":
        capture["body_excerpt"] = capture.pop("response_body")
    elif damage == "missing-headers":
        capture.pop("response_headers")
    else:
        capture["error"] = "ReadTimeout"
    plans = [plan_case("one"), plan_case("two", mutation="omission")]
    result = build(audit_fixture(plans, [receipt(plan, capture) for plan in plans]))
    field = first_field(result)
    assert len(field["groups"]) == 2
    assert all(case["comparison"] == "unknown" for case in field["cases"])
    assert result["summary"]["requestSentCases"] == 2
    if damage == "transport-error":
        assert result["summary"]["errorCases"] == 2
        assert result["summary"]["executedCases"] == 0


def test_accounting_matches_plans_to_receipts_and_keeps_family_checks_separate():
    plans = [plan_case("one"), plan_case("two", mutation="omission"),
             plan_case("three", mutation="wrong-type-number"),
             plan_case("four", mutation="unchanged", planned_requests=0, status="not-sent", reason_code="unchanged-baseline"),
             plan_case("five", mutation="format")]
    probes = [receipt(plans[0], exchange()),
              receipt(plans[1], status="blocked-prerequisite", missing_prerequisites=["successful-positive-control", "second-identity"]),
              receipt(plans[2], status="budget-exhausted", reason_code="request-budget-exhausted"),
              receipt(plans[3], status="not-sent", reason_code="unchanged-baseline"),
              receipt(plans[4], status="execution-error", reason_code="request-execution-error"),
              {"operation": "POST /widgets", "check": "access-bypass", "status": "completed", "requests": 0, "request_sent": False}]
    audit = audit_fixture(plans, probes)
    audit["plans"][0]["test_plan"]["supplemental_checks"] = [
        {"check": "authorization", "planned_requests": None, "conditional": True,
         "missing_prerequisites": ["second-identity"]}]
    result = build(audit)
    summary = result["summary"]
    assert summary["totalCases"] == summary["plannedCases"] == 5
    assert [summary[key] for key in ["executedCases", "skippedCases", "errorCases", "unknownCases", "pendingCases"]] == [1, 3, 1, 0, 0]
    assert summary["totalCases"] == sum(summary[key] for key in ["executedCases", "skippedCases", "errorCases", "unknownCases", "pendingCases"])
    assert summary["budgetExhaustedCases"] == 1
    assert summary["operationCheckCases"] == 1
    assert summary["operationChecks"]["unknownCases"] == 1
    assert {"successful-positive-control", "second-identity", "request-budget-exhausted"} <= {row["reason"] for row in summary["blockers"]}
    assert len(result["operations"][0]["checkPlans"]) == 1


def test_multiple_exchanges_are_one_case_and_budget_stops_are_explicit():
    plan = plan_case("one", mutation="sql-boolean", planned_requests=2, conditional=True)
    captured = [exchange(label="control"), exchange(label="probe")]
    probe = receipt(plan, status="budget-exhausted", exchanges=captured, request_sent=True,
                    requests=2, reason_code="request-budget-exhausted")
    result = build(audit_fixture([plan], [probe]))
    summary = result["summary"]
    assert summary["executedCases"] == summary["totalCases"] == 1
    assert summary["evidenceCount"] == 2
    case = first_field(result)["cases"][0]
    assert case["partial"]
    assert case["exchanges"] == captured
    assert "stopped before all" in case["interpretation"]


def test_live_unmatched_plan_is_pending_finished_missing_receipt_is_unknown():
    audit = audit_fixture([plan_case()])
    audit["running"] = True
    pending = build(audit)
    assert pending["summary"]["pendingCases"] == 1
    assert pending["summary"]["individualRecordsMissing"] is False
    audit["running"] = False
    result = build(audit)
    assert result["summary"]["unknownCases"] == 1
    assert result["summary"]["skippedCases"] == 0
    assert result["summary"]["individualRecordsMissing"] is True
    assert build({})["summary"]["individualRecordsMissing"] is False


def test_older_aggregate_coverage_never_creates_case_results():
    result = build({"coverage": {"fields": [{"operation": "POST /legacy", "field_pointer": "/enabled",
                                              "planned_requests": 9, "requests_sent": 3, "status_counts": {"completed": 3}}]},
                    "scope": {"requests_sent": 4}, "requests": []})
    assert result["summary"]["totalCases"] == 0
    assert result["summary"]["individualRecordsMissing"]
    assert first_field(result)["summary"]["individualRecordsMissing"]
    assert first_field(result)["coverage"][0]["requests_sent"] == 3
    assert result["summary"]["requestBreakdown"] == {}


def test_operation_scoping_and_baseline_log_fallback_prevent_cross_operation_matches():
    plan = plan_case()
    audit = audit_fixture([plan], [receipt(plan, exchange())])
    audit["baselines"] = []
    audit["log"] = [exchange(label="baseline", endpoint="POST /widgets"),
                    exchange('{"ok":true}', status=200, label="baseline", endpoint="POST /other")]
    other = {**plan, "operation": "otherOperation"}
    audit["plans"].append({"endpoint": "POST /other", "operation_id": "otherOperation", "test_plan": {"probes": [other]}})
    audit["probes"].append(receipt(other, exchange()))
    result = build(audit)
    assert len(result["operations"]) == 2
    assert result["operations"][0]["fields"][0]["cases"][0]["comparison"] == "same-denial"
    assert result["operations"][1]["fields"][0]["cases"][0]["comparison"] == "different"
    assert result["summary"]["totalCases"] == 2


def test_model_does_not_mutate_original_objects():
    planned = plan_case()
    audit = audit_fixture([planned], [receipt(planned, exchange())])
    result = node("const before=JSON.stringify(input); model.buildResults(input);"
                  "process.stdout.write(JSON.stringify({unchanged:before===JSON.stringify(input)}));", audit)
    assert result["unchanged"]


def test_redacted_equivalence_does_not_override_recorded_response_difference():
    plans = [plan_case("one"), plan_case("two", mutation="omission")]
    baseline = exchange(headers={"set-cookie": "<redacted>"})
    probes = [receipt(plan, exchange(headers={"set-cookie": "<redacted>"}),
                      status="field-response-observed", reason_code="response-difference") for plan in plans]
    result = build(audit_fixture(plans, probes, baseline))
    field = first_field(result)
    assert len(field["groups"]) == 2  # Unknown original differences cannot be grouped as equivalent.
    assert result["summary"]["sameDenialCases"] == 0
    assert result["summary"]["responseDifferenceCases"] == 2
    assert all(case["comparisonDiscrepancy"] for case in field["cases"])
    assert all("redacted exchanges look equivalent" in case["uncertainty"] for case in field["cases"])


def test_changing_metadata_does_not_explain_a_difference_hidden_by_credential_redaction():
    plan = plan_case()
    baseline = exchange(label="baseline", endpoint="POST /widgets",
                        headers={"set-cookie": "session=<credential>", "date": "first"})
    response = exchange(endpoint="POST /widgets",
                        headers={"set-cookie": "session=<credential>", "date": "second"})
    probe = receipt(plan, response, status="field-response-observed", reason_code="response-difference")
    audit = audit_fixture([plan], [probe], baseline)
    audit["log"] = [baseline, response]
    audit["requests"] = 2
    result = build(audit)
    case = first_field(result)["cases"][0]
    assert case["comparison"] == "different"
    assert case["comparisonDiscrepancy"] is True
    assert case["reclassifiedMetadataDifference"] is False
    assert case["metadataDifferences"][0]["name"] == "date"
    assert result["summary"]["sameDenialCases"] == 0
    assert "redacted exchanges look equivalent" in case["uncertainty"]
    requests = result["summary"]["responseSummary"]["endpoint"]
    assert requests["baselineResponses"] == requests["applicationDenialResponses"] == 1
    assert requests["sameDenialResponses"] == 0
    assert requests["unknownResponses"] == requests["comparisonDiscrepancyResponses"] == 1


def test_import_redaction_marker_preserves_cookie_difference_without_probe_reason():
    plans = [plan_case("one"), plan_case("two", mutation="omission")]
    baseline = exchange(label="baseline", endpoint="POST /widgets",
                        headers={"set-cookie": "<credential>", "date": "first"})
    captures = [exchange(label=f"mutation-{i}", endpoint="POST /widgets",
                         headers={"set-cookie": "<credential>", "date": f"later-{i}"})
                for i in range(2)]
    probes = [receipt(plan, captured, status="request-sent")
              for plan, captured in zip(plans, captures, strict=True)]
    audit = audit_fixture(plans, probes, baseline)
    audit["log"] = [baseline, *[{**capture, "comparison_before_import_redaction": {
        "classification": "different", "equivalent": False, "body_status_equivalent": True,
        "meaningful_header_names": ["set-cookie"]}} for capture in captures]]
    audit["requests"] = 3
    original = copy.deepcopy(audit)
    result = build(audit)
    field = first_field(result)
    assert len(field["groups"]) == 2
    assert {case["comparison"] for case in field["cases"]} == {"different"}
    assert all(case["comparisonDiscrepancy"] for case in field["cases"])
    assert all("pre-redaction difference" in case["uncertainty"] for case in field["cases"])
    assert all(case["meaningfulHeaderDifferences"][0]["name"] == "set-cookie" for case in field["cases"])
    assert all(case["meaningfulHeaderDifferences"][0]["valuesRedacted"] for case in field["cases"])
    assert result["summary"]["sameDenialCases"] == 0
    responses = result["summary"]["responseSummary"]["endpoint"]
    assert responses["sameDenialResponses"] == 0
    assert responses["comparisonDiscrepancyResponses"] == 2
    assert responses["meaningfulHeaderDifferenceResponses"] == 2
    assert audit == original


def test_import_redaction_marker_preserves_credential_echo_difference_and_no_value():
    baseline = exchange('{"detail":"<credential>"}')
    changed = exchange('{"detail":"<credential>"}', comparison_before_import_redaction={
        "classification": "different", "equivalent": False, "body_status_equivalent": False,
        "meaningful_header_names": []})
    result = node("process.stdout.write(JSON.stringify(model.compareResponses(input[0],input[1])));",
                  [baseline, changed])
    assert result["classification"] == "different"
    assert result["equivalent"] is False and result["applicationEquivalent"] is False
    assert result["redactionDifference"]
    assert "concealed values cannot be reconstructed" in result["reason"]


def test_import_marker_does_not_override_current_diagnostic_policy_or_incomplete_response():
    baseline = exchange(headers={"set-cookie": "<credential>", "date": "first"})
    changed = exchange(headers={"set-cookie": "<credential>", "date": "later"}, comparison_before_import_redaction={
        "classification": "different", "equivalent": False, "body_status_equivalent": True,
        "meaningful_header_names": ["date"]})
    result = node("process.stdout.write(JSON.stringify(model.compareResponses(input[0],input[1])));",
                  [baseline, changed])
    assert result["classification"] == "same-denial" and not result["redactionDifference"]
    changed["error"] = "ReadTimeout"
    changed["comparison_before_import_redaction"]["meaningful_header_names"] = ["set-cookie"]
    result = node("process.stdout.write(JSON.stringify(model.compareResponses(input[0],input[1])));",
                  [baseline, changed])
    assert result["classification"] == "unknown" and result["equivalent"] is None


def test_new_comparison_retains_meaningful_difference_hidden_by_old_receipt_classifier():
    plan = plan_case()
    result = build(audit_fixture([plan], [receipt(plan, exchange('{"id":9007199254740993}'))],
                                exchange('{"id":9007199254740992}')))
    case = first_field(result)["cases"][0]
    assert case["comparison"] == "different"
    assert case["comparisonDiscrepancy"]
    assert "Review this discrepancy" in case["interpretation"]


def test_body_field_named_query_is_not_misclassified_as_query_parameter():
    probe = {"operation": "POST /widgets", "family": "body-injection", "check": "error-probe",
             "field_pointer": "/query/value", "status": "request-sent", "request_sent": True,
             "exchanges": [exchange()]}
    plan = {**probe, "mutation": "error-probe", "status": "planned", "planned_requests": 2}
    plan.pop("exchanges")
    audit = audit_fixture()
    audit["plans"][0]["test_plan"]["supplemental_probes"] = [plan]
    audit["probes"] = [probe]
    result = build(audit)
    assert first_field(result)["location"] == "body"
    assert result["summary"]["totalCases"] == 1


def test_compact_export_references_exact_original_plan_and_evidence_without_body_duplication():
    plans = [plan_case("one"), plan_case("two", mutation="paired-probe", conditional=True, planned_requests=2)]
    captured = [exchange(label="control"), exchange(label="probe")]
    probes = [receipt(plans[0], exchange()),
              receipt(plans[1], exchanges=captured, request_sent=True, requests=2)]
    audit = audit_fixture(plans, probes)
    result = node("process.stdout.write(JSON.stringify(model.exportResults(input)));", audit)
    cases = result["operations"][0]["fields"][0]["cases"]
    assert cases[0]["receiptSource"] == "#/coverage/probes/0"
    assert cases[0]["evidence"][0]["source"] == "#/coverage/probes/0/exchange"
    assert cases[0]["planSource"] == "#/test_plans/0/test_plan/probes/0"
    assert cases[0]["baselineEvidence"] == "#/coverage/baselines/0/exchange"
    assert [entry["source"] for entry in cases[1]["evidence"]] == [
        "#/coverage/probes/1/exchanges/0", "#/coverage/probes/1/exchanges/1"]
    assert "response_body" not in json.dumps(result)
    assert result["operations"][0]["fields"][0]["groups"][0]["caseIds"] == [cases[0]["id"]]
    assert all("interpretation" in case and "uncertainty" in case for case in cases)
    # Verify every JSON pointer resolves against the same structure auditExportPayload writes.
    payload = {"coverage": {"probes": probes, "baselines": audit["baselines"]},
               "test_plans": audit["plans"], "requests": audit["log"]}
    for case in cases:
        for pointer in [case["receiptSource"], case["planSource"], case["baselineEvidence"],
                        *[entry["source"] for entry in case["evidence"]]]:
            target = payload
            for token in pointer[2:].split("/"):
                target = target[int(token)] if isinstance(target, list) else target[token]
            assert target


def test_compact_export_baseline_log_reference_works_for_older_audits():
    plan = plan_case()
    audit = audit_fixture([plan], [receipt(plan, exchange())])
    audit["baselines"] = []
    audit["log"] = [exchange(label="baseline", endpoint="POST /widgets")]
    result = node("process.stdout.write(JSON.stringify(model.exportResults(input)));", audit)
    assert result["operations"][0]["fields"][0]["cases"][0]["baselineEvidence"] == "#/requests/0"


@pytest.mark.parametrize(("check", "kind"), [
    ("contract-review", "specification"), ("passive-review", "baseline-review"),
    ("response-contract", "baseline-review"), ("transport", "transport-review"),
    ("jwt-offline", "offline-token"),
])
def test_explicit_review_receipts_are_observations_without_implying_probe_requests(check, kind):
    probe = {"operation": "POST /widgets", "check": check, "family": check, "field_pointer": "",
             "status": "completed", "reason_code": "completed", "request_sent": False, "requests": 0,
             "missing_prerequisites": []}
    result = build(audit_fixture(probes=[probe]))
    summary, case = result["summary"], result["operations"][0]["checks"][0]
    assert case["state"] == "observed"
    assert case["observationKind"] == kind
    assert case["requestSent"] is False
    assert case["exchanges"] == []
    assert summary["totalCases"] == 0
    assert summary["operationChecks"]["observedCases"] == 1
    assert summary["operationChecks"]["executedCases"] == summary["operationChecks"]["requestSentCases"] == 0
    assert not summary["blockers"]
    assert summary["fieldRecordsMissing"] is summary["operationCheckRecordsMissing"] is False


def test_baseline_review_needs_captured_baseline_and_generic_completed_receipt_stays_unknown():
    probes = [{"operation": "POST /widgets", "check": check, "status": "completed",
               "request_sent": False, "requests": 0} for check in ["response-contract", "access-bypass"]]
    audit = audit_fixture(probes=probes)
    audit["baselines"] = []
    result = build(audit)
    assert result["summary"]["operationChecks"]["unknownCases"] == 2
    assert result["summary"]["operationChecks"]["observedCases"] == 0
    assert result["summary"]["fieldRecordsMissing"] is False
    assert result["summary"]["operationCheckRecordsMissing"] is True


def test_all_actual_local_denied_run_reviews_have_honest_zero_request_observations():
    from tests.test_denied_campaign_integration import audit

    result, _ = audit()
    model = build({"probes": result["probes"], "plans": [{"endpoint": result["endpoint"], "test_plan": result["test_plan"]}],
                   "fieldCoverage": result["field_coverage"], "log": result["log"],
                   "baselines": [{"endpoint": result["endpoint"], "exchange": result["baseline"]}],
                   "requests": result["requests_sent"], "requestBreakdown": result["request_breakdown"]})
    observed = [case for case in model["operations"][0]["checks"] if case["state"] == "observed"]
    assert {case["mutation"] for case in observed} == {
        "contract-review", "transport", "response-contract", "passive-review", "framing", "redirect-downgrade"}
    assert all(case["observationKind"] == "baseline-review" for case in observed
               if case["mutation"] in {"framing", "redirect-downgrade"})
    assert all(not case["requestSent"] for case in observed)
    assert model["summary"]["operationChecks"]["unknownCases"] == 0
    assert model["summary"]["fieldRecordsMissing"] is False
    assert model["summary"]["operationCheckRecordsMissing"] is False
    assert not any(blocker["reason"] == "execution-receipt-or-evidence-not-recorded" for blocker in model["summary"]["blockers"])


def test_current_engine_mock_receipts_preserve_redaction_and_account_for_every_field_case():
    from namazu.audit.engine import audit_operation, audit_plan
    from namazu.spec import parse_spec

    base, secret = "http://127.0.0.1:9876", "local-results-fixture-secret-48219"
    parsed = parse_spec({"openapi": "3.1.0", "info": {"title": "Local results fixture", "version": "1"},
                         "servers": [{"url": base}], "paths": {"/widgets": {"post": {
                             "requestBody": {"content": {"application/json": {"schema": {
                                 "type": "object", "properties": {"enabled": {"type": "boolean"},
                                                                        "quantity": {"type": "integer", "minimum": 1, "maximum": 5}}}}}},
                             "responses": {"403": {"description": "Denied"}}}}}})
    options = {"base_url": base, "profile": "writes", "allow_mutating": True, "request_budget": 12,
               "identities": {"primary": {"Authorization": f"Bearer {secret}"}},
               "example": {"body": {"enabled": True, "quantity": 3, "password": secret}}}
    operation_id = parsed["operations"][0]["id"]
    plan = audit_plan(parsed, operation_id, **options)
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(403, json={"error": "Not entitled"}))) as client:
        result = audit_operation(parsed, operation_id, client=client, **options)
    audit = {"running": False, "plans": [plan], "probes": result["probes"],
             "fieldCoverage": result["field_coverage"], "log": result["log"],
             "baselines": [{"endpoint": result["endpoint"], "exchange": result["baseline"]}],
             "requests": result["requests_sent"], "requestBreakdown": result["request_breakdown"]}
    model = build(audit)
    assert secret not in json.dumps(model)
    assert len(model["operations"]) == 1
    expected = len(plan["test_plan"]["probes"]) + len(plan["test_plan"]["supplemental_probes"])
    assert model["summary"]["totalCases"] == model["summary"]["plannedCases"] == expected
    assert model["summary"]["totalRequests"] == 12
    assert model["summary"]["sameDenialCases"] > 0
    assert model["summary"]["budgetExhaustedCases"] > 0
    assert model["summary"]["responseDifferenceCases"] == 0
    assert model["summary"]["operationChecks"]["skippedCases"] > 0
    assert model["summary"]["requestBreakdown"]["inventory"] == 0


@pytest.fixture
def exported_excerpts():
    return json.loads(Path("tests/fixtures/response_classification_export.json").read_text(encoding="utf8"))


def compare(baseline, response, **options):
    return node("process.stdout.write(JSON.stringify(model.compareResponses(input.baseline,input.response,input.options)));",
                {"baseline": baseline, "response": response, "options": options})


def test_export_identical_application_denial_records_metadata_changes_and_reclassifies_old_lead(exported_excerpts):
    data = exported_excerpts
    comparison = compare(data["baseline"], data["metadata_only_denial"])
    assert comparison["equivalent"] is comparison["applicationEquivalent"] is True
    assert comparison["classification"] == "same-denial"
    assert {row["name"] for row in comparison["metadataDifferences"]} == {"date", "fm-correlation-id", "x-iinfo"}
    assert comparison["meaningfulHeaderDifferences"] == []
    plan = plan_case(pointer="/documentUri")
    probe = receipt(plan, data["metadata_only_denial"], status="field-specific-response-observed",
                    reason_code="field-response-difference-lead")
    result = build(audit_fixture([plan], [probe], data["baseline"]))
    case = first_field(result)["cases"][0]
    assert case["comparison"] == "same-denial"
    assert case["reclassifiedMetadataDifference"] is True
    assert case["comparisonDiscrepancy"] is False
    assert case["derivedReasonCode"] == "same-denial-as-baseline"
    assert case["receipt"]["reason_code"] == "field-response-difference-lead"
    assert case["exchanges"][0] == data["metadata_only_denial"]
    assert result["summary"]["responseDifferenceCases"] == 0


def test_export_field_validation_is_an_observation_with_original_body_and_headers(exported_excerpts):
    data = exported_excerpts
    compared = compare(data["baseline"], data["validation"], fieldPointer="/documentUri")
    assert compared["classification"] == "validation-observation"
    assert not compared["equivalent"]
    assert compared["meaningfulHeaderDifferences"]  # Never discard these because validation is expected.
    plan = plan_case(pointer="/documentUri")
    result = build(audit_fixture([plan], [receipt(plan, data["validation"], status="field-specific-response-observed",
                                                 reason_code="field-response-difference-lead")], data["baseline"]))
    case = first_field(result)["cases"][0]
    assert case["comparison"] == "validation-observation"
    assert case["derivedReasonCode"] == "field-validation-observed"
    assert "not automatically a security lead" in case["uncertainty"]
    assert case["exchanges"][0] == data["validation"]
    assert compare(data["baseline"], exchange('{"error":"Bad request"}', status=400),
                   fieldPointer="/documentUri")["classification"] == "different"
    assert compare(data["baseline"], data["validation"], fieldPointer="/unrelated")["classification"] == "different"


def test_export_explicit_edge_markers_are_distinct_from_plain_403(exported_excerpts):
    data = exported_excerpts
    comparison = compare(data["baseline"], data["edge_block"])
    assert comparison["classification"] == "edge-block"
    assert comparison["edgeMarkers"] == ["/_Incapsula_Resource", "Incapsula incident ID"]
    assert compare(data["baseline"], data["baseline"])["classification"] == "same-denial"
    unbranded = {**data["edge_block"], "response_body": "<html><body>Forbidden</body></html>"}
    assert compare(data["baseline"], unbranded)["classification"] == "different"
    plan = plan_case()
    case = first_field(build(audit_fixture([plan], [receipt(plan, data["edge_block"])], data["baseline"])))["cases"][0]
    assert case["comparison"] == "edge-block"
    assert "Downstream handling is unknown" in case["uncertainty"]
    assert "HTTP 403 alone" in case["uncertainty"]


def test_export_security_header_change_stays_visible_despite_application_equivalence(exported_excerpts):
    data = exported_excerpts
    compared = compare(data["baseline"], data["security_header_change"])
    assert compared["applicationEquivalent"] is True
    assert compared["equivalent"] is False
    assert compared["classification"] == "different"
    assert "x-frame-options" in {row["name"] for row in compared["meaningfulHeaderDifferences"]}


def test_export_timeout_is_incomplete_and_never_grouped_as_denial_or_validation(exported_excerpts):
    data = exported_excerpts
    comparison = compare(data["baseline"], data["timeout"])
    assert comparison["equivalent"] is comparison["applicationEquivalent"] is None
    assert comparison["classification"] == "unknown"
    plans = [plan_case(str(index), mutation=f"case-{index}") for index in range(6)]
    probes = [receipt(plan, captured, status="execution-error") for plan, captured in zip(plans, data["timeouts"], strict=True)]
    result = build(audit_fixture(plans, probes, data["baseline"]))
    assert result["summary"]["errorCases"] == result["summary"]["incompleteCases"] == 6
    assert result["summary"]["executedCases"] == result["summary"]["sameDenialCases"] == 0
    assert len(first_field(result)["groups"]) == 6
    assert all(case["comparison"] == "unknown" for case in first_field(result)["cases"])


def test_metadata_policy_is_exact_configurable_and_cannot_hide_security_headers(exported_excerpts):
    data = exported_excerpts
    strict = compare(data["baseline"], data["metadata_only_denial"], policy={"metadata_headers": []})
    assert strict["applicationEquivalent"] is True
    assert strict["equivalent"] is False
    assert strict["metadataDifferences"] == []
    assert {row["name"] for row in strict["meaningfulHeaderDifferences"]} == {"date", "fm-correlation-id", "x-iinfo"}
    permitted = compare(data["baseline"], data["metadata_only_denial"],
                        policy={"metadata_headers": ["DATE", "Fm-Correlation-Id", "X-IINFO"]})
    assert permitted["equivalent"]
    rejected = node("const names=['x-*','x-frame-options','set-cookie','www-authenticate','x-custom'];"
                    "process.stdout.write(JSON.stringify(names.map(name=>{try{model.normalizePolicy({metadata_headers:[name]});"
                    "return false;}catch{return true;}})));", {})
    assert all(rejected)
    result = build({"response_comparison": {"metadata_headers": []}})
    assert result["responseComparisonPolicy"] == {"metadata_headers": []}


def test_unique_export_request_counts_do_not_sum_overlapping_probe_receipts(exported_excerpts):
    data = exported_excerpts
    plan = plan_case(pointer="/documentUri")
    audit = audit_fixture([plan], [receipt(plan, data["metadata_only_denial"])], data["baseline"])
    audit["plans"][0]["endpoint"] = "POST /mock"
    audit["baselines"][0]["endpoint"] = "POST /mock"
    audit["requests"] = data["counts"]["total_requests"]
    audit["log"] = data["requests"]
    audit["probes"].append({"operation": "POST /mock", "check": "aggregate", "request_sent": True,
                            "exchanges": data["requests"][50:]})
    result = build(audit)
    summary = result["summary"]["responseSummary"]
    assert summary["total"]["requests"] == 141
    assert summary["endpoint"]["requests"] == 91
    assert summary["inventory"]["requests"] == 50
    assert summary["endpoint"]["baselineResponses"] == 1
    assert summary["endpoint"]["applicationDenialResponses"] == 40
    assert summary["endpoint"]["sameDenialResponses"] == 39
    assert summary["endpoint"]["validationResponses"] == 28
    assert summary["endpoint"]["edgeBlockResponses"] == 15
    assert summary["inventory"]["edgeBlockResponses"] == 4
    assert summary["endpoint"]["incompleteResponses"] == 6
    assert summary["endpoint"]["differentResponses"] == 2  # OPTIONS and TRACE, not validation rejections.
    assert summary["unassigned"]["requests"] == 0
    assert result["summary"]["evidenceCount"] != summary["total"]["requests"]
    assert summary["logComplete"] is True
    audit["log"] = audit["log"][:2]
    assert build(audit)["summary"]["responseSummary"]["logComplete"] is False
