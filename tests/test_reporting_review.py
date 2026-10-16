"""Independent regression checks for honest offline assessment accounting."""
import copy
import json

import pytest

from namazu.audit.reporting import assess_saved_audit

ENDPOINT = "POST /mock"


def record(*, label="mutation", status=403, body=None, headers=None, request_body=None):
    return {"endpoint": ENDPOINT, "label": label, "method": "POST", "url": "http://127.0.0.1/mock",
            "status": status, "request_headers": {}, "request_body": request_body or '{"value":1}',
            "response_headers": {"content-type": "application/json", **(headers or {})},
            "response_body": json.dumps({"error": "Denied"} if body is None else body), "error": ""}


def audit(baseline, *requests):
    return {"findings": [], "requests": [baseline, *requests],
            "scope": {"requests_sent": 1 + len(requests), "second_identity": False},
            "coverage": {"baselines": [{"endpoint": ENDPOINT, "exchange": baseline,
                                         "status": baseline["status"], "positive_control": False}],
                         "checks": [], "probes": []}}


@pytest.mark.parametrize("absent", [False, True])
def test_missing_status_is_an_incomplete_attempt_not_a_received_response(absent):
    baseline = record(label="baseline")
    incomplete = record(status=0)
    if absent:
        incomplete.pop("status")
    result = assess_saved_audit(audit(baseline, incomplete))
    totals = result["request_accounting"]["total"]
    assert totals["request_attempts"] == 2
    assert totals["responses_received"] == 1
    assert totals["incomplete-test"] == 1
    assert result["response_cases"][1]["classification"] == "incomplete-test"


def test_distinct_fields_and_repeated_evidence_are_counted_separately():
    payload = audit(record(label="baseline"))
    evidence = {"id": "input.example", "endpoint": ENDPOINT,
                "assessment": {"category": "security", "origin": "runtime-observation",
                               "verification": "impact-demonstrated"}}
    payload["findings"] = [{**evidence, "parameter": "/left"}, {**evidence, "parameter": "/right"},
                           {**evidence, "parameter": "/left"}]
    security = assess_saved_audit(payload)["security"]
    assert security["demonstrated_vulnerabilities"] == 2
    assert security["affected_operations"] == 1
    assert security["evidence_records"] == 3
    assert security["finding_refs"] == ["#/findings/0", "#/findings/1", "#/findings/2"]


@pytest.mark.parametrize("pointer,key", [("/timestamp", "timestamp"), ("/requestId", "requestId")])
def test_mutated_input_with_metadata_name_remains_meaningful(pointer, key):
    baseline = record(label="baseline", body={"error": "Denied", key: "original"})
    mutated = record(body={"error": "Denied", key: "changed"}, request_body=json.dumps({key: "changed"}))
    payload = audit(baseline, mutated)
    payload["coverage"]["probes"] = [{"operation": ENDPOINT, "field_pointer": pointer,
                                         "request_sent": True, "exchanges": [mutated]}]
    result = assess_saved_audit(payload)
    assert result["response_cases"][1]["classification"] == "different"
    assert result["request_accounting"]["endpoint"].get("same-denial", 0) == 0
    # Without that input association the same key is diagnostic metadata.
    payload["coverage"]["probes"] = []
    assert assess_saved_audit(payload)["response_cases"][1]["classification"] == "same-denial"


def test_2xx_without_business_assertions_does_not_claim_successful_summarisation():
    baseline = record(label="baseline", status=200, body={"status": "accepted"})
    payload = audit(baseline)
    payload["coverage"]["baselines"][0]["positive_control"] = True
    result = assess_saved_audit(payload)
    assert "resource-and-content-assertions" in result["missing_prerequisites"]
    assert any("summarisation" in item and "has not been established" in item
               for item in result["coverage_limitations"])
    assert result["security"]["demonstrated_vulnerabilities"] == 0


def test_expected_denial_does_not_remove_success_prerequisite():
    baseline = record(label="baseline")
    payload = audit(baseline)
    payload["coverage"]["baselines"][0].update(outcome="success", expected_negative=True,
                                                positive_control=False)
    result = assess_saved_audit(payload)
    assert "successful-positive-control" in result["missing_prerequisites"]
    assert any("summarisation" in item for item in result["coverage_limitations"])


def test_offline_assessment_preserves_originals_and_redacts_echoed_header_credentials():
    baseline = record(label="baseline", status=200, headers={
        "cache-control": 'public, extension="fixture-secret-value"'})
    baseline["request_headers"] = {"Authorization": "Bearer fixture-secret-value"}
    payload = audit(baseline)
    original = copy.deepcopy(payload)
    result = assess_saved_audit(payload)
    assert payload == original
    assert "fixture-secret-value" not in json.dumps(result)
    assert "<credential>" in json.dumps(result["header_observations"])
    assert result["target_requests_sent"] == 0


@pytest.mark.parametrize("status,reason", [
    ("field-response-observed", "response-difference"),
    ("field-specific-response-observed", "field-response-difference-lead"),
])
def test_original_difference_hidden_by_redaction_stays_unresolved(status, reason):
    baseline = record(label="baseline", headers={"set-cookie": "session=<credential>", "date": "first"})
    mutation = record(headers={"set-cookie": "session=<credential>", "date": "second"})
    payload = audit(baseline, mutation)
    payload["coverage"]["probes"] = [{"operation": ENDPOINT, "field_pointer": "/value",
        "request_sent": True, "status": status, "reason_code": reason,
        "exchanges": [mutation]}]
    result = assess_saved_audit(payload)
    assert result["request_accounting"]["endpoint"].get("same-denial", 0) == 0
    assert result["response_cases"][1]["classification"] in {"unknown", "comparison-discrepancy"}
