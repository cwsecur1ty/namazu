"""Offline regression cases sanitised from the user's October 9 audit export."""
import copy
import json
import subprocess
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from namazu.audit import coverage
from namazu.audit.engine import _probe_coverage
from namazu.audit.model import Exchange
from namazu.audit.response_compare import (
    compare_responses,
    equivalent,
    field_validation_observed,
    normalize_policy,
    safe_comparison,
)
from tests.test_input_campaign import run, setup
from tests.test_response_comparison import record


@pytest.fixture
def saved_export():
    return json.loads((Path(__file__).parent / "fixtures" / "response_classification_export.json").read_text(encoding="utf-8"))


def captured(row):
    return Exchange(label=row.get("label", "sanitised local fixture"), method=row["method"], url=row["url"],
                    request_headers=row.get("request_headers", {}), request_body=row.get("request_body"),
                    status=row["status"], headers=row.get("response_headers", {}), body=row.get("response_body", ""),
                    truncated=row.get("truncated", False), error=row.get("error", ""))


def test_identical_export_denial_reports_only_named_metadata_differences(saved_export):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["metadata_only_denial"])
    before = copy.deepcopy([baseline.to_dict(), changed.to_dict()])
    comparison = compare_responses(changed, baseline)
    assert comparison["classification"] == "same-denial"
    assert comparison["equivalent"] is comparison["body_status_equivalent"] is True
    assert {item["name"] for item in comparison["metadata_differences"]} == {"date", "fm-correlation-id", "x-iinfo"}
    assert comparison["meaningful_header_differences"] == []
    assert [baseline.to_dict(), changed.to_dict()] == before
    receipt = record(baseline, changed, field="documentUri")
    assert receipt["status"] == "same-denial"
    assert "unknown" in receipt["reason"]


def test_export_validation_response_is_observation_with_original_evidence(saved_export):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["validation"])
    before = changed.to_dict()
    comparison = compare_responses(changed, baseline, field_name="documentUri")
    assert comparison["classification"] == "validation-observation"
    assert comparison["equivalent"] is False
    assert comparison["body_status_equivalent"] is False
    receipt = record(baseline, changed, field="documentUri")
    assert receipt["reason_code"] == "field-validation-observed"
    assert "lead" not in receipt["reason"].lower()
    assert receipt["exchanges"][0] == before
    assert not field_validation_observed(changed, "otherField")
    generic = copy.deepcopy(changed)
    generic.body = '{"title":"Bad Request","field":"documentUri"}'
    assert not field_validation_observed(generic, "documentUri")


def test_explicit_incapsula_markers_are_edge_block_not_application_denial(saved_export):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["edge_block"])
    comparison = compare_responses(changed, baseline)
    assert comparison["classification"] == "edge-block"
    assert comparison["edge_block_markers"] == ["/_Incapsula_Resource", "Incapsula incident ID"]
    receipt = record(baseline, changed)
    assert receipt["status"] == "edge-block-observed"
    assert "downstream application handling is unknown" in receipt["reason"]
    # A status, a CDN header, or a mention of the product cannot identify a block page.
    for body in ("Forbidden", "<html>Forbidden</html>", '<html src="/_Incapsula_Resource">normal page</html>'):
        changed.body = body
        assert compare_responses(changed, baseline)["classification"] != "edge-block"
    assert compare_responses(baseline, baseline)["classification"] == "same-denial"


def test_meaningful_security_header_change_is_preserved_separately(saved_export):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["security_header_change"])
    comparison = compare_responses(changed, baseline)
    assert comparison["body_status_equivalent"] is True
    assert comparison["equivalent"] is False
    assert comparison["classification"] == "different"
    assert comparison["meaningful_header_differences"] == [{"name": "x-frame-options", "left": "SAMEORIGIN", "right": "DENY"}]


def test_all_six_export_timeouts_remain_incomplete(saved_export):
    baseline = captured(saved_export["baseline"])
    assert len(saved_export["timeouts"]) == 6
    for row in saved_export["timeouts"]:
        timeout = captured(row)
        comparison = compare_responses(timeout, baseline)
        assert comparison["classification"] == "unknown"
        assert comparison["equivalent"] is None
        assert comparison["comparable"] is False
        receipt = record(baseline, timeout)
        assert receipt["status"] == "execution-error"
        assert receipt["request_sent"] is True
        assert "Incomplete test" in receipt["reason"]
        assert receipt["exchanges"][0]["error"] == timeout.error


def test_full_offline_export_classification_accounts_for_recorded_post_exchanges(saved_export):
    baseline = captured(saved_export["baseline"])
    categories = Counter()
    for row in saved_export["requests"]:
        if row["method"] != "POST" or row["seqGlobal"] == saved_export["baseline"]["seqGlobal"]:
            continue
        response = captured(row)
        try:
            fields = list(json.loads(response.body).get("errors", {}))
        except (ValueError, AttributeError):
            fields = []
        categories[compare_responses(response, baseline, field_name=fields[0] if fields else "")["classification"]] += 1
    assert categories == {"same-denial": 39, "edge-block": 15, "validation-observation": 28, "different": 8, "unknown": 6}


def test_metadata_policy_is_explicit_configurable_and_cannot_hide_security_headers(saved_export):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["metadata_only_denial"])
    assert equivalent(changed, baseline) is True
    assert equivalent(changed, baseline, policy={"metadata_headers": []}) is False
    partial = compare_responses(changed, baseline, policy={"metadata_headers": [" DATE ", "FM-Correlation-ID"]})
    assert {item["name"] for item in partial["metadata_differences"]} == {"date", "fm-correlation-id"}
    assert {item["name"] for item in partial["meaningful_header_differences"]} == {"x-iinfo"}
    for unsupported in ("*", "x-*", "set-cookie", "content-security-policy", "x-validation-field", "x-custom-diagnostic"):
        with pytest.raises(ValueError, match="Unsupported"):
            normalize_policy({"metadata_headers": [unsupported]})
    with pytest.raises(ValueError):
        normalize_policy({"metadata_headers": "date"})


def test_comparison_metadata_values_do_not_bypass_credential_redaction(saved_export):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["metadata_only_denial"])
    secret = "private-comparison-credential"
    changed.request_headers = {"Authorization": "Bearer " + secret}
    changed.headers["fm-correlation-id"] = secret
    comparison = safe_comparison(compare_responses(changed, baseline), changed, baseline)
    assert secret not in json.dumps(comparison)
    assert any(item["left"] == "<credential>" for item in comparison["metadata_differences"])
    assert secret not in json.dumps(record(baseline, changed))
    changed.request_headers = {"X-Custom-Identity": secret}
    comparison = safe_comparison(compare_responses(changed, baseline), changed, baseline, credentials={secret})
    assert secret not in json.dumps(comparison)


@pytest.mark.parametrize("fixture_key,reason,status", [
    ("validation", "field-validation-observed", "field-specific-response-observed"),
    ("edge_block", "edge-block-page", "edge-block-observed"),
    ("timeout", "transport-error", "execution-error"),
])
def test_schema_campaign_saves_classification_and_original_evidence(saved_export, fixture_key, reason, status):
    _, _, built, plan = setup(schema={"type": "object", "properties": {"documentUri": {"type": "string"}}},
                             body={"documentUri": "http://127.0.0.1/document"})
    calls = 0

    def handler(request):
        nonlocal calls
        row = saved_export["baseline"] if calls == 0 else saved_export[fixture_key]
        calls += 1
        if row.get("error"):
            raise httpx.ReadTimeout("sanitised local timeout", request=request)
        return httpx.Response(row["status"], headers=row["response_headers"], content=row["response_body"])

    result, _, _ = run(plan, built, handler)
    receipts = [item for item in result["probes"] if item["request_sent"]]
    assert receipts and all(item["reason_code"] == reason and item["status"] == status for item in receipts)
    if fixture_key == "validation":
        assert all("lead" not in item["observation"] for item in receipts)
    if fixture_key != "timeout":
        assert all(item["exchange"]["response_body"] == saved_export[fixture_key]["response_body"] for item in receipts)


def test_validation_and_meaningful_header_change_are_both_retained_in_field_coverage(saved_export):
    _, _, built, plan = setup(schema={"type": "object", "properties": {"documentUri": {"type": "string"}}},
                             body={"documentUri": "http://127.0.0.1/document"})
    baseline = saved_export["baseline"]
    candidate = copy.deepcopy(saved_export["validation"])
    candidate["response_headers"]["x-frame-options"] = "SAMEORIGIN"
    calls = 0

    def handler(request):
        nonlocal calls
        row = baseline if calls == 0 else candidate
        calls += 1
        return httpx.Response(row["status"], headers=row["response_headers"], content=row["response_body"])

    result, _, _ = run(plan, built, handler)
    field = next(item for item in result["field_coverage"] if item["field_pointer"] == "/documentUri")
    assert field["response_classification_counts"] == {"validation-observation": field["requests_sent"]}
    assert field["meaningful_header_difference_cases"] == field["requests_sent"]
    for receipt in result["probes"]:
        if receipt["request_sent"]:
            assert receipt["comparison"]["classification"] == "validation-observation"
            assert any(change["name"] == "x-frame-options" for change in receipt["comparison"]["meaningful_header_differences"])


def test_python_and_browser_classification_agree_for_sanitised_export(saved_export):
    cases = []
    expected = []
    baseline = captured(saved_export["baseline"])
    for row in saved_export["requests"]:
        if row["method"] != "POST" or row["seqGlobal"] == saved_export["baseline"]["seqGlobal"]:
            continue
        try:
            fields = list(json.loads(row["response_body"]).get("errors", {}))
        except (ValueError, AttributeError):
            fields = []
        field = fields[0].rsplit(".", 1)[-1] if fields else ""
        cases.append({"exchange": row, "field": field})
        expected.append(compare_responses(captured(row), baseline, field_name=field)["classification"])
    module = str(Path(__file__).resolve().parents[1] / "namazu" / "static" / "audit-results.js")
    script = """
const model = require(process.argv[1]);
const data = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(data.cases.map(item => model.compareResponses(data.baseline, item.exchange,
  { fieldPointer: item.field ? '/' + item.field : '' }).classification)));
"""
    process = subprocess.run(["node", "-e", script, module], input=json.dumps({"baseline": saved_export["baseline"], "cases": cases}),
                             capture_output=True, text=True, check=True)
    assert json.loads(process.stdout) == expected


@pytest.mark.parametrize("campaign_receipt", [False, True])
def test_family_coverage_retains_validation_and_meaningful_header_observations(campaign_receipt):
    comparison = {"classification": "validation-observation", "meaningful_header_differences": [
        {"name": "x-frame-options", "left": "SAMEORIGIN", "right": "DENY"},
    ]}
    receipt = {"family": "input-handling", "requests": 1, "request_sent": True,
               "status": "field-specific-response-observed", "reason_code": "field-validation-observed"}
    if campaign_receipt:
        receipt["comparison"] = comparison
        executor = SimpleNamespace(probe_results=[], campaign_result={"probes": [receipt]})
        family = "schema-inputs"
    else:
        receipt["comparisons"] = [comparison]
        executor = SimpleNamespace(probe_results=[receipt])
        family = "input-handling"
    ledger = coverage.Ledger()
    _probe_coverage(ledger, executor)
    entry = next(item for item in ledger.entries() if item.check == family)
    assert entry.findings == 0
    assert entry.requests == 1
    assert entry.state == "inconclusive"
    assert "field-validation-observed" in entry.reason_codes
    assert "meaningful-response-header-difference" in entry.reason_codes
    assert "validation rejection was observed" in entry.reason
    assert "x-frame-options" in entry.reason
    assert "lead" not in entry.reason.lower()


@pytest.mark.parametrize("credential", ["true", "0", "403", "same-denial", 'quote"slash\\tab\tline\nnull\0'])
def test_comparison_redaction_only_changes_string_header_values(saved_export, credential):
    baseline, changed = captured(saved_export["baseline"]), captured(saved_export["metadata_only_denial"])
    changed.request_headers = {"Cookie": "identity=" + credential}
    changed.headers["fm-correlation-id"] = credential
    original = compare_responses(changed, baseline)
    redacted = safe_comparison(original, changed, baseline, credentials={credential})
    assert redacted["comparable"] is True
    assert redacted["equivalent"] is True
    assert redacted["body_status_equivalent"] is True
    assert redacted["classification"] == "same-denial"
    assert any(item["left"] == "<credential>" for item in redacted["metadata_differences"])
    assert any(item["left"] == credential for item in original["metadata_differences"])
