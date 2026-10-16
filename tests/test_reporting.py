"""Offline assessment of sanitised captured evidence, without replaying the target."""
import copy
import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit import contract, reporting


def saved_audit():
    fixture = json.loads(Path("tests/fixtures/response_classification_export.json").read_text(encoding="utf-8"))
    return {"findings": [], "requests": fixture["requests"], "scope": {"requests_sent": 141, "second_identity": False},
            "coverage": {"baselines": [{"endpoint": "POST /mock", "status": 403, "positive_control": False,
                                        "exchange": fixture["baseline"]}],
                         "checks": fixture["notes_audit"]["coverage"]["checks"]}}


def test_full_saved_export_counts_remain_correct_and_source_unchanged(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline reporting must never construct a target HTTP client")
    monkeypatch.setattr(httpx, "Client", forbidden)
    payload = saved_audit()
    before = copy.deepcopy(payload)
    result = reporting.assess_saved_audit(payload)
    assert payload == before
    endpoint = result["request_accounting"]["endpoint"]
    assert endpoint["request_attempts"] == 91
    assert endpoint["responses_received"] == 85
    assert endpoint["same-denial"] == 39
    assert endpoint["validation-observation"] == 28
    assert endpoint["edge-block"] == 15
    assert endpoint["incomplete-test"] == 6
    assert result["request_accounting"]["inventory"]["request_attempts"] == 50
    assert result["security"]["demonstrated_vulnerabilities"] == 0
    assert result["blocked_families"]["count"] == 9
    assert result["operations"][0]["response_review"]["contract"]["state"] == "unavailable"
    assert {"distinct-second-identity", "successful-positive-control", "explicit-permission-matrix"} <= set(result["missing_prerequisites"])
    assert any("summarisation" in note for note in result["coverage_limitations"])
    assert any("cache isolation" in note for note in result["coverage_limitations"])


def test_new_snapshot_reviews_non_baseline_statuses_and_aggregates_evidence():
    payload = saved_audit()
    operation = {"id": "create", "method": "POST", "path": "/mock",
                 "responses": {"403": {"content": {"application/json": {"schema": {"type": "object"}}}}}}
    payload["contract_snapshots"] = {"POST /mock": contract.snapshot({"document": {}}, operation)}
    result = reporting.assess_saved_audit(payload)
    review = result["operations"][0]["response_review"]
    findings = review["contract"]["findings"]
    assert len(findings) == 1
    mismatch = findings[0]["evidence"]["mismatches"]
    status400 = next(row for row in mismatch if row["kind"] == "undocumented-status" and row["status"] == 400)
    assert status400["occurrence_count"] == 28
    assert len(status400["occurrences"]) == 28
    assert review["edge_responses"] == 15
    assert review["incomplete_tests"] == 6
    assert findings[0]["assessment"]["category"] == "contract"
    assert result["security"]["demonstrated_vulnerabilities"] == 0


def test_assessment_endpoint_only_reads_evidence_and_html_escapes_values(monkeypatch):
    from namazu.audit import transport
    monkeypatch.setattr(transport.Executor, "send", lambda *a, **k: (_ for _ in ()).throw(AssertionError("No replay")))
    payload = saved_audit()
    payload["requests"][50]["response_body"] = '<script>alert("retained text")</script>'
    result = TestClient(app, base_url="http://127.0.0.1").post("/api/audit/assess", json=payload)
    assert result.status_code == 200
    assert result.json()["target_requests_sent"] == 0
    assessment = result.json()
    assessment["coverage_limitations"].append('<script>alert("text")</script>')
    rendered = reporting.render_html(assessment)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_offline_review_redacts_credentials_in_disclosure_and_header_evidence():
    record = {"method": "POST", "url": "http://127.0.0.1/mock", "endpoint": "POST /mock",
              "label": "baseline", "request_headers": {"Authorization": "Bearer very-secret-value"},
              "request_body": '{}', "status": 500,
              "response_headers": {"Content-Type": "application/json", "X-Powered-By": "Framework/1.0 very-secret-value"},
              "response_body": '{"detail":"System.InvalidOperationException: very-secret-value at /app/service.py"}'}
    assessment = reporting.assess_saved_audit({"requests": [record], "findings": []})
    assert "very-secret-value" not in json.dumps(assessment)
    assert assessment["operations"][0]["response_review"]["disclosures"]["distinct_observations"] > 0
    assert assessment["security"]["demonstrated_vulnerabilities"] == 0


def test_audit_redaction_does_not_rewrite_boolean_coverage_metadata():
    from tests.test_denied_campaign_integration import audit
    result, _ = audit(identities={"primary": {"headers": {"Authorization": "Bearer true"}}},
                      request_budget=4)
    headers = {name.lower(): value for name, value in result["baseline"]["request_headers"].items()}
    assert headers["authorization"] == "<credential>"
    assert result["baseline_verdict"]["positive_control"] is False
    assert all(isinstance(row["request_sent"], bool) for row in result["probes"])


def test_portable_artifact_keeps_evidence_pointers_and_redacts_echoes():
    source = saved_audit()
    source["requests"][50]["request_headers"] = {"Authorization": "Bearer portable-secret"}
    source["requests"][50]["response_body"] = '{"detail":"portable-secret"}'
    source["coverage"]["results"] = {"old_incorrect_count": 99}
    assessment = reporting.assess_saved_audit(source)
    assessment["field_results"] = {"summary": {"sameDenialCases": 39}}
    report = reporting.portable_evidence(assessment, source)
    assert "portable-secret" not in json.dumps(report)
    assert report["coverage"]["results"] == assessment["field_results"]
    assert "old_incorrect_count" not in json.dumps(report)
    assert len(report["requests"]) == len(source["requests"])
    assert 'id="request-50"' in reporting.render_html(report)
    assert 'href="#request-50"' in reporting.render_html(report)
