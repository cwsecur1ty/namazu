"""An inapplicable probe is not an instruction to repair credentials or invent inputs."""
import copy
from types import SimpleNamespace

from namazu.audit import probes, reporting
from namazu.audit.model import Exchange
from tests.test_assessment_view import render_script


def receipts_fixture():
    executor = SimpleNamespace(exchanges=[], probe_results=[])
    baseline = Exchange(label="baseline", method="POST", url="http://127.0.0.1/mock", status=403,
                        body='{"detail":"Not entitled"}')
    probes.run(executor, "pagination-bound", lambda: [], family="posture", baseline=baseline,
               endpoint="POST /mock", missing=["GET method", "pagination input", "successful-positive-control"],
               applicable=False)
    probes.run(executor, "bounded-rate-observation", lambda: [], family="posture", baseline=baseline,
               endpoint="POST /mock", missing=["read-only-method", "successful-positive-control"])
    probes.run(executor, "url-fetch-error", lambda: [], family="body-injection", baseline=baseline,
               endpoint="POST /mock", missing=["URL-like input"], applicable=False)
    probes.run(executor, "sql-boolean", lambda: [], family="body-injection", baseline=baseline,
               endpoint="POST /mock", missing=["numeric seed value", "successful-positive-control"], applicable=False)
    probes.run(executor, "cross-identity-write", lambda: [], family="write-authorization", baseline=baseline,
               endpoint="POST /mock", missing=["second-identity", "successful-positive-control"])
    checks = []
    for family in {row["family"] for row in executor.probe_results}:
        checks.append({"check": family, "state": "blocked", "blocked_on": ["POST /mock"],
                       "missing_prerequisites": sorted({reason for row in executor.probe_results if row["family"] == family
                                                        for reason in row["missing_prerequisites"]})})
    return {"findings": [], "requests": [], "coverage": {"probes": executor.probe_results, "checks": checks,
            "baselines": [{"endpoint": "POST /mock", "status": 403, "positive_control": False,
                           "exchange": baseline.to_dict()}]}}


def test_actual_mock_probe_receipts_separate_non_applicability_from_missing_setup():
    payload = receipts_fixture()
    before = copy.deepcopy(payload)
    result = reporting.assess_saved_audit(payload)
    assert payload == before
    assert {"GET method", "read-only-method", "pagination input", "URL-like input", "numeric seed value"}.isdisjoint(result["missing_prerequisites"])
    assert {"second-identity", "successful-positive-control", "distinct-second-identity"} <= set(result["missing_prerequisites"])
    assert len(result["not_applicable"]) == 4
    assert not result["applicability_unknown"]
    assert result["not_applicable"][0]["recorded_prerequisites"] == payload["coverage"]["probes"][0]["missing_prerequisites"]
    assert all(row["evidence_ref"].startswith("#/coverage/probes/") for row in result["not_applicable"])
    assert result["target_requests_sent"] == 0


def test_same_requirement_still_blocks_another_applicable_probe():
    payload = receipts_fixture()
    payload["coverage"]["probes"].append({"family": "body-injection", "check": "numeric-control",
        "operation": "POST /mock", "status": "blocked-prerequisite", "missing_prerequisites": ["numeric seed value"]})
    result = reporting.assess_saved_audit(payload)
    assert "numeric seed value" in result["missing_prerequisites"]
    assert len(result["not_applicable"]) == 4


def test_legacy_post_method_requirement_is_not_identity_setup_even_without_probe_receipts():
    payload = receipts_fixture()
    payload["coverage"]["probes"] = []
    payload["coverage"]["checks"] = [{"check": "posture", "state": "blocked", "blocked_on": ["POST /mock"],
        "missing_prerequisites": ["GET method", "read-only-method", "pagination input", "JWT credential"]}]
    result = reporting.assess_saved_audit(payload)
    assert "GET method" not in result["missing_prerequisites"]
    assert "read-only-method" not in result["missing_prerequisites"]
    assert {row["recorded_prerequisites"][0] for row in result["not_applicable"]} == {"GET method", "read-only-method"}
    assert {row["recorded_prerequisites"][0] for row in result["applicability_unknown"]} == {"pagination input", "JWT credential"}
    assert all("does not identify an applicable probe" in row["detail"] for row in result["applicability_unknown"])


def test_unknown_or_mixed_operation_methods_are_not_assumed_inapplicable():
    payload = {"findings": [], "coverage": {"checks": [{"check": "posture", "state": "blocked",
        "blocked_on": ["GET /first", "POST /second"], "missing_prerequisites": ["GET method"]}]}}
    result = reporting.assess_saved_audit(payload)
    assert not result["not_applicable"]
    assert result["applicability_unknown"][0]["recorded_prerequisites"] == ["GET method"]


def test_known_applicable_jwt_credential_requirement_remains_actionable():
    payload = {"findings": [], "coverage": {"probes": [{"family": "jwt", "check": "jwt-replay", "operation": "GET /reports",
        "status": "blocked-prerequisite", "missing_prerequisites": ["JWT credential"]}],
        "checks": [{"check": "jwt", "state": "blocked", "missing_prerequisites": ["JWT credential"]}]}}
    result = reporting.assess_saved_audit(payload)
    assert "JWT credential" in result["missing_prerequisites"]
    assert not result["not_applicable"] and not result["applicability_unknown"]


def test_assessment_view_separates_non_applicability_and_keeps_receipts_accessible():
    payload = receipts_fixture()
    assessment = reporting.assess_saved_audit(payload)
    result = render_script("""
const view = NamazuAssessmentView.render(audit);
const missing = byTag(view,'section').find(item=>item.textContent.startsWith('Missing prerequisites'));
const nonApplicable = byTag(view,'details').find(item=>item.textContent.startsWith('Does not apply to the recorded'));
const links = byTag(nonApplicable,'a'); links[0].fire('click');
process.stdout.write(JSON.stringify({missing:missing.textContent,nonApplicable:nonApplicable.textContent,
 opened:byClass(view,'case-evidence').some(item=>item.open && item.textContent.includes('pagination-bound'))}));
""", {"assessment": assessment, "probes": payload["coverage"]["probes"], "log": [], "findings": []})
    assert "GET method" not in result["missing"]
    assert "GET method" in result["nonApplicable"]
    assert "not instructions to change credentials" in result["nonApplicable"]
    assert result["opened"]
    report = reporting.render_html(assessment)
    assert "Does not apply to the recorded operation or input" in report
    assert "#/coverage/probes/0" in report
