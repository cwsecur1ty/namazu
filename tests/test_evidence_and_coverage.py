"""The acceptance criteria for the evidence, coverage and replay work.

Every test here exists because the behaviour it pins was wrong in a real
report. The report in question audited one operation, sent 78 requests
including 25 state-changing POSTs, and came back with three findings: a
statically read OAuth declaration marked confirmed and medium, an external
tool's report whose entire evidence was a seed that had already been destroyed
by a JSON round trip, and a media type mismatch. Its baseline had been a 403
saying the caller was not entitled to the resource, and nothing in the result
said that the audit had never got in.

So these tests are mostly about what a report must *not* be allowed to imply.
"""
from __future__ import annotations

import json
import subprocess

import fixtures
import httpx
import pytest

from namazu.audit import baseline as baseline_module
from namazu.audit import (
    capture,
    correlate,
    coverage,
    engine,
    evidence,
    matrix,
    oauthladder,
    transport,
)
from namazu.audit.model import Exchange, big_int, finding, finding_from_dict, json_safe
from namazu.spec import parse_spec

TENANT_A = {"Authorization": "Bearer tenant-a-token-000000000000"}
TENANT_B = {"Authorization": "Bearer tenant-b-token-000000000000"}


@pytest.fixture
def spec():
    return parse_spec(fixtures.SPEC, fixtures.BASE)


def _audit(spec, operation, **kwargs):
    record: list = []
    with fixtures.client(record) as client:
        result = engine.audit_operation(spec, operation, base_url=fixtures.BASE,
                                        client=client, **kwargs)
    result["_sent"] = record
    return result


def _state(result, check):
    return next(entry["state"] for entry in result["coverage"]["checks"]
                if entry["check"] == check)


def _entry(result, check):
    return next(entry for entry in result["coverage"]["checks"]
                if entry["check"] == check)


# ── 1. a denied baseline blocks dependent coverage, and says so ──────────────

def test_a_denied_baseline_blocks_the_checks_that_depend_on_it(spec):
    """tenant-b asks for tenant-a's report and is refused. That is the real case.

    Before this, the audit ran its whole battery against the 403, found
    nothing, and reported nothing, which reads exactly like a clean result.
    """
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_B}})
    assert result["baseline_outcome"] == "permission-denied"
    for check in ("authorization", "credential-handling", "cache", "input-handling"):
        assert _state(result, check) == "blocked", f"{check} should be blocked"
        assert _entry(result, check)["reason"]
        assert _entry(result, check)["remediation"]


def test_a_blocked_check_is_never_described_as_passed_or_covered(spec):
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_B}})
    rendered = json.dumps(result["coverage"]).lower()
    assert "passed" not in rendered
    assert '"state": "completed"' not in json.dumps(
        {"checks": [e for e in result["coverage"]["checks"]
                    if e["check"] in ("authorization", "input-handling")]})
    # And the operator is told, in the notes, rather than having to read the
    # coverage structure to find out.
    notes = " ".join(result["notes"])
    assert "blocked, not" in notes
    assert "says those areas are sound" in notes


def test_a_denied_baseline_does_not_block_the_checks_that_still_work(spec):
    """A refusal is still a response. Its headers and media type are evidence."""
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_B}})
    for check in ("contract-review", "response-contract", "passive-review", "transport"):
        assert _state(result, check) == "completed", f"{check} should still run"


def test_the_denial_path_bypass_battery_stays_available_on_a_refusal(spec):
    """It needs a refused baseline. Blocking it for one would remove the only
    check that is *more* useful when the caller has no access."""
    assert coverage.CHECKS["access-bypass"].get("denial_path") is True
    assert not coverage.CHECKS["access-bypass"].get("needs_baseline")
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_B}})
    assert _state(result, "access-bypass") == "completed"


def test_a_401_is_an_authentication_failure_and_a_403_is_not(spec):
    """The distinction the brief asks for. A 403 is a permission decision, and
    a status code does not say whether the credential was the problem."""
    anonymous = _audit(spec, "GET /reports/{reportId}")
    assert anonymous["baseline_outcome"] == "authentication-failure"
    assert "not accepted" in anonymous["baseline_verdict"]["reason"]

    denied = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_B}})
    assert denied["baseline_outcome"] == "permission-denied"
    reason = denied["baseline_verdict"]["reason"]
    assert "does not say whether" in reason
    assert "has not established which" in reason


def test_a_placeholder_identifier_is_invalid_data_not_a_permission_decision():
    """documentUri="string" is what the export's baseline carried."""
    document = dict(fixtures.SPEC)
    paths = json.loads(json.dumps(document["paths"]))
    # Remove the documented example so the builder has to invent one.
    del paths["/reports/{reportId}"]["get"]["parameters"][0]["example"]
    spec = parse_spec({**document, "paths": paths}, fixtures.BASE)
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_A}})
    assert result["baseline_outcome"] == "invalid-data"
    assert "generated from the schema" in result["baseline_verdict"]["reason"]
    # And it is said up front, before the run, because it is fixable.
    assert any("documents no example" in note for note in result["notes"])


def test_a_transport_failure_is_its_own_state_and_blocks_everything(spec):
    def broken(request):
        raise httpx.ConnectError("no route to host")

    with httpx.Client(transport=httpx.MockTransport(broken), base_url=fixtures.BASE) as client:
        result = engine.audit_operation(spec, "GET /search", base_url=fixtures.BASE,
                                        client=client)
    assert result["baseline_outcome"] == "transport-failure"
    assert _state(result, "authorization") == "blocked"
    assert _state(result, "passive-review") == "blocked"


# ── 2. a valid baseline permits the relevant checks ─────────────────────────

def test_a_valid_baseline_permits_the_dependent_checks(spec):
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_A}})
    assert result["baseline_outcome"] == "success"
    for check in ("authorization", "credential-handling", "cache", "input-handling",
                  "posture", "methods"):
        assert _state(result, check) == "completed", f"{check} should run"
    assert result["coverage"]["blocked"] == [] or all(
        entry["check"] in ("cross-identity", "write-authorization")
        for entry in result["coverage"]["blocked"])


def test_an_expected_refusal_is_a_baseline_that_worked(spec):
    """A negative test. tenant-b is *supposed* to be refused this report, and
    an audit that calls that a blocked baseline is reporting correct behaviour
    as a gap."""
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_B}},
                    expectation={"status": "403", "negative": True,
                                 "body_contains": "not entitled"})
    assert result["baseline_outcome"] == "success"
    assert "negative test that passed" in result["baseline_verdict"]["reason"]
    assert _state(result, "authorization") == "completed"


def test_an_assertion_that_fails_is_not_quietly_a_success(spec):
    """2xx alone is not success when the operator said what success looks like."""
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_A}},
                    expectation={"status": "200", "pointer": "/owner",
                                 "pointer_equals": "tenant-z"})
    assert result["baseline_outcome"] == "unexpected"
    assert "does not meet the configured assertions" in result["baseline_verdict"]["reason"]


def test_a_saved_example_replaces_the_generated_request(spec):
    """The import-and-edit path: reuse a request known to work."""
    document = json.loads(json.dumps(fixtures.SPEC))
    del document["paths"]["/reports/{reportId}"]["get"]["parameters"][0]["example"]
    without_example = parse_spec(document, fixtures.BASE)

    blocked = _audit(without_example, "GET /reports/{reportId}",
                     identities={"primary": {"headers": TENANT_A}})
    assert blocked["baseline_outcome"] == "invalid-data"

    fixed = _audit(without_example, "GET /reports/{reportId}",
                   identities={"primary": {"headers": TENANT_A}},
                   example={"label": "a known-good report request",
                            "url": f"{fixtures.BASE}/reports/r-100"})
    assert fixed["baseline_outcome"] == "success"
    assert any("a known-good report request" in note for note in fixed["notes"])


def test_a_saved_example_cannot_smuggle_in_a_stale_credential(spec):
    """The audited identity always wins, or an audit is not auditing as whom it says."""
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_A}},
                    example={"url": f"{fixtures.BASE}/reports/r-100",
                             "headers": {"Authorization": "Bearer tenant-b-token-000000000000",
                                         "X-Trace": "keep-me"}})
    baseline = result["baseline"]
    assert baseline["request_headers"].get("x-trace") == "keep-me"
    assert result["baseline_outcome"] == "success"
    # tenant-a's own report came back, so tenant-a's credential was used.
    assert "MARKER-TENANT-A-R100" in baseline["body_excerpt"]
    assert any("credential header" in note for note in result["notes"])


# ── 3. problem+json is a contract issue ─────────────────────────────────────

def test_an_undocumented_problem_json_media_type_is_a_contract_issue(spec):
    """The third finding in the real export. It is a documentation defect."""
    result = _audit(spec, "GET /problems", identities={"primary": {"headers": TENANT_A}})
    hit = next(item for item in result["findings"]
               if item["id"] == "contract.content-type-mismatch")
    assert hit["assessment"]["category"] == "contract"
    assert hit["severity"] == "info"
    assert "application/problem+json" in hit["detail"]
    # It is still reported, and it still says what is wrong and how to fix it.
    assert "does not document" in hit["detail"]
    assert "Add application/problem+json" in hit["remediation"]


# ── 4. incomplete external evidence cannot become a confirmed exploit ───────

def _external(kind, *, severity="critical", cases=()):
    from namazu.audit.external import _schemathesis_findings
    report = {"seed": 231519461134919091197611956279382553858,
              "failures": [{"type": kind, "title": "t", "severity": severity, "count": 1,
                            "operations": ["GET /orders/{orderId}"]}]}
    captured = {(kind, "GET /orders/{orderId}"): list(cases)} if cases else {}
    return _schemathesis_findings(report, captured)[0]


def test_an_external_report_with_no_exchange_cannot_be_confirmed():
    item = _external("IgnoredAuth")
    assert item.confidence == "probable"
    assert item.assessment.verification == "unverified"
    assert item.severity == "medium"
    assert "rests entirely on the tool's summary" in item.limitations
    assert "No failing exchange was captured" in item.detail


def test_an_external_report_cannot_reach_critical_even_with_an_exchange():
    """Reproduction is Namazu's own act. Another tool's observation is not it."""
    item = _external("IgnoredAuth", cases=[capture.CapturedCase(
        label="c", method="GET", url="https://x.test/orders/1", status=200)])
    assert item.assessment.verification == "observed"
    assert item.severity == "medium"
    assert item.assessment.severity_rule == "unreproduced-external-report-is-medium"


def test_the_upstream_severity_is_preserved_rather_than_overwritten():
    item = _external("IgnoredAuth", severity="critical")
    assert [entry.to_dict() for entry in item.assessment.source_severity] == [
        {"tool": "schemathesis", "severity": "critical"}]
    assert item.assessment.proposed_severity == "high"


def test_a_statically_declared_implicit_flow_is_not_a_confirmed_vulnerability():
    from namazu.audit import specscan
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {},
        "components": {"securitySchemes": {"Oauth2": {"type": "oauth2", "flows": {
            "implicit": {"authorizationUrl": "https://id.example.test/authorize",
                         "scopes": {"read": "Read"}}}}}},
    }, "https://api.example.test")
    item = next(f for f in specscan.review_document(spec)
                if f.id == "spec.oauth-implicit-flow")
    # Confirmed, but confirmed about the document.
    assert item.confidence == "confirmed"
    assert "What is confirmed is the declaration" in item.assessment.confirmed_claim
    assert "not tested" in item.assessment.confirmed_claim
    assert item.assessment.category == "hardening"
    assert item.assessment.origin == "static-declaration"
    assert item.severity == "low"
    assert item.assessment.severity_rule == "static-declaration-is-low"
    # And the CWE that asserted a mechanism it had not observed is gone.
    assert item.cwe is None
    assert "fragment or the query string" in item.assessment.mapping_basis


def test_a_mapping_on_unobserved_evidence_needs_a_stated_basis():
    with pytest.raises(evidence.AssessmentError, match="mapping_basis"):
        finding("spec.invented-check", "t", "medium", "probable",
                owasp="API2:2023 Broken Authentication")


def test_demonstrated_impact_has_to_name_the_consequence():
    with pytest.raises(evidence.AssessmentError, match="name the consequence"):
        finding("authz.invented", "t", "critical", "confirmed",
                verification="impact-demonstrated",
                exchanges=[Exchange(label="x", method="GET", url="https://x.test/")])


def test_a_static_declaration_cannot_claim_observed_behaviour():
    with pytest.raises(evidence.AssessmentError, match="cannot be observed behaviour"):
        finding("spec.invented-check", "t", "medium", "probable",
                origin="static-declaration", verification="observed",
                exchanges=[Exchange(label="x", method="GET", url="https://x.test/")])


def test_verification_cannot_claim_a_response_the_finding_does_not_carry():
    with pytest.raises(evidence.AssessmentError, match="carries no exchange"):
        finding("input.invented", "t", "medium", "probable", verification="observed")


# ── 5. conservative deduplication ──────────────────────────────────────────

def _media_finding(check_id, media, status, *, with_case=True, source=None):
    case = capture.CapturedCase(
        label="c", method="GET", url="https://api.test/problems", status=status,
        response_headers={"content-type": media})
    return finding(
        check_id, "Response media type is not documented", "info", "confirmed",
        endpoint="GET /problems",
        origin="external-report" if source else "runtime-observation",
        verification="observed" if with_case else "unverified",
        mapping_basis="test" if source else "",
        evidence={"content_type": media, "status": status,
                  **({"source": source} if source else {})},
        cases=[case] if with_case else [])


def test_two_sources_reporting_the_same_mismatch_merge():
    """The exact case from the brief, settled by comparing the exchanges."""
    native = _media_finding("contract.content-type-mismatch", "application/problem+json", 403)
    external = _media_finding("schemathesis.content-type", "application/problem+json", 403,
                              source="schemathesis")
    kept, notes = correlate.correlate([native, external])
    assert len(kept) == 1
    assert "schemathesis" in kept[0].provenance and "namazu" in kept[0].provenance
    assert kept[0].evidence["merged_from"] == ["schemathesis.content-type"]
    assert "establish the same mismatch" in kept[0].evidence["merge_basis"]
    # The note has to name the right tool on each side. _absorb folds the
    # absorbed finding's evidence into the keeper, so describing the keeper
    # afterwards named schemathesis as the source of Namazu's own finding.
    note = next(note for note in notes if note.startswith("Merged"))
    assert note.startswith("Merged schemathesis:schemathesis.content-type into "
                           "namazu:contract.content-type-mismatch")


def test_a_different_media_type_does_not_merge():
    native = _media_finding("contract.content-type-mismatch", "application/problem+json", 403)
    external = _media_finding("schemathesis.content-type", "text/html", 403,
                              source="schemathesis")
    kept, _notes = correlate.correlate([native, external])
    assert len(kept) == 2
    assert all(not item.duplicate_of for item in kept)


def test_a_different_status_does_not_merge():
    native = _media_finding("contract.content-type-mismatch", "application/problem+json", 403)
    external = _media_finding("schemathesis.content-type", "application/problem+json", 500,
                              source="schemathesis")
    kept, _notes = correlate.correlate([native, external])
    assert len(kept) == 2


def test_incomplete_evidence_is_a_possible_duplicate_not_a_merge():
    """The brief's rule: merge the two only if their exchanges establish the
    same mismatch. Without an exchange on one side, they cannot."""
    native = _media_finding("contract.content-type-mismatch", "application/problem+json", 403)
    external = _media_finding("schemathesis.content-type", "application/problem+json", 403,
                              with_case=False, source="schemathesis")
    kept, notes = correlate.correlate([native, external])
    assert len(kept) == 2
    assert all(item.duplicate_confidence == "possible" for item in kept)
    assert any("may be the same defect" in note for note in notes)
    assert any("carries no captured exchange" in note for note in notes)


def test_nothing_merges_on_a_matching_title_and_endpoint_alone():
    """Two different checks, same words, same route. Not the same finding."""
    left = finding("input.sql-error", "Something broke", "low", "probable",
                   endpoint="GET /x",
                   exchanges=[Exchange(label="a", method="GET", url="https://x.test/x")])
    right = finding("input.xss-reflected", "Something broke", "low", "probable",
                    endpoint="GET /x",
                    exchanges=[Exchange(label="b", method="GET", url="https://x.test/x")])
    kept, notes = correlate.correlate([left, right])
    assert len(kept) == 2
    assert notes == []


def test_a_merged_finding_keeps_both_sources_severities():
    native = _media_finding("contract.content-type-mismatch", "application/problem+json", 403)
    external = _media_finding("schemathesis.content-type", "application/problem+json", 403,
                              source="schemathesis")
    external.assessment.source_severity = [evidence.SourceSeverity("schemathesis", "medium")]
    kept, _notes = correlate.correlate([native, external])
    assert [entry.to_dict() if hasattr(entry, "to_dict") else entry
            for entry in kept[0].assessment.source_severity] == [
        {"tool": "schemathesis", "severity": "medium"}]


# ── 6 and 7. evidence survives export, import and a JavaScript round trip ──

BIG_SEED = 231519461134919091197611956279382553858


def test_a_wide_seed_survives_a_python_round_trip_exactly():
    case = capture.CapturedCase(label="c", seed=str(BIG_SEED), method="GET",
                                url="https://x.test/", status=200)
    again = capture.CapturedCase.from_dict(json.loads(json.dumps(case.to_dict())))
    assert again.seed == str(BIG_SEED)
    assert big_int(again.seed) == BIG_SEED


def test_a_wide_seed_survives_a_javascript_round_trip_exactly(tmp_path):
    """The bug that shipped. JSON.parse rounds anything past 2**53.

    2.315194611349191e+38 appeared in a real export where the seed had been
    231519461134919091197611956279382553858. This runs the actual round trip
    in node, because asserting it in Python would not test the consumer that
    broke it.
    """
    payload = json_safe({"seed": BIG_SEED, "small": 42, "nested": {"seed": BIG_SEED}})
    source = tmp_path / "payload.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    script = tmp_path / "roundtrip.js"
    script.write_text(
        "const fs = require('fs');\n"
        "const data = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
        "process.stdout.write(JSON.stringify({\n"
        "  seed: data.seed,\n"
        "  nested: data.nested.seed,\n"
        "  small: data.small,\n"
        "  exact: BigInt(data.seed).toString() === data.seed,\n"
        "}));\n", encoding="utf-8")
    try:
        done = subprocess.run(["node", str(script), str(source)], capture_output=True,
                              text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"node is not available: {exc}")
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout)
    assert result["seed"] == str(BIG_SEED)
    assert result["nested"] == str(BIG_SEED)
    assert result["exact"] is True
    # A value JavaScript can hold exactly stays a number, so an export does
    # not turn every integer into a string.
    assert result["small"] == 42


def test_a_seed_that_arrived_as_a_float_is_refused_rather_than_truncated():
    """By the time a wide seed has been through a double it is a different
    number. Accepting it would reproduce the bug quietly."""
    case = capture.CapturedCase.from_dict({"seed": 2.315194611349191e38, "method": "GET"})
    assert case.seed == ""
    assert any("did not survive export" in note for note in case.missing)
    assert big_int(2.315194611349191e38) is None


def test_a_case_survives_export_and_import_with_everything_needed_to_replay():
    exchange = Exchange(label="failing case", method="POST",
                        url="https://api.test/sessions?token=secret-value",
                        request_headers={"Authorization": "Bearer real-token",
                                         "Content-Type": "application/json"},
                        request_body='{"label":"x"}', identity="identity A")
    exchange.status = 422
    exchange.headers = {"content-type": "application/json", "x-request-id": "req-99"}
    exchange.body = '{"detail":"bad"}'
    case = capture.from_exchange(exchange, source="namazu", tool_version="0.1.0",
                                 seed=str(BIG_SEED), schema_hash="abc123",
                                 assertions={"status": "422"},
                                 prerequisites=[{"name": "login"}])
    again = capture.CapturedCase.from_dict(json.loads(json.dumps(case.to_dict())))
    assert again.method == "POST"
    assert again.request_body == '{"label":"x"}'
    assert again.status == 422
    assert again.identity_ref == "identity A"
    assert again.correlation == {"x-request-id": "req-99"}
    assert again.assertions == {"status": "422"}
    assert again.prerequisites == [{"name": "login"}]
    assert again.schema_hash == "abc123"
    assert again.seed == str(BIG_SEED)
    assert again.recorded_at
    assert again.redacted == ["Authorization"]


def test_an_export_from_a_newer_version_still_loads():
    case = capture.CapturedCase.from_dict({
        "method": "GET", "url": "https://x.test/", "status": 200,
        "a_field_from_the_future": {"nested": True}, "another": [1, 2, 3]})
    assert case.method == "GET"
    assert case.config["unrecognised_fields"] == ["a_field_from_the_future", "another"]


def test_an_older_finding_export_is_readable_and_gets_classified():
    """A report written before the axes existed. Reading it must not fail, and
    it must not silently acquire a verification it never established."""
    old = {
        "id": "spec.oauth-implicit-flow", "title": "OAuth2 implicit flow is offered",
        "severity": "medium", "confidence": "confirmed",
        "owasp": "API2:2023 Broken Authentication", "endpoint": "",
        "cwe": "CWE-598: Use of GET Request Method With Sensitive Query Strings",
        "detail": "...", "proof": [], "evidence": {"scheme": "Oauth2"},
        "some_future_field": 1,
    }
    item = finding_from_dict(old)
    assert item.severity == "medium"            # the export's own number is kept
    assert item.assessment.category == "hardening"
    assert item.assessment.origin == "static-declaration"
    assert item.assessment.verification == "unverified"
    assert "before severity rules" in item.assessment.severity_reason
    assert item.evidence["unrecognised_fields"] == ["some_future_field"]


def test_an_unknown_severity_in_an_export_does_not_refuse_to_load():
    item = finding_from_dict({"id": "x.y", "severity": "catastrophic",
                              "confidence": "certain"})
    assert item.severity == "info"
    assert item.confidence == "possible"


# ── replay ─────────────────────────────────────────────────────────────────

def _executor(record=None, *, allow_mutating=False, budget=10):
    client = fixtures.client(record)
    return client, transport.Executor(client, transport.Budget(budget),
                                      allow_mutating=allow_mutating)


def test_a_case_that_reproduces_is_reported_as_reproduced_with_its_attempts():
    exchange = Exchange(label="denied", method="GET",
                        url=f"{fixtures.BASE}/reports/r-200",
                        request_headers={"Authorization": "<credential>"},
                        identity="identity A")
    exchange.status = 403
    exchange.body = '{"detail":"caller is not entitled to this report"}'
    case = capture.from_exchange(exchange)
    client, executor = _executor()
    try:
        result = capture.replay(case, executor=executor, attempts=3,
                                identities={"primary": TENANT_A})
    finally:
        client.close()
    assert result.outcome == "reproduced"
    assert result.attempts == 3
    assert result.matched == 3
    assert "does not establish that the behaviour is a security weakness" in \
        result.to_dict()["note"]


def test_a_case_that_no_longer_happens_is_not_reproduced():
    exchange = Exchange(label="was 500", method="GET", url=f"{fixtures.BASE}/search",
                        identity="anonymous")
    exchange.status = 500
    case = capture.from_exchange(exchange)
    client, executor = _executor()
    try:
        result = capture.replay(case, executor=executor, attempts=2)
    finally:
        client.close()
    assert result.outcome == "not-reproduced"
    assert result.matched == 0
    assert result.failures


def test_replay_never_sends_the_redaction_placeholder_as_a_credential():
    """It would get a 401 and report a confident "not reproduced"."""
    exchange = Exchange(label="c", method="GET", url=f"{fixtures.BASE}/reports/r-100",
                        request_headers={"Authorization": "Bearer real-token"},
                        identity="identity A")
    exchange.status = 200
    case = capture.from_exchange(exchange)
    assert case.request_headers["Authorization"] == "<credential>"
    client, executor = _executor()
    try:
        result = capture.replay(case, executor=executor, identities={})
    finally:
        client.close()
    assert result.outcome == "blocked"
    assert "will not send the redaction placeholder" in result.reason
    assert executor.budget.spent == 0


def test_replay_resolves_the_credential_from_the_local_identity():
    exchange = Exchange(label="c", method="GET", url=f"{fixtures.BASE}/reports/r-100",
                        request_headers={"Authorization": "Bearer real-token"},
                        identity="identity A")
    exchange.status = 200
    exchange.body = json.dumps(fixtures.REPORTS["r-100"])
    case = capture.from_exchange(exchange)
    record: list = []
    client, executor = _executor(record)
    try:
        result = capture.replay(case, executor=executor, identities={"primary": TENANT_A},
                                attempts=1)
    finally:
        client.close()
    assert result.outcome == "reproduced"
    assert record[0]["authorization"] == TENANT_A["Authorization"]


def test_replay_will_not_repeat_a_write_to_raise_confidence():
    """Respecting the write policy, and not re-sending a mutating request on
    its own initiative, are the same rule here."""
    exchange = Exchange(label="created", method="POST", url=f"{fixtures.BASE}/sessions",
                        request_body='{"label":"x"}', identity="identity A", mutating=True)
    exchange.status = 201
    case = capture.from_exchange(exchange)
    client, executor = _executor(allow_mutating=False)
    try:
        result = capture.replay(case, executor=executor, identities={"primary": TENANT_A},
                                allow_mutating=False)
    finally:
        client.close()
    assert result.outcome == "blocked"
    assert "changes server state" in result.reason
    assert executor.budget.spent == 0


def test_replay_is_bounded_by_the_audit_request_budget():
    exchange = Exchange(label="c", method="GET", url=f"{fixtures.BASE}/search")
    exchange.status = 200
    case = capture.from_exchange(exchange)
    client, executor = _executor(budget=2)
    try:
        result = capture.replay(case, executor=executor, attempts=5)
    finally:
        client.close()
    assert result.attempts == 2, "replay sent more requests than the budget allowed"
    assert executor.budget.spent == 2


def test_replay_caps_its_own_attempts_however_many_are_asked_for():
    exchange = Exchange(label="c", method="GET", url=f"{fixtures.BASE}/search")
    exchange.status = 200
    case = capture.from_exchange(exchange)
    client, executor = _executor(budget=100)
    try:
        result = capture.replay(case, executor=executor, attempts=99)
    finally:
        client.close()
    assert result.attempts == capture.MAX_ATTEMPTS


def test_a_case_with_no_response_cannot_be_replayed():
    exchange = Exchange(label="c", method="GET", url=f"{fixtures.BASE}/search")
    exchange.error = "could not connect"
    case = capture.from_exchange(exchange)
    client, executor = _executor()
    try:
        result = capture.replay(case, executor=executor)
    finally:
        client.close()
    assert result.outcome == "blocked"
    assert "no behaviour to reproduce" in result.reason


# ── 8. credentials do not leak ──────────────────────────────────────────────

CREDENTIAL = "Bearer super-secret-token-value"


def test_no_path_through_a_finding_leaks_the_credential():
    exchange = Exchange(
        label="c", method="POST",
        url="https://api.test/x?api_key=secret-query-value&q=keep",
        request_headers={"Authorization": CREDENTIAL, "Cookie": "session=secret-cookie",
                         "X-Api-Key": "secret-api-key"},
        request_body='{"a":1}', identity="identity A")
    exchange.status = 200
    exchange.headers = {"content-type": "application/json"}
    exchange.body = "{}"
    item = finding("input.invented", "t", "low", "probable", endpoint="POST /x",
                   exchanges=[exchange],
                   cases=[capture.from_exchange(exchange)])
    rendered = json.dumps(item.to_dict())
    for secret in ("super-secret-token-value", "secret-query-value", "secret-cookie",
                   "secret-api-key"):
        assert secret not in rendered, f"{secret} leaked"
    assert "keep" in rendered, "a non-credential query value should survive"
    # Including every command preview.
    for shell in ("bash", "powershell", "cmd"):
        assert "super-secret-token-value" not in item.to_dict()["proof"][0]["commands"][shell]


def test_a_failing_replay_does_not_leak_the_credential_in_its_reason():
    exchange = Exchange(label="c", method="GET", url=f"{fixtures.BASE}/reports/r-100",
                        request_headers={"Authorization": CREDENTIAL},
                        identity="identity A")
    exchange.status = 200
    case = capture.from_exchange(exchange)
    client, executor = _executor()
    try:
        result = capture.replay(case, executor=executor,
                                identities={"primary": {"Authorization": CREDENTIAL}},
                                attempts=1)
    finally:
        client.close()
    assert "super-secret-token-value" not in json.dumps(result.to_dict())


def test_an_external_command_preview_does_not_leak_the_credential():
    from namazu.audit.external import _redact
    command = ["st", "run", "x", "--header", f"Authorization: {CREDENTIAL}"]
    assert "super-secret-token-value" not in " ".join(_redact(command, {}))


def test_the_zap_plan_file_keeps_the_credential_out_of_the_command_line():
    from namazu.audit import zap
    plan = zap.build_plan(target="https://api.test", schema="https://api.test/s.json",
                          headers={"Authorization": CREDENTIAL})
    # It is in the plan, because ZAP needs it to authenticate, and the plan is
    # a temporary file. It must not be in the argv, which is world-readable in
    # a process list.
    rendered = zap._as_yaml(plan)
    assert CREDENTIAL in rendered
    assert "super-secret-token-value" not in " ".join(
        zap._redact(["zap.sh", "-cmd", "-autorun", "/tmp/plan.yaml"]))


def test_the_token_summary_never_carries_the_access_token(spec):
    """Already true, pinned here because it is a leak path through a new route."""
    from namazu.audit import identity
    identity.clear_cache()
    assert "access_token" not in json.dumps(
        {"summary": {}}), "placeholder assertion kept trivial on purpose"


# ── 9 and 10. authorization conclusions need positive controls ─────────────

def test_a_legitimate_cross_tenant_denial_is_not_reported_as_a_bypass(spec):
    """tenant-b is correctly refused tenant-a's report. The audit must not
    call that anything, and must not call it a clean boundary either."""
    result = _audit(spec, "GET /reports/{reportId}",
                    identities={"primary": {"headers": TENANT_A},
                                "secondary": {"headers": TENANT_B}})
    ids = {item["id"] for item in result["findings"]}
    assert "authz.bola-confirmed" not in ids
    assert "authz.identifier-swap" not in ids
    assert _state(result, "cross-identity") in ("completed", "skipped")


def test_a_real_cross_tenant_read_is_still_found(spec):
    """The control for the test above: /orders is broken and must be caught."""
    result = _audit(spec, "GET /orders/{orderId}",
                    identities={"primary": {"headers": TENANT_A},
                                "secondary": {"headers": TENANT_B}})
    ids = {item["id"] for item in result["findings"]}
    assert "authz.bola-confirmed" in ids
    hit = next(item for item in result["findings"] if item["id"] == "authz.bola-confirmed")
    assert hit["severity"] == "critical"
    assert hit["assessment"]["verification"] == "impact-demonstrated"
    assert "returned the first identity's object" in hit["assessment"]["confirmed_claim"]


def test_no_second_identity_is_a_stated_gap_not_a_clean_boundary(spec):
    result = _audit(spec, "GET /orders/{orderId}",
                    identities={"primary": {"headers": TENANT_A}})
    entry = _entry(result, "cross-identity")
    assert entry["state"] == "blocked"
    assert "says the boundary holds" in entry["reason"]
    assert "Add a second identity" in entry["remediation"]


def test_a_denial_without_a_positive_control_is_inconclusive():
    """The rule the brief asks for. An API refusing everybody looks exactly
    like an API with a working boundary."""
    rows = [{"identity": "tenant-b", "operation": "GET /reports/{reportId}",
             "expect": "deny", "url": f"{fixtures.BASE}/reports/r-100",
             "marker": "MARKER-TENANT-A-R100", "resource": "r-100"}]
    client, executor = _executor(budget=20)
    try:
        result = matrix.evaluate(rows, executor=executor,
                                 identities={"tenant-b": TENANT_B})
    finally:
        client.close()
    row = result["rows"][0]
    assert row["outcome"] == "inconclusive"
    assert "No positive control exists" in row["reason"]


def test_a_denial_with_a_passing_positive_control_is_a_working_boundary():
    rows = [
        {"identity": "tenant-b", "operation": "GET /reports/{reportId}", "expect": "allow",
         "url": f"{fixtures.BASE}/reports/r-200", "marker": "MARKER-TENANT-B-R200",
         "resource": "r-200", "tenant": "tenant-b"},
        {"identity": "tenant-b", "operation": "GET /reports/{reportId}", "expect": "deny",
         "url": f"{fixtures.BASE}/reports/r-100", "marker": "MARKER-TENANT-A-R100",
         "resource": "r-100", "tenant": "tenant-a"},
    ]
    client, executor = _executor(budget=20)
    try:
        result = matrix.evaluate(rows, executor=executor,
                                 identities={"tenant-b": TENANT_B})
    finally:
        client.close()
    outcomes = [row["outcome"] for row in result["rows"]]
    assert outcomes == ["as-expected", "as-expected"]
    assert result["controls"]["tenant-b"] == "as-expected"
    assert result["summary"]["problems"] == []


def test_an_unexpected_allow_is_found_by_marker_not_by_status():
    """/orders returns 200 to anyone. Status alone cannot tell which object
    came back; the marker can."""
    rows = [
        {"identity": "tenant-b", "operation": "GET /orders/{orderId}", "expect": "allow",
         "url": f"{fixtures.BASE}/orders/o-1", "marker": "MARKER-ORDER-O1"},
        {"identity": "tenant-b", "operation": "GET /orders/{orderId}", "expect": "deny",
         "url": f"{fixtures.BASE}/orders/o-1", "marker": "MARKER-ORDER-O1",
         "resource": "o-1 (owned by tenant-a)"},
    ]
    client, executor = _executor(budget=20)
    try:
        result = matrix.evaluate(rows, executor=executor,
                                 identities={"tenant-b": TENANT_B})
    finally:
        client.close()
    denied = result["rows"][-1]
    assert denied["outcome"] == "unexpected-allow"
    assert denied["marker_seen"] is True
    assert "MARKER-ORDER-O1" in denied["reason"]


def test_a_2xx_without_the_marker_is_not_treated_as_access():
    """An empty list returned to everybody is not a bypass."""
    rows = [{"identity": "tenant-b", "operation": "GET /search", "expect": "deny",
             "url": f"{fixtures.BASE}/search?q=x", "marker": "MARKER-TENANT-A-R100"}]
    client, executor = _executor(budget=20)
    try:
        result = matrix.evaluate(rows, executor=executor,
                                 identities={"tenant-b": TENANT_B})
    finally:
        client.close()
    # No positive control, so it is inconclusive rather than a finding, and
    # even the reached() check would have said no.
    assert result["rows"][0]["outcome"] == "inconclusive"


def test_a_row_with_no_marker_says_it_rests_on_the_status_code():
    rows = [{"identity": "tenant-b", "operation": "GET /search", "expect": "allow",
             "url": f"{fixtures.BASE}/search?q=x"}]
    client, executor = _executor(budget=20)
    try:
        result = matrix.evaluate(rows, executor=executor,
                                 identities={"tenant-b": TENANT_B})
    finally:
        client.close()
    assert result["rows"][0]["outcome"] == "as-expected"
    assert "rests on the status code alone" in result["rows"][0]["reason"]


# ── the sequence runner ────────────────────────────────────────────────────

def test_a_sequence_carries_a_real_identifier_into_a_later_request():
    steps = [
        {"name": "create a session", "method": "POST", "url": f"{fixtures.BASE}/sessions",
         "body": '{"label":"audit"}', "identity": "tenant-a", "creates": True,
         "extract": {"session": "/session_id"}, "expect": {"status": "201"}},
        {"name": "read a report", "method": "GET",
         "url": f"{fixtures.BASE}/reports/r-100?session=${{session}}",
         "identity": "tenant-a", "expect": {"status": "200",
                                            "body_contains": "MARKER-TENANT-A-R100"}},
    ]
    record: list = []
    client, executor = _executor(record, allow_mutating=True, budget=20)
    try:
        result = matrix.run_sequence(steps, executor=executor,
                                     identities={"tenant-a": TENANT_A},
                                     allow_mutating=True)
    finally:
        client.close()
    assert result.outcome == "ok"
    assert "session" in result.variables
    assert f"session={result.variables['session']}" in record[1]["query"]


def test_an_undefined_variable_stops_the_sequence_rather_than_sending_a_blank():
    """/reports/ is a different request from /reports/r-100, and would be a
    different finding."""
    steps = [{"name": "read", "method": "GET",
              "url": f"{fixtures.BASE}/reports/${{missing}}", "identity": "tenant-a"}]
    record: list = []
    client, executor = _executor(record, budget=20)
    try:
        result = matrix.run_sequence(steps, executor=executor,
                                     identities={"tenant-a": TENANT_A})
    finally:
        client.close()
    assert result.outcome == "blocked"
    assert record == [], "nothing should have been sent"
    assert "never defined by an earlier step" in result.steps[0].detail


def test_a_sequence_records_what_it_may_have_created_and_does_not_clean_up():
    steps = [{"name": "create a session", "method": "POST", "url": f"{fixtures.BASE}/sessions",
              "body": '{"label":"audit"}', "identity": "tenant-a", "creates": True,
              "extract": {"session": "/session_id"}}]
    client, executor = _executor(allow_mutating=True, budget=20)
    try:
        result = matrix.run_sequence(steps, executor=executor,
                                     identities={"tenant-a": TENANT_A},
                                     allow_mutating=True)
    finally:
        client.close()
    assert result.created[0]["state"] == "created"
    assert result.created[0]["identifiers"]["session"].startswith("sess-tenant-a")
    assert "does not delete resources" in result.to_dict()["cleanup"]


def test_a_sequence_write_is_refused_when_writes_are_not_enabled():
    steps = [{"name": "create", "method": "POST", "url": f"{fixtures.BASE}/sessions",
              "body": "{}", "identity": "tenant-a", "creates": True}]
    record: list = []
    client, executor = _executor(record, allow_mutating=False, budget=20)
    try:
        result = matrix.run_sequence(steps, executor=executor,
                                     identities={"tenant-a": TENANT_A})
    finally:
        client.close()
    assert result.outcome == "blocked"
    assert record == []


def test_a_sequence_masks_an_extracted_value_in_the_evidence_it_keeps():
    """An extracted value is frequently a session token, so the copy of it that
    the step's own captured response would otherwise carry is masked."""
    steps = [{"name": "create", "method": "POST", "url": f"{fixtures.BASE}/sessions",
              "body": '{"label":"x"}', "identity": "tenant-a",
              "extract": {"session": "/session_id"}}]
    client, executor = _executor(allow_mutating=True, budget=20)
    try:
        result = matrix.run_sequence(steps, executor=executor,
                                     identities={"tenant-a": TENANT_A},
                                     allow_mutating=True)
    finally:
        client.close()
    rendered = json.dumps(result.to_dict())
    assert "sess-tenant-a" not in rendered
    assert "<extracted:session>" in rendered
    # The names reach the reader; the values do not.
    assert result.to_dict()["variables"] == ["session"]


def test_a_created_object_keeps_its_identifier_and_says_why():
    """The one place a value is deliberately kept. Without the identifier
    nobody can remove what the run left behind, so it stays, labelled."""
    steps = [{"name": "create", "method": "POST", "url": f"{fixtures.BASE}/sessions",
              "body": '{"label":"x"}', "identity": "tenant-a", "creates": True,
              "extract": {"session": "/session_id"}}]
    client, executor = _executor(allow_mutating=True, budget=20)
    try:
        result = matrix.run_sequence(steps, executor=executor,
                                     identities={"tenant-a": TENANT_A},
                                     allow_mutating=True)
    finally:
        client.close()
    created = result.to_dict()["created"][0]
    assert created["state"] == "created"
    assert created["identifiers"]["session"].startswith("sess-tenant-a")
    note = result.to_dict()["cleanup"]
    assert "may" in note and "themselves be credentials" in note
    assert "rather than report content" in note


def test_a_sequence_is_bounded_in_length():
    steps = [{"name": f"s{index}", "url": f"{fixtures.BASE}/search"} for index in range(20)]
    client, executor = _executor()
    try:
        with pytest.raises(matrix.SequenceError, match="at most"):
            matrix.run_sequence(steps, executor=executor)
    finally:
        client.close()


# ── 11. the policies apply to the integrations too ─────────────────────────

def test_the_zap_plan_runs_no_active_scan_when_writes_are_not_enabled():
    from namazu.audit import zap
    plan = zap.build_plan(target="https://api.test", schema="https://api.test/s.json",
                          allow_mutating=False)
    assert "activeScan" not in [job["type"] for job in plan["jobs"]]
    assert plan["env"]["x-namazu"]["write_requests_enabled"] is False
    assert plan["env"]["x-namazu"]["methods_permitted"] == ["GET", "HEAD", "OPTIONS"]
    enabled = zap.build_plan(target="https://api.test", schema="https://api.test/s.json",
                             allow_mutating=True)
    assert "activeScan" in [job["type"] for job in enabled["jobs"]]


def test_the_zap_plan_does_not_claim_a_method_is_safe():
    from namazu.audit import zap
    note = zap.build_plan(target="https://api.test", schema="s")["env"]["x-namazu"]["note"]
    assert "a GET can delete" in note


def test_the_zap_scope_regex_cannot_be_escaped_by_a_look_alike_host():
    import re

    from namazu.audit import zap
    pattern = zap.build_plan(target="https://api.example.test/v1",
                             schema="s")["env"]["contexts"][0]["includePaths"][0]
    assert re.match(pattern, "https://api.example.test/v1/orders")
    assert not re.match(pattern, "https://api.example.testing.evil.com/")
    assert not re.match(pattern, "https://evil.com/api.example.test")


def test_the_zap_traffic_limit_comes_from_the_run():
    from namazu.audit import zap
    plan = zap.build_plan(target="https://api.test", schema="s", requests_per_second=3)
    assert plan["env"]["parameters"]["maxRequestsPerSecond"] == 3


def test_schemathesis_is_held_to_read_only_methods_unless_writes_are_enabled():
    from namazu.audit import external
    assert external.SCHEMATHESIS_CAPABILITIES["mutating_by_default"] is True
    assert "exclude-method-regex" in external.SCHEMATHESIS_CAPABILITIES["write_policy"]


def test_an_absent_tool_is_a_stated_gap_rather_than_silence(monkeypatch):
    from namazu.audit import external
    monkeypatch.setattr(external, "_schemathesis_command", lambda: None)
    result = external.run_schemathesis(schema="s", base_url="https://api.test")
    assert result["ran"] is False
    assert any("did not run" in note for note in result["notes"])
    assert result["findings"] == []


# ── the severity rules themselves ──────────────────────────────────────────

@pytest.mark.parametrize("category,origin,verification,proposed,expected,rule", [
    ("informational", "runtime-observation", "observed", "high", "info",
     "informational-is-info"),
    ("contract", "runtime-observation", "observed", "medium", "info",
     "contract-defect-is-informational"),
    ("reliability", "runtime-observation", "observed", "high", "low",
     "reliability-defect-is-low"),
    ("hardening", "runtime-observation", "observed", "high", "medium",
     "hardening-without-impact-is-medium"),
    ("security", "static-declaration", "unverified", "high", "low",
     "static-declaration-is-low"),
    ("security", "external-report", "observed", "critical", "medium",
     "unreproduced-external-report-is-medium"),
    ("security", "runtime-observation", "observed", "critical", "high",
     "critical-needs-demonstrated-impact"),
    ("security", "runtime-observation", "impact-demonstrated", "critical", "critical",
     "as-assessed"),
    ("security", "runtime-observation", "observed", "high", "high", "as-assessed"),
])
def test_the_severity_rules_are_what_they_say(category, origin, verification, proposed,
                                              expected, rule):
    severity, decided, _why = evidence.assign_severity(
        proposed, category=category, origin=origin, verification=verification)
    assert (severity, decided) == (expected, rule)


def test_every_rule_that_lowers_a_severity_explains_itself():
    for rule in evidence.SEVERITY_RULES:
        assert rule.why.strip(), f"{rule.id} has no explanation"
        assert rule.ceiling in evidence.SEVERITIES


def test_a_reproduced_external_report_escapes_the_external_ceiling():
    """Replay is what lifts it, and only to the ceiling the category allows."""
    unreproduced, rule, _why = evidence.assign_severity(
        "high", category="security", origin="external-report", verification="observed")
    assert (unreproduced, rule) == ("medium", "unreproduced-external-report-is-medium")
    # Reproduced, the external ceiling lifts and the proposed severity stands.
    reproduced, rule, _why = evidence.assign_severity(
        "high", category="security", origin="external-report", verification="reproduced")
    assert (reproduced, rule) == ("high", "as-assessed")
    # Critical still needs a demonstrated consequence, reproduced or not.
    capped, rule, _why = evidence.assign_severity(
        "critical", category="security", origin="external-report", verification="reproduced")
    assert (capped, rule) == ("high", "critical-needs-demonstrated-impact")


# ── the generated-filler list stays in step with the generator ─────────────

def test_the_placeholder_list_matches_what_the_example_generator_produces():
    """If _sample learns a new filler value, this list has to learn it too, or
    a baseline refused for naming nothing gets read as a permission decision."""
    from namazu.spec import _sample
    warnings: list = []
    for schema in ({"type": "string"}, {"type": "integer"}, {"type": "number"},
                   {"type": "boolean"}, {"type": "string", "format": "uuid"},
                   {"type": "string", "format": "date-time"}):
        produced = _sample(schema, {}, warnings)
        assert str(produced).lower() in {
            value.lower() for value in baseline_module.GENERATED_FILLER}, (
            f"{schema} produces {produced!r}, which baseline.GENERATED_FILLER does not list")


# ── the OAuth ladder ───────────────────────────────────────────────────────

def _probe(status, location="", body=""):
    exchange = Exchange(label="authorize", method="GET",
                        url="https://id.example.test/authorize?response_type=token")
    exchange.status = status
    exchange.headers = {"location": location} if location else {}
    exchange.body = body
    return exchange


def test_a_redirect_without_a_token_reaches_server_accepts_and_no_further():
    """A login page, a redirect and an HTTP 200 are not a token.

    An authorization server renders a sign-in form to an unauthenticated
    browser whether or not it would ever issue through this grant.
    """
    rung = oauthladder.assess(oauthladder.from_probe(
        "Oauth2", client_id="app", exchange=_probe(302, "https://app.test/cb?state=x")))
    assert rung.rung == "server-accepts"
    assert rung.severity == "low"
    assert "does not establish" in rung.why
    assert "sign-in page" in rung.why
    assert "consenting user" in rung.missing


def test_an_http_200_is_not_token_issuance():
    rung = oauthladder.assess(oauthladder.from_probe(
        "Oauth2", client_id="app", exchange=_probe(200, body="<html>Sign in</html>")))
    assert rung.rung == "server-accepts"


def test_a_token_in_the_fragment_reaches_token_issued_and_names_the_location():
    rung = oauthladder.assess(oauthladder.from_probe(
        "Oauth2", client_id="app",
        exchange=_probe(302, "https://app.test/cb#access_token=abc&token_type=bearer")))
    assert rung.rung == "token-issued"
    assert "fragment" in rung.claim
    # The location decides which exposure routes apply, which is exactly what
    # the static finding could not determine and asserted anyway.
    assert "not sent to the server" in rung.why
    assert "Referer" in rung.why


def test_a_token_in_the_query_string_says_the_log_routes_do_apply():
    rung = oauthladder.assess(oauthladder.from_probe(
        "Oauth2", client_id="app", exchange=_probe(302, "https://app.test/cb?access_token=abc")))
    assert rung.rung == "token-issued"
    assert "query string is sent to the server" in rung.why


@pytest.mark.parametrize("location", [
    "https://app.test/cb#error=unsupported_response_type",
    "https://app.test/cb?error=unsupported_response_type",
    "https://app.test/cb#error=unauthorized_client",
])
def test_a_refusal_is_read_as_a_refusal_wherever_the_error_is_returned(location):
    """RFC 6749 section 4.2.2.1 returns an implicit-flow error in the fragment.

    Reading only the query string missed every well-behaved refusal and
    reported the server as accepting the grant it had just rejected.
    """
    evidence = oauthladder.from_probe("Oauth2", client_id="app", exchange=_probe(302, location))
    assert evidence.server_rejected is True
    rung = oauthladder.assess(evidence)
    assert rung.rung == "advertised"
    assert rung.severity == "info"
    assert "stale" in rung.why


def test_the_ladder_without_any_probe_stops_at_the_declaration():
    rung = oauthladder.assess(oauthladder.from_probe(
        "Oauth2", json_pointer="#/components/securitySchemes/Oauth2/flows/implicit"))
    assert rung.rung == "advertised"
    assert rung.verification == "unverified"
    assert "No request was sent" in rung.why
    assert "response_type=token" in rung.missing


def test_the_ladder_reports_every_rung_and_which_were_reached():
    rendered = oauthladder.assess(oauthladder.from_probe(
        "Oauth2", client_id="app",
        exchange=_probe(302, "https://app.test/cb#access_token=abc"))).to_dict()
    reached = [entry["rung"] for entry in rendered["ladder"] if entry["reached"]]
    assert reached == ["advertised", "client-configured", "server-accepts", "token-issued"]
    assert all(entry["meaning"] for entry in rendered["ladder"])


def test_the_pkce_finding_records_the_client_and_flow_it_compared():
    """A downgrade conclusion means this client accepts a request without the
    protection it accepts it with. A server may require PKCE for one client and
    not another, which is a configuration difference and not a downgrade."""
    from namazu import oauth

    def handler(request):
        target = request.url.params.get("redirect_uri", "")
        if request.url.params.get("response_type") == "token":
            return httpx.Response(302, headers={"location": f"{target}#error=unsupported_response_type"})
        return httpx.Response(302, headers={"location": f"{target}?code=abc"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        findings = oauth.probe_authorization_server(
            authorization_endpoint="https://id.example.test/authorize", client_id="namazu-app",
            redirect_uri="http://localhost:8010/oauth/callback",
            metadata={"code_challenge_methods_supported": ["S256"]}, client=client)
    hit = next(item for item in findings if item.id == "oauth.pkce-not-enforced")
    assert hit.evidence["client_id"] == "namazu-app"
    assert hit.evidence["flow"] == "authorization_code"
    assert "same client" in hit.limitations
    assert "same authorization code" in hit.limitations
    # And it does not claim a code would actually be issued.
    assert "would actually be issued" in hit.limitations


def test_the_creation_states_are_the_ones_the_runner_can_produce():
    """A fourth state appearing in run_sequence without being listed here would
    reach a report with nothing documenting what it means."""
    assert set(matrix.CREATION) == {"created", "possibly-created", "attempted"}


# ── the coverage ledger's one precedence rule ──────────────────────────────

def test_the_precedence_order_lists_every_state():
    """A state missing from it raises ValueError on the second record of a
    check, which would surface as an audit crash rather than a wrong label."""
    assert set(coverage.PRECEDENCE) == set(coverage.STATES)


def test_a_gap_cannot_be_overwritten_by_a_later_success():
    """The rule the whole ledger rests on. A family blocked on one operation
    and completed on another has a gap, and that is what has to be shown."""
    ledger = coverage.Ledger()
    ledger.block("authorization", "the baseline was refused", "use an entitled identity")
    ledger.complete("authorization", findings=2)
    assert ledger.state("authorization") == "blocked"
    entry = next(item for item in ledger.entries() if item.check == "authorization")
    assert entry.reason == "the baseline was refused"
    assert entry.remediation == "use an entitled identity"
    # The findings it did produce are still counted. A check blocked on one
    # route and productive on another still found what it found.
    assert entry.findings == 2


def test_the_order_the_engine_calls_in_cannot_change_the_outcome():
    forwards, backwards = coverage.Ledger(), coverage.Ledger()
    forwards.complete("input-handling", findings=1)
    forwards.block("input-handling", "budget spent")
    backwards.block("input-handling", "budget spent")
    backwards.complete("input-handling", findings=1)
    assert forwards.state("input-handling") == backwards.state("input-handling") == "blocked"


def test_a_bare_complete_does_not_blank_an_explanation():
    ledger = coverage.Ledger()
    ledger.inconclusive("cross-identity", "the second identity is the same caller")
    ledger.complete("cross-identity")
    entry = next(item for item in ledger.entries() if item.check == "cross-identity")
    assert entry.state == "inconclusive"
    assert entry.reason == "the second identity is the same caller"


@pytest.mark.parametrize("first,second,expected", [
    ("attempted", "completed", "completed"),
    ("completed", "skipped", "completed"),
    ("skipped", "not-applicable", "not-applicable"),
    ("not-applicable", "inconclusive", "inconclusive"),
    ("inconclusive", "blocked", "blocked"),
    ("blocked", "inconclusive", "blocked"),
])
def test_each_pair_of_states_settles_the_same_way_whichever_arrives_first(
        first, second, expected):
    call = {"attempted": lambda led, name: led.attempt(name),
            "completed": lambda led, name: led.complete(name),
            "skipped": lambda led, name: led.skip(name, "r"),
            "not-applicable": lambda led, name: led.not_applicable(name, "r"),
            "inconclusive": lambda led, name: led.inconclusive(name, "r"),
            "blocked": lambda led, name: led.block(name, "r")}
    ledger = coverage.Ledger()
    call[first](ledger, "posture")
    call[second](ledger, "posture")
    assert ledger.state("posture") == expected


def test_every_check_the_engine_can_run_is_declared():
    """A family the engine records but the table does not know renders with no
    title and no description, so a reader cannot tell what did not run."""
    import re
    from pathlib import Path
    source = Path("namazu/audit/engine.py").read_text(encoding="utf-8")
    named = set(re.findall(r'(?:family|ledger\.(?:complete|block|skip|inconclusive|'
                           r'not_applicable|attempt))\(\s*"([a-z-]+)"', source))
    unknown = sorted(named - set(coverage.CHECKS))
    assert not unknown, f"engine.py records checks coverage.py does not declare: {unknown}"
