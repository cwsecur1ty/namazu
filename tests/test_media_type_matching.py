"""Which response media types count as the one the contract declared.

The case that prompted this: an operation documenting ``application/json``
returns ``application/problem+json`` for its errors, which is RFC 9457 problem
details and what a well-behaved API does. Those are two different media types,
so the match is not clean. But the body is JSON, the declared schema was
written for JSON, and the old behaviour returned at the media type and never
looked at the body at all. It reported the cosmetic defect and dropped the
substantive one.

So the first test here is the one that matters: a problem+json error body that
violates the declared schema has to be reported as a schema violation. The
rest hold the line in the other direction, because "treat anything JSON-ish as
a match" would quietly accept a response the contract never described.
"""
import httpx
import pytest

from namazu.audit import contract
from namazu.audit.model import Exchange
from namazu.runner import execute_request, review_response
from namazu.spec import parse_spec

BASE = "https://api.example.test"


def _document(declared, status="400"):
    """An operation whose error response declares exactly ``declared``."""
    return {
        "openapi": "3.0.3", "info": {"title": "Shop", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/orders": {"get": {
            "responses": {
                "200": {"description": "Orders", "content": {"application/json": {
                    "schema": {"type": "object"}}}},
                status: {"description": "Problem", "content": {
                    media: {"schema": {
                        "type": "object",
                        "required": ["title", "status"],
                        "properties": {"title": {"type": "string"},
                                       "status": {"type": "integer"}},
                    }} for media in declared}},
            },
        }}},
    }


def _review(declared, *, content_type, body, status=400):
    spec = parse_spec(_document(declared), BASE)
    operation = next(op for op in spec["operations"] if op["id"] == "GET /orders")
    return review_response(spec, operation, status, {"content-type": content_type}, body, False)


PROBLEM = '{"title": "Order not found", "status": 404}'
# Same media type, but "status" is a string where the schema requires an integer.
BROKEN_PROBLEM = '{"title": "Order not found", "status": "404"}'


# ── the finding that used to be lost ────────────────────────────────────────

def test_a_problem_json_body_is_validated_against_the_declared_schema():
    """The point of the change. This body is wrong and has to be reported.

    Before, the media type mismatch returned early: this response was reported
    as an undocumented media type and its body was never checked, so a contract
    violation in an error payload could not be found at all.
    """
    report = _review(["application/json"], content_type="application/problem+json",
                     body=BROKEN_PROBLEM)
    assert report["valid"] is False
    assert any("status" in str(error) for error in report["errors"]), report["errors"]
    assert {entry["name"] for entry in report["checks"]} >= {"Response schema"}


def test_a_well_formed_problem_json_body_is_not_a_failure():
    report = _review(["application/json"], content_type="application/problem+json", body=PROBLEM)
    assert report["valid"] is True
    assert report["errors"] == []


def test_the_undocumented_media_type_is_still_reported_as_a_warning():
    """Softening it must not mean saying nothing: the contract is incomplete."""
    report = _review(["application/json"], content_type="application/problem+json", body=PROBLEM)
    note = " ".join(report["warnings"])
    assert "application/problem+json" in note
    assert "application/json" in note
    # The warning is raised before the schema check runs, and the schema report
    # carries warnings of its own; losing it to the merge is the easy mistake.
    assert report["warnings"], "the warning did not survive schema validation"


def test_the_content_type_check_is_neither_a_pass_nor_a_failure():
    checks = {entry["name"]: entry["valid"] for entry in
              _review(["application/json"], content_type="application/problem+json",
                      body=PROBLEM)["checks"]}
    assert checks["Documented Content-Type"] is None


# ── the line held in the other direction ────────────────────────────────────

def test_an_exactly_declared_media_type_still_passes_cleanly():
    report = _review(["application/problem+json"], content_type="application/problem+json",
                     body=PROBLEM)
    checks = {entry["name"]: entry["valid"] for entry in report["checks"]}
    assert checks["Documented Content-Type"] is True
    assert report["warnings"] == []


def test_an_unrelated_media_type_is_still_an_error():
    report = _review(["application/json"], content_type="text/csv", body="a,b\n1,2")
    assert report["valid"] is False
    assert any(error["path"] == "$.headers.content-type" for error in report["errors"])


def test_a_suffix_matches_nothing_when_no_json_type_is_declared():
    """text/plain is not JSON, so problem+json has nothing to match."""
    report = _review(["text/plain"], content_type="application/problem+json", body=PROBLEM)
    assert report["valid"] is False
    assert any(error["path"] == "$.headers.content-type" for error in report["errors"])


def test_a_missing_content_type_is_still_an_error():
    report = _review(["application/json"], content_type="", body=PROBLEM)
    assert report["valid"] is False
    assert any("(missing)" in error["message"] for error in report["errors"])


@pytest.mark.parametrize("declared,actual", [
    ("application/xml", "application/atom+xml"),
    ("text/xml", "application/problem+xml"),
    ("text/json", "application/problem+json"),
])
def test_the_other_structured_suffixes_match_their_syntax(declared, actual):
    checks = {entry["name"]: entry["valid"] for entry in
              _review([declared], content_type=actual, body=PROBLEM)["checks"]}
    assert checks["Documented Content-Type"] is None


def test_a_json_suffix_does_not_match_a_declared_xml_type():
    """The suffix names a syntax; it does not make every suffix equivalent."""
    report = _review(["application/xml"], content_type="application/problem+json", body=PROBLEM)
    assert report["valid"] is False
    assert any(error["path"] == "$.headers.content-type" for error in report["errors"])


# ── what the audit reports ──────────────────────────────────────────────────

def _baseline(content_type: str, body: str, status: int = 400) -> Exchange:
    exchange = Exchange(label="baseline", method="GET", url=f"{BASE}/orders")
    exchange.status = status
    exchange.headers = {"content-type": content_type}
    exchange.body = body
    return exchange


def _audit(declared, *, content_type, body):
    spec = parse_spec(_document(declared), BASE)
    operation = next(op for op in spec["operations"] if op["id"] == "GET /orders")
    return contract.review(spec, operation, _baseline(content_type, body), "GET /orders")


def test_the_audit_calls_a_suffix_mismatch_information_not_a_defect():
    """The old wording claimed a client would fail to parse it. It would not."""
    hit = next(item for item in _audit(["application/json"],
                                       content_type="application/problem+json", body=PROBLEM)
               if item.id == "contract.content-type-mismatch")
    assert hit.severity == "info"
    assert hit.evidence["match"] == "syntax suffix"
    assert "still validated" in hit.detail


def test_the_audit_still_calls_a_real_mismatch_a_defect():
    hit = next(item for item in _audit(["application/json"], content_type="text/csv", body="a,b")
               if item.id == "contract.content-type-mismatch")
    assert hit.severity == "low"
    assert "match" not in hit.evidence


def test_the_audit_reports_the_schema_violation_behind_a_suffix_mismatch():
    """Both findings, because both are true, and the second one is the useful one."""
    ids = {item.id for item in _audit(["application/json"],
                                      content_type="application/problem+json",
                                      body=BROKEN_PROBLEM)}
    assert "contract.response-schema-violation" in ids
    assert "contract.content-type-mismatch" in ids


def test_a_documented_media_type_produces_no_media_finding():
    ids = {item.id for item in _audit(["application/problem+json"],
                                      content_type="application/problem+json", body=PROBLEM)}
    assert "contract.content-type-mismatch" not in ids


# ── end to end through the runner ───────────────────────────────────────────

def test_the_runner_reports_a_problem_response_as_valid_with_a_warning():
    spec = parse_spec(_document(["application/json"]), BASE)

    def handler(request):
        return httpx.Response(400, content=PROBLEM,
                              headers={"content-type": "application/problem+json"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(spec, "GET /orders", base_url=BASE, client=client)
    assert result["validation"]["valid"] is True
    assert any("application/problem+json" in note for note in result["validation"]["warnings"])
