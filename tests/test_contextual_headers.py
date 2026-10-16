"""Header values are contextual observations, not a browser exploitation oracle."""
import json
from pathlib import Path

import pytest

from namazu.audit import passive, posture
from namazu.audit.model import Exchange


def response(*, content_type="application/json", headers=None, request_headers=None,
             body='{"message":"ok"}', status=200, error="", url="https://api.example.test/mock"):
    return Exchange("local fixture", "POST", url, request_headers=request_headers or {},
                    status=status, headers={"content-type": content_type, **(headers or {})},
                    body=body, error=error)


def ids(findings):
    return {item.id for item in findings}


@pytest.mark.parametrize("media", ["application/json", "application/problem+json", "application/octet-stream"])
def test_no_blanket_browser_or_cache_warnings_for_api_responses(media):
    exchange = response(content_type=media, request_headers={"Authorization": "Bearer fixture"})
    observations = passive.review_headers(exchange, endpoint="POST /mock")
    assert ids(observations).isdisjoint({"transport.no-hsts", "transport.no-nosniff",
                                      "transport.cacheable-private"})
    assert posture.framing_controls(exchange, "POST /mock") == []


def test_html_missing_controls_are_qualified_hardening_not_clickjacking_proof():
    exchange = response(content_type="text/html", body="<html>Error</html>", status=403)
    observations = passive.review_headers(exchange, endpoint="POST /mock")
    assert {"transport.no-hsts", "transport.no-nosniff"} <= ids(observations)
    frame = posture.framing_controls(exchange, "POST /mock")[0]
    assert frame.category == "hardening"
    assert frame.verification == "observed"
    assert "HTML error page alone" in frame.limitations


@pytest.mark.parametrize("headers", [
    {"x-frame-options": "DENY"},
    {"content-security-policy": "frame-ancestors 'none'"},
    {"x-frame-options": "DENY", "content-security-policy": "frame-ancestors 'none'"},
])
def test_equivalent_framing_controls_share_one_presence_observation(headers):
    exchange = response(content_type="text/html", headers=headers)
    assert posture.framing_controls(exchange, "POST /mock") == []
    recorded = [item for item in passive.review_headers(exchange, endpoint="POST /mock")
                if item.id == "transport.header-observation"]
    assert len(recorded) == 1
    assert recorded[0].category == "informational"
    assert recorded[0].evidence["headers"] == headers
    assert "valid, enforced" in recorded[0].detail


def test_header_presence_does_not_assert_effective_protection():
    exchange = response(content_type="text/html", headers={
        "strict-transport-security": "max-age=0", "x-frame-options": "invalid",
        "content-security-policy-report-only": "frame-ancestors 'none'",
        "x-content-type-options": "anything"})
    item = next(item for item in passive.review_headers(exchange, endpoint="POST /mock")
                if item.id == "transport.header-observation")
    assert item.evidence["headers"]["strict-transport-security"] == "max-age=0"
    assert "correctness were not established" in item.limitations
    assert item.severity == "info"


def test_report_only_csp_is_not_an_enforced_frame_ancestor_declaration():
    exchange = response(content_type="text/html", headers={
        "content-security-policy-report-only": "frame-ancestors 'none'"})
    assert "clickjacking.missing-frame-controls" in ids(posture.framing_controls(exchange, "POST /mock"))


def test_download_is_not_treated_as_browser_document():
    exchange = response(content_type="text/html", headers={"content-disposition": "attachment; filename=page.html"})
    assert passive.review_headers(exchange, endpoint="POST /mock") == []
    assert posture.framing_controls(exchange, "POST /mock") == []


def test_browser_use_can_be_declared_without_inventing_it_from_json():
    exchange = response()
    assert "transport.no-hsts" in ids(passive.review_headers(exchange, endpoint="POST /mock", browser_use=True))
    assert "transport.no-nosniff" not in ids(passive.review_headers(exchange, endpoint="POST /mock", browser_use=True))


def test_explicit_edge_page_is_not_an_application_header_defect():
    fixture = json.loads((Path(__file__).parent / "fixtures" / "response_classification_export.json").read_text())
    entry = fixture["edge_block"]
    exchange = response(content_type="text/html", status=403,
                        body=entry.get("response_body") or entry["body_excerpt"])
    assert passive.header_context(exchange)["response_source"] == "recognised-edge-block"
    assert passive.review_headers(exchange, endpoint="POST /mock") == []
    assert posture.framing_controls(exchange, "POST /mock") == []


@pytest.mark.parametrize("cache,auth,status,expected", [
    ("", True, 200, False), ("max-age=300", True, 200, False),
    ("public, max-age=300", False, 200, False), ("public", True, 403, False),
    ("private, max-age=300", True, 200, False), ("public, no-store", True, 200, False),
    ("public, max-age=300", True, 200, True), ("s-maxage=60", True, 200, True),
])
def test_shared_cache_policy_review_requires_context(cache, auth, status, expected):
    exchange = response(headers={"cache-control": cache}, status=status,
                        request_headers={"Authorization": "Bearer fixture"} if auth else {})
    found = [item for item in passive.review_headers(exchange, endpoint="POST /mock")
             if item.id == "transport.cacheable-private"]
    assert bool(found) is expected
    if found:
        assert found[0].category == "hardening"
        assert "remain untested" in found[0].limitations
        assert "No cross-identity cache access" in found[0].impact


@pytest.mark.parametrize("headers", [
    {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
    {"access-control-allow-origin": "*"},
    {"access-control-allow-private-network": "true"},
])
def test_cors_headers_alone_never_demonstrate_exploitation(headers):
    observations = passive.review_headers(response(headers=headers), endpoint="POST /mock")
    assert any(item.id.startswith("cors.") for item in observations)
    assert all(item.category != "security" and item.verification == "observed" for item in observations)
    assert all(item.severity == "info" for item in observations)


def test_wildcard_credentials_explains_browser_rejection():
    observations = passive.review_headers(response(headers={
        "access-control-allow-origin": "*", "access-control-allow-credentials": "true"}), endpoint="POST /mock")
    item = next(item for item in observations if item.id == "cors.wildcard-with-credentials")
    assert "Browsers do not permit credentialed reads" in item.detail


def test_cookie_values_and_echoed_authentication_are_redacted_from_header_evidence():
    exchange = response(headers={"set-cookie": "session=fixture-cookie-secret; Path=/",
                                "content-security-policy": "report-uri /Bearer-fixture-secret"},
                        request_headers={"Authorization": "Bearer Bearer-fixture-secret"})
    findings = passive.review(exchange, endpoint="POST /mock")
    payload = json.dumps([item.to_dict() for item in findings])
    assert "fixture-cookie-secret" not in payload
    assert "Bearer-fixture-secret" not in payload
    assert "<credential>" in payload
    cookie = next(item for item in findings if item.id == "cookie.weak-flags")
    assert cookie.category == "hardening"
    assert "SameSite defaults" in cookie.limitations


def test_cookie_flag_names_inside_the_value_are_not_treated_as_attributes():
    exchange = response(headers={"set-cookie": "session=httponly-secure-samesite; Path=/"})
    item = next(item for item in passive.review(exchange, endpoint="POST /mock")
                if item.id == "cookie.weak-flags")
    assert set(item.evidence["missing"]) == {"HttpOnly", "Secure", "SameSite"}


def test_reflected_credential_in_cache_header_is_redacted_in_detail_and_evidence():
    exchange = response(headers={"cache-control": 'public, extension="cache-fixture-token"'},
                        request_headers={"Authorization": "Bearer cache-fixture-token"})
    findings = passive.review_headers(exchange, endpoint="POST /mock")
    item = next(item for item in findings if item.id == "transport.cacheable-private")
    assert "cache-fixture-token" not in json.dumps(item.to_dict())
    assert "<credential>" in item.detail
    assert "<credential>" in item.evidence["cache_control"]


def test_timeout_has_no_header_assessment():
    assert passive.review_headers(response(status=0, error="timed out"), endpoint="POST /mock") == []


def test_redirect_header_does_not_prove_credentials_were_forwarded():
    exchange = response(status=302, headers={"location": "http://127.0.0.1/mock"},
                        request_headers={"Authorization": "Bearer fixture-secret"})
    item = posture.downgrade_redirect(exchange, "POST /mock")[0]
    assert item.category == "hardening"
    assert item.verification == "observed"
    assert "redirect was not followed" in item.limitations
