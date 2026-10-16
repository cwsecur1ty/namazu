"""Offline response-contract and disclosure review, including denied baselines."""
import copy
import json
from pathlib import Path

import httpx

from namazu.audit import contract, disclosure
from namazu.audit.engine import audit_operation
from namazu.audit.model import Exchange
from namazu.spec import parse_spec

BASE = "http://127.0.0.1"


def spec_document():
    return {"openapi": "3.0.3", "info": {"title": "local fixture", "version": "1"},
            "servers": [{"url": BASE}], "paths": {"/mock": {"post": {
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object", "required": ["documentUri"],
                    "properties": {"documentUri": {"type": "string", "example": "example-document"}}}}}},
                "responses": {"200": {"description": "ok", "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Summary"}}}},
                    "403": {"description": "denied", "content": {"application/json": {"schema": {"type": "object"}}}}}}}},
            "components": {"schemas": {"Summary": {"type": "object", "required": ["summary"],
                "properties": {"summary": {"type": "string"}, "example": {"type": "boolean"}}}}}}


def saved_contract():
    spec = parse_spec(spec_document())
    return contract.snapshot(spec, spec["operations"][0], request_url=BASE + "/mock")


def exchange(status=403, body='{"detail":"denied"}', media="application/json", **kwargs):
    return Exchange(label="local fixture", method="POST", url=BASE + "/mock", status=status,
                    body=body, headers={"content-type": media}, **kwargs)


def test_all_responses_are_reviewed_and_repeated_contract_defects_aggregate():
    rows = [exchange(), exchange(400, '{"errors":{"documentUri":["required"]}}', "application/problem+json"),
            exchange(400, '{"errors":{"documentUri":["required"]}}', "application/problem+json"),
            exchange(200, '{"summary":12}')]
    result = contract.review_exchanges(saved_contract(), rows, "POST /mock")
    assert result["request_attempts"] == result["responses_received"] == 4
    assert result["contract"]["reviewed_responses"] == 4
    assert result["contract"]["mismatch_occurrences"] == 3
    assert len(result["contract"]["findings"]) == 1
    found = result["contract"]["findings"][0]
    assert found["assessment"]["category"] == "contract"
    assert found["assessment"]["verification"] == "observed"
    assert found["severity"] == "info"
    issues = found["evidence"]["mismatches"]
    assert {item["kind"] for item in issues} == {"undocumented-status", "undocumented-media-type", "response-schema-violation"}
    assert issues[0]["occurrence_count"] == 2
    assert [ref["pointer"] for ref in issues[0]["occurrences"]] == ["/log/1", "/log/2"]
    assert all(item["proof"] for item in result["findings"])


def test_explicit_edge_blocks_and_timeouts_do_not_become_application_defects():
    block = '<html><iframe src="/_Incapsula_Resource"></iframe>Incapsula incident ID: test</html>'
    rows = [exchange(), exchange(403, block, "text/html"), exchange(0, "", error="ReadTimeout")]
    result = contract.review_exchanges(saved_contract(), rows, "POST /mock")
    assert result["request_attempts"] == 3
    assert result["responses_received"] == 2
    assert result["application_responses"] == 1
    assert result["edge_responses"] == result["incomplete_tests"] == 1
    assert result["contract"]["reviewed_responses"] == 1
    assert not result["findings"]
    assert "downstream handling is unknown" in result["contract"]["exchanges"][1]["reason"]


def test_plain_html_403_without_block_markers_remains_application_evidence():
    result = contract.review_exchanges(saved_contract(), [exchange(403, "<html>Forbidden</html>", "text/html")], "POST /mock")
    assert result["edge_responses"] == 0
    assert result["contract"]["mismatch_occurrences"] == 1


def test_missing_contract_is_visible_and_saved_input_is_not_modified():
    row = exchange(400, '{"errors":{"documentUri":["required"]}}').to_dict()
    payload = {"requests": [{**row, "endpoint": "POST /mock", "seqGlobal": 51}]}
    before = copy.deepcopy(payload)
    result = contract.review_saved_audit(payload)
    review = result["operations"][0]["response_review"]
    assert review["contract"]["state"] == "unavailable"
    assert review["contract"]["missing_prerequisites"]
    assert review["disclosures"]["ordinary_validation_responses"] == 1
    assert review["contract"]["exchanges"][0]["evidence_ref"]["pointer"] == "/requests/0"
    assert payload == before


def test_response_only_snapshot_resolves_schema_references_without_request_examples():
    saved = saved_contract()
    assert "requestBody" not in saved["operation"]
    assert "example-document" not in json.dumps(saved)
    assert saved["document"]["components"]["schemas"]["Summary"]["properties"]["example"] == {"type": "boolean"}
    good = contract.review_exchanges(saved, [exchange(200, '{"summary":"done","example":true}')], "POST /mock")
    assert not good["findings"]
    bad = contract.review_exchanges(saved, [exchange(200, '{"summary":"done","example":12}')], "POST /mock")
    assert bad["contract"]["mismatch_occurrences"] == 1


def test_remote_schema_references_are_never_fetched_during_offline_review(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline response review must never create target traffic")

    monkeypatch.setattr(httpx.Client, "send", forbidden)
    import socket
    monkeypatch.setattr(socket, "create_connection", forbidden)
    document = spec_document()
    document["components"]["schemas"]["Summary"] = {"$ref": "https://invalid.example.test/schema.json"}
    parsed = parse_spec(document)
    saved = contract.snapshot(parsed, parsed["operations"][0], request_url=BASE + "/mock")
    assert saved["warnings"]
    result = contract.review_exchanges(saved, [exchange(200, '{"summary":"done"}')], "POST /mock")
    assert result["contract"]["exchanges"][0]["state"] == "incomplete"
    assert result["contract"]["exchanges"][0]["warnings"]


def test_edge_page_diagnostic_text_is_not_reported_as_application_disclosure():
    body = '<html>Incapsula incident ID: test <iframe src="/_Incapsula_Resource"></iframe>System.Exception at /app/example.py</html>'
    result = contract.review_exchanges(saved_contract(), [exchange(403, body, "text/html")], "POST /mock")
    assert not result["findings"]
    assert result["disclosures"]["edge_responses_excluded"] == 1


def test_method_probe_does_not_apply_the_post_response_contract():
    options = exchange(405)
    options.method = "OPTIONS"
    result = contract.review_exchanges(saved_contract(), [exchange(), options], "POST /mock")
    assert result["contract"]["reviewed_responses"] == 1
    assert result["contract"]["state"] == "partial"
    assert result["contract"]["exchanges"][1]["reason_code"] == "operation-contract-unmatched"
    assert not result["contract"]["findings"]


def test_route_matching_keeps_path_parameter_mutations_but_excludes_other_routes():
    saved = saved_contract()
    saved["operation"].update(path="/reports/{id}", method="GET")
    saved["request_path"] = "/api/reports/one"
    rows = [Exchange(label="resource change", method="GET", url=BASE + "/api/reports/two", status=403),
            Exchange(label="different route", method="GET", url=BASE + "/api/admin/two", status=403)]
    result = contract.review_exchanges(saved, rows, "GET /reports/{id}")
    assert result["contract"]["reviewed_responses"] == 1


def test_ordinary_validation_and_primitive_type_names_are_not_disclosures():
    body = {"type": "https://tools.ietf.org/html/rfc9110#section-15.5.1", "title": "Validation errors",
            "errors": {"$.regenerate": ["The JSON value could not be converted to System.Boolean. Path: $.regenerate | LineNumber: 0 | BytePositionInLine: 105."]},
            "traceId": "not-a-leak", "correlationId": "not-a-leak"}
    result = disclosure.review_exchanges([exchange(400, json.dumps(body))], "POST /mock")
    assert result["ordinary_validation_responses"] == 1
    assert not result["observations"]


def test_explicit_limited_detail_is_deduplicated_informational_and_redacted():
    body = json.dumps({"detail": "System.InvalidOperationException from backend: backend.example.invalid; password=secret-value"})
    rows = [exchange(400, body, request_headers={"Authorization": "Bearer secret-value"}) for _ in range(3)]
    result = disclosure.review_exchanges(rows, "POST /mock")
    assert len(result["observations"]) == 2
    assert "secret-value" not in json.dumps(result)
    for item in result["observations"]:
        assert item["severity"] == "info"
        assert item["assessment"]["category"] == "informational"
        assert item["assessment"]["verification"] == "observed"
        assert item["evidence"]["occurrence_count"] == 3
        assert len(item["evidence"]["occurrences"]) == 3
        assert "private" not in item["detail"].lower()
        assert "internal" not in item["detail"].lower()
        assert "unknown" in item["limitations"]


def test_stack_traces_paths_and_headers_are_restained_observations():
    row = exchange(500, 'Traceback (most recent call last):\n File "/app/main.py", line 20', "text/plain")
    row.headers["server"] = "sample/1.2.3"
    result = disclosure.review_exchanges([row], "POST /mock")
    levels = {item["evidence"]["disclosure_level"] for item in result["observations"]}
    assert levels == {"potentially-sensitive", "limited-implementation-detail"}
    assert all(item["severity"] == "info" for item in result["observations"])


def test_truncated_body_still_allows_status_and_media_type_review():
    row = exchange(403, "<html>partial", "text/html", truncated=True)
    result = contract.review_exchanges(saved_contract(), [row], "POST /mock")
    assert result["contract"]["mismatch_occurrences"] == 1
    issue = result["contract"]["findings"][0]["evidence"]["mismatches"][0]
    assert issue["kind"] == "undocumented-media-type"
    assert result["contract"]["exchanges"][0]["warnings"]


def test_redacted_full_body_is_not_mistaken_for_a_truncated_excerpt():
    row = exchange(200, '{"summary":"<credential>"}').to_dict()
    row["body_length"] = 1000  # Original credential was longer than its replacement.
    result = contract.review_exchanges(saved_contract(), [row], "POST /mock")
    assert result["contract"]["exchanges"][0]["state"] == "reviewed"


def test_documentation_links_and_same_request_hostname_are_not_disclosures():
    row = exchange(400, json.dumps({
        "detail": "Read https://help.example.test/api/errors for details",
        "documentation": "https://service.example.test/docs/errors",
        "instance": "POST " + BASE + "/mock", "errors": {"DocumentUri": ["required"]}}))
    assert not disclosure.review_exchanges([row], "POST /mock")["observations"]


def test_saved_export_retains_the_existing_counts_without_target_traffic():
    saved = json.loads((Path(__file__).parent / "fixtures/response_classification_export.json").read_text(encoding="utf-8"))
    result = contract.review_saved_audit({"requests": saved["requests"]})
    assert len(result["operations"]) == 1
    reviewed = result["operations"][0]["response_review"]
    assert reviewed["request_attempts"] == 91
    assert reviewed["responses_received"] == 85
    assert reviewed["edge_responses"] == 15
    assert reviewed["incomplete_tests"] == 6
    assert reviewed["disclosures"]["ordinary_validation_responses"] == 28
    assert reviewed["contract"]["state"] == "unavailable"


def test_engine_reviews_mutations_after_a_conforming_denied_baseline():
    def handler(request):
        body = json.loads(request.content or "{}")
        if body.get("documentUri") == "example-document":
            return httpx.Response(403, json={"detail": "denied"})
        return httpx.Response(400, json={"errors": {"documentUri": ["must be a string"]}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_operation(spec_document(), "POST /mock", profile="writes", allow_mutating=True,
                                 request_budget=8, client=client)
    assert result["baseline_status"] == 403
    review = result["response_review"]
    assert review["contract"]["reviewed_responses"] > 1
    assert review["contract"]["mismatch_occurrences"] > 0
    assert len([item for item in result["findings"] if item["id"] == "contract.response-disagreement"]) == 1
    assert result["contract_snapshot"]["operation"]["method"] == "POST"
