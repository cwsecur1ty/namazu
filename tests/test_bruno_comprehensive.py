"""Offline regression against pinned, genuinely CLI-produced Bruno evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from namazu.bruno import import_report
from namazu.bruno_collections import export_collection, import_collection

FIXTURES = Path(__file__).parent / "fixtures/bruno/comprehensive"


def document(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def files():
    root = FIXTURES / "collection"
    return [{"path": path.relative_to(root).as_posix(), "content": path.read_text(encoding="utf-8")}
            for path in sorted(root.rglob("*")) if path.suffix == ".bru" or path.name == "bruno.json"]


def imported():
    return import_collection(files(), environment="Local")


def test_real_cli_provenance_and_independent_receipts_match_committed_reports():
    provenance = document("provenance.json")
    assert provenance["cli"] == "@usebruno/cli@4.2.1"
    assert provenance["parser"] == "@usebruno/lang@0.40.0"
    assert provenance["collection_requests"] == 36
    for run in provenance["runs"]:
        report = FIXTURES / run["report"]
        # Hash the line-ending-normalized bytes so the receipt matches on any
        # platform; git may hand back CRLF on a Windows checkout.
        normalized = report.read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(normalized).hexdigest() == run["normalized_output_sha256"]
        results = [row for iteration in document(run["report"]) for row in iteration["results"]]
        receipts = document(run["report"].replace(".json", "-receipts.json"))
        assert len(results) == run["logical_executions"] == 72
        assert len(receipts) == run["mock_network_attempts"] == 72
        assert run["observed_responses"] == 70 and run["no_response_executions"] == 2
        assert {urlsplit(row["request"]["url"]).hostname for row in results} == {"127.0.0.1"}


def test_real_nested_duplicate_names_and_iterations_are_separate_evidence():
    first = import_report(document("report.json"))
    again = import_report(document("report.json"))
    info = first["bruno"]
    assert info["recorded_executions"] == 72
    assert info["observed_responses"] == 70
    assert info["dispatch_unknown"] == 2
    assert info["recorded_iterations"] == 2
    assert info["wire_attempts"] is None
    assert first["scope"]["requests_sent"] is None
    assert first["provenance"]["requests_sent_during_current_action"] == 0
    assert len({row["id"] for row in info["executions"]}) == 72
    duplicates = [row for row in info["executions"] if row["name"] == "Same request"]
    assert len(duplicates) == 6
    assert len({row["filename"] for row in duplicates}) == 3
    assert {row["iteration"] for row in duplicates} == {0, 1}
    assert [row["id"] for row in info["executions"]] == [row["id"] for row in again["bruno"]["executions"]]
    assert first["findings"] == []


def test_assertion_failures_denials_and_missing_bodies_do_not_claim_vulnerabilities():
    report = import_report(document("report.json"))
    counts = report["bruno"]["assertion_counts"]
    assert counts["assertionResults"]["fail"] == 2
    assert counts["testResults"]["fail"] == 2
    assert report["findings"] == []
    omitted = import_report(document("omitted.json"))
    assert omitted["bruno"]["recorded_executions"] == 72
    assert omitted["bruno"]["observed_responses"] == 70
    assert all(row["missing_evidence"] for row in omitted["bruno"]["executions"])
    assert omitted["findings"] == []


def test_real_cli_receipts_capture_inheritance_override_no_auth_and_unicode():
    receipts = document("report-receipts.json")[:36]
    by_query = {row["path"]: row for row in receipts}
    root = by_query["/echo?layer=environment"]
    assert root["headers"]["authorization"] == "Bearer fixture-shared-token"
    assert by_query["/echo?case=override"]["headers"]["authorization"] == "Bearer fixture-request-token"
    assert "authorization" not in by_query["/echo?case=no-auth"]["headers"]
    nested = next(row for row in receipts if "layer=request" in row["path"])
    assert nested["headers"]["authorization"] == "Bearer fixture-folder-token"
    assert parse_qs(urlsplit(nested["path"]).query)["message"] == ["caf\u00e9 \u96ea"]
    assert nested["headers"]["x-override"] == "folder", "Pinned CLI casing behavior is deliberately recorded"
    spaced = next(row for row in receipts if row["path"].startswith("/space"))
    assert unquote(spaced["path"]) == "/space path/caf\u00e9?layer=folder"


@pytest.mark.parametrize("case,expected", [("null", None), ("false", False), ("zero", 0), ("string", "caf\u00e9 \u96ea")])
def test_real_cli_scalar_json_bodies_are_exact_values(case, expected):
    row = next(row for row in document("report-receipts.json") if row["path"] == "/echo?case=" + case)
    assert row["headers"]["content-type"] == "application/json"
    assert row["body_bytes"] > 0
    assert json.loads(row["body"]) == expected


@pytest.mark.parametrize("path,expected", [("/scalar-false", "false"), ("/scalar-zero", "0"), ("/scalar-null", "null")])
def test_scalar_responses_remain_present_and_distinct_from_omitted_evidence(path, expected):
    report = import_report(document("report.json"))
    rows = [row for row in report["requests"] if urlsplit(row["url"]).path == path]
    assert len(rows) == 2
    assert all(row["response_body"] == expected for row in rows)
    assert all("response body" not in row["missing_evidence"] for row in rows)


def test_empty_text_mode_and_official_empty_block_grammar_boundary_are_distinct():
    rows = document("report-receipts.json")
    actual_empty = next(row for row in rows if row["path"] == "/echo?case=empty-text")
    parser_boundary = next(row for row in rows if row["path"] == "/echo?case=empty-text-block")
    assert actual_empty["body"] == "" and actual_empty["body_bytes"] == 0
    assert actual_empty["headers"]["content-type"] == "text/plain"
    assert parser_boundary["body"] == "}\n\nassert {\nres.status: eq 200"
    assert parser_boundary["body_bytes"] == 30


def test_definitions_require_environment_and_preserve_safe_request_semantics():
    selection = import_collection(files())
    assert selection["requires_environment"]
    assert selection["requests_sent"] == 0
    value = imported()
    by_id = {row["id"]: row for row in value["requests"]}
    assert len(by_id) == 36
    assert len([row for row in value["requests"] if row["name"] == "Same request"]) == 3
    assert by_id["03-json-object.bru"]["can_prepare"]
    assert json.loads(by_id["03-json-object.bru"]["request"]["body"])["name"] == "caf\u00e9 \u96ea"
    assert "authorization" not in {key.lower() for key in by_id["01-request-auth-override.bru"]["request"]["headers"]}
    assert by_id["01-request-auth-override.bru"]["authentication"]
    assert by_id["02-no-auth.bru"]["authentication"] == []
    assert "disabled=collection-value" in by_id["23-disabled-variable.bru"]["request"]["url"]
    assert "fixture-opaque-auth-value" not in json.dumps(value)
    for name in ["19-unresolved-query.bru", "20-inert-script.bru", "21-graphql.bru", "28-owned-file.bru", "29-owned-multipart.bru"]:
        assert not by_id[name]["can_prepare"] and by_id[name]["blockers"]
    # A folder upload does not give permission to read referenced local files.
    assert "Owned synthetic local upload" not in json.dumps(value)


def test_safe_body_exports_roundtrip_without_becoming_scripts_or_losing_scalars():
    rows = {row["id"]: row for row in imported()["requests"]}
    names = ["03-json-object.bru", "04-json-null.bru", "05-json-false.bru", "06-json-zero.bru", "07-json-string.bru", "22-json-escapes.bru"]
    original = [rows[name]["request"] for name in names]
    exported = export_collection(original)
    restored = import_collection(exported["files"], environment="Local")
    assert len(restored["requests"]) == len(names)
    for old, new in zip(original, restored["requests"], strict=True):
        assert new["request"]["method"] == old["method"]
        assert new["request"]["url"] == old["url"]
        assert json.loads(new["request"]["body"]) == json.loads(old["body"])
        assert new["can_prepare"]


def test_negative_inputs_remain_explicit_errors():
    with pytest.raises(ValueError):
        import_report(document("negative/unsupported-report.json"))
    with pytest.raises(ValueError):
        import_collection([{"path": "malformed.bru", "content": (FIXTURES / "negative/malformed.bru").read_text(encoding="utf-8")}])
