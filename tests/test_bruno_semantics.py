"""Pinned official CLI fixtures plus adversarial offline interoperability cases."""
from __future__ import annotations

import copy
import json
import socket
from pathlib import Path

import httpx
import pytest

from namazu.bruno import import_report, sanitise
from namazu.bruno_collections import export_collection, import_collection

ROOT = Path(__file__).parent / "fixtures/bruno/comprehensive"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("Bruno import/export must remain offline")
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", denied)


def files():
    root = ROOT / "collection"
    return [{"path": path.relative_to(root).as_posix(), "content": path.read_text(encoding="utf-8")}
            for path in root.rglob("*") if path.suffix == ".bru" or path.name == "bruno.json"]


@pytest.fixture(scope="module")
def collection():
    return import_collection(files(), environment="Local")


def by_path(collection):
    return {row["id"]: row for row in collection["requests"]}


def test_sanitisation_is_idempotent_for_persisted_request_definitions(collection):
    once = sanitise(collection["requests"])
    assert sanitise(once) == once
    assert once[0]["authentication_mode"] == collection["requests"][0]["authentication_mode"]
    assert once[0]["authentication"] == collection["requests"][0]["authentication"]
    collision = {"authentication_mode": "bearer", "authentication": [{"header": "Authorization", "scheme": "bearer"}],
                 "request": {"body": {"scheme": "bearer", "echo": "bearer"}}}
    safe = sanitise(collision, extra_secrets=["bearer"])
    assert safe["authentication_mode"] == safe["authentication"][0]["scheme"] == "bearer"
    assert safe["request"]["body"] == {"scheme": "<credential>", "echo": "<credential>"}


def test_official_cli_generated_fixture_provenance_and_definition_identity(collection):
    provenance = json.loads((ROOT / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["cli"] == "@usebruno/cli@4.2.1" and provenance["parser"] == "@usebruno/lang@0.40.0"
    assert collection["format"] == "bruno-request-definitions" and collection["format_version"] == 1
    assert not collection["response_contract"] and collection["requests_sent"] == 0
    assert len(collection["requests"]) == len({row["id"] for row in collection["requests"]}) == 36
    same = [row for row in collection["requests"] if row["name"] == "Same request"]
    assert len(same) == 3 and len({row["folder"] for row in same}) == 3
    assert all(row["source_ref"] == row["id"] and row["definition"]["meta"]["name"] == row["name"] for row in same)


def test_pinned_auth_and_case_variant_header_precedence_matches_real_receipts(collection):
    rows = by_path(collection)
    inherited = rows["Other folder/Same request.bru"]
    nested = rows["Nested folder/Same request.bru"]
    receipts = json.loads((ROOT / "report-receipts.json").read_text(encoding="utf-8"))
    captured = next(row for row in receipts if row["path"].startswith("/echo?layer=request"))
    assert captured["headers"]["x-override"] == nested["request"]["headers"]["x-override"] == "folder"
    assert any("Case-variant" in warning for warning in nested["warnings"])
    assert inherited["authentication_mode"] == "bearer"
    assert rows["02-no-auth.bru"]["authentication_mode"] == "none"
    assert rows["01-request-auth-override.bru"]["authentication_mode"] == "bearer"
    assert all("authorization" not in {name.lower() for name in row["request"]["headers"]} for row in rows.values())
    assert nested["request"]["headers"]["X-Collection"] == "inherited"


def test_effective_variables_and_opaque_auth_references_remain_secret_free(collection):
    rows = by_path(collection)
    assert rows["Nested folder/Same request.bru"]["variables"]["layer"] == "request"
    assert rows["Other folder/Same request.bru"]["variables"]["layer"] == "environment"
    assert rows["23-disabled-variable.bru"]["variables"]["disabledFallback"] == "collection-value"
    serialized = json.dumps(collection, ensure_ascii=False)
    for secret in ("fixture-shared-token", "fixture-folder-token", "fixture-request-token", "fixture-opaque-auth-value"):
        assert secret not in serialized
    opaque = rows["24-opaque-auth-reference.bru"]
    assert opaque["variables"]["opaque"] == "<credential>"
    assert "opaque" in opaque["authentication"][0]["variables"]
    assert opaque["can_prepare"]


def test_scalar_empty_body_and_content_type_semantics_are_distinct(collection):
    rows = by_path(collection)
    for name, body in (("04-json-null.bru", "null"), ("05-json-false.bru", "false"), ("06-json-zero.bru", "0")):
        request = rows[name]["request"]
        assert request["body"] == body and request["has_body"] and request["body_mode"] == "json"
        assert request["content_type"] == "application/json"
    assert rows["25-empty-text.bru"]["request"]["body"] == "}\n\nassert {\nres.status: eq 200"
    assert rows["25-empty-text.bru"]["request"]["has_body"]
    assert rows["33-empty-text-mode.bru"]["request"]["body"] == ""
    assert rows["33-empty-text-mode.bru"]["request"]["has_body"]
    assert rows["11-no-body.bru"]["request"]["body"] is None
    assert not rows["11-no-body.bru"]["request"]["has_body"]
    custom = rows["27-custom-content-type.bru"]["request"]
    assert sum(name.lower() == "content-type" for name in custom["headers"]) == 1
    assert custom["content_type"] == "application/problem+json"
    assert json.loads(rows["22-json-escapes.bru"]["request"]["body"])


def test_unsupported_and_dynamic_effects_remain_visible_and_inert(collection):
    rows = by_path(collection)
    blocked = {name for name, row in rows.items() if not row["can_prepare"]}
    assert blocked == {"19-unresolved-query.bru", "20-inert-script.bru", "21-graphql.bru", "28-owned-file.bru", "29-owned-multipart.bru"}
    assert rows["19-unresolved-query.bru"]["unresolved"] == ["missingValue"]
    assert rows["20-inert-script.bru"]["definition"]["script"] == "[source omitted; never executed]"
    assert rows["28-owned-file.bru"]["request"]["body"] is None
    assert rows["29-owned-multipart.bru"]["request"]["body"] is None


def test_generated_report_keeps_logical_iterations_unknown_attempts_and_body_scalars():
    report = json.loads((ROOT / "report.json").read_text(encoding="utf-8"))
    imported = import_report(report)
    evidence = imported["bruno"]
    assert evidence["recorded_iterations"] == 2 and evidence["iteration_indexes"] == [0, 1]
    assert evidence["recorded_executions"] == 72 and evidence["observed_responses"] == 70
    assert evidence["dispatch_unknown"] == 2 and evidence["observed_execution_dispatches"] == 70
    assert evidence["recorded_skipped"] == 0 and evidence["wire_attempts"] is None
    assert imported["scope"]["requests_sent"] is None and imported["findings"] == []
    values = [row["response_body"] for row in imported["requests"]]
    assert "false" in values and "0" in values and "null" in values
    assert len({row["exchange_id"] for row in imported["requests"]}) == 72
    assert imported["provenance"]["requests_sent_during_current_action"] == 0


def test_generated_omitted_report_does_not_reconstruct_evidence_from_definitions():
    imported = import_report(json.loads((ROOT / "omitted.json").read_text(encoding="utf-8")))
    assert imported["bruno"]["recorded_executions"] == 72 and imported["bruno"]["observed_responses"] == 70
    assert all(row["response_body"] is None for row in imported["requests"])
    assert all(row["missing_evidence"] for row in imported["requests"])
    assert imported["findings"] == []


def one_report():
    return [{"iterationIndex": 0, "results": [{"test": {"filename": "folder/same.bru"},
        "request": {"method": "GET", "url": "http://fixture.localhost/", "headers": {"Authorization": "Bearer first-secret"}},
        "response": {"status": 200, "headers": {"content-type": "application/json"}, "data": {"value": True}},
        "assertionResults": [], "testResults": []}]}]


def test_separately_credentialed_original_reports_keep_distinct_provenance_after_redaction():
    original = one_report()
    changed = copy.deepcopy(original)
    changed[0]["results"][0]["request"]["headers"]["Authorization"] = "Bearer second-secret"
    first, second = import_report(original), import_report(changed)
    assert first["bruno"]["source"] == second["bruno"]["source"]
    assert first["bruno"]["source_id"] != second["bruno"]["source_id"]
    assert first["requests"][0]["exchange_id"] != second["requests"][0]["exchange_id"]
    assert first["bruno"]["source_hash_basis"] == "original-canonical-json"


def test_missing_assertions_skips_and_conflicting_source_claims_are_explicit():
    report = one_report()
    skipped = copy.deepcopy(report[0]["results"][0])
    skipped["response"] = {"status": "skipped", "data": None}
    skipped["skipped"] = True
    report[0]["results"].append(skipped)
    report[0]["results"][0]["skipped"] = True
    result = import_report(report)
    assert result["bruno"]["recorded_skipped"] == 1
    assert result["bruno"]["observed_responses"] == 1 and len(result["requests"]) == 1
    assert result["bruno"]["warnings"]
    assert result["bruno"]["assertion_evidence_missing"]["preRequestTestResults"] == 2
    assert result["bruno"]["assertion_evidence_missing"]["assertionResults"] == 0


def test_transitive_auth_aliases_raw_header_echoes_and_metadata_are_redacted_correctly():
    data = {"auth": {"mode": "bearer", "bearer": {"token": "{{opaque}}"}}, "vars": [
        {"name": "opaque", "value": "{{second}}"}, {"name": "second", "value": "private-value"}],
        "body_mode": "none", "http": {"auth": "inherit"}, "headers": {"X-Collection": "inherited"},
        "response_body": "echo private-value", "raw": "GET / HTTP/1.1\r\nAuthorization: Bearer raw-private\r\n\r\n", "echo": "raw-private"}
    safe = sanitise(data)
    assert "private-value" not in json.dumps(safe) and "raw-private" not in json.dumps(safe)
    assert safe["auth"]["mode"] == "bearer" and safe["http"]["auth"] == "inherit"
    assert safe["body_mode"] == "none" and safe["headers"]["X-Collection"] == "inherited"


def test_basic_apikey_and_oauth_keep_auth_configuration_without_credential_values():
    data = {"auth": {"mode": "apikey", "apikey": {"key": "X-Custom", "value": "{{opaque}}", "placement": "header"},
        "basic": {"username": "local-user", "password": "fixture-password"},
        "oauth2": {"grantType": "client_credentials", "accessTokenUrl": "https://identity.localhost/token",
                   "clientSecret": "fixture-client-secret"}},
        "variables": [{"name": "opaque", "value": "fixture-api-value"}],
        "body": {"label": "header", "value": "fixture-api-value"}}
    safe = sanitise(data)
    assert safe["auth"]["apikey"] == {"key": "X-Custom", "value": "<credential>", "placement": "header"}
    assert safe["auth"]["oauth2"]["accessTokenUrl"] == "https://identity.localhost/token"
    assert safe["auth"]["oauth2"]["grantType"] == "client_credentials"
    assert safe["body"]["label"] == "header"
    for secret in ("local-user", "fixture-password", "fixture-client-secret", "fixture-api-value"):
        assert secret not in json.dumps(safe)


@pytest.mark.parametrize("body", ["null", "false", "0", '""'])
def test_official_parser_export_roundtrip_preserves_json_scalar_bodies(body):
    converted = export_collection([{"method": "POST", "url": "http://fixture.localhost/value",
        "headers": {"Content-Type": "application/json"}, "body": body}])
    restored = import_collection(converted["files"], environment="Local")["requests"][0]["request"]
    assert restored["body"] == body and restored["has_body"]


def test_empty_text_export_refuses_official_serializer_loss():
    with pytest.raises(ValueError, match="serializer cannot preserve"):
        export_collection([{"method": "POST", "url": "http://fixture.localhost/value",
            "headers": {"Content-Type": "text/plain"}, "body": ""}])


@pytest.mark.parametrize("body", [None, False, 0, "", "JSON string", '{"looks":"encoded"}'])
def test_explicit_prepared_json_values_export_without_null_or_string_type_loss(body):
    converted = export_collection([{"method": "POST", "url": "http://fixture.localhost/value",
        "content_type": "application/problem+json", "has_body": True, "body_encoding": "json-value", "body": body}])
    restored = import_collection(converted["files"], environment="Local")["requests"][0]["request"]
    assert restored["has_body"] and restored["content_type"] == "application/problem+json"
    assert json.loads(restored["body"]) == body
    assert type(json.loads(restored["body"])) is type(body)
