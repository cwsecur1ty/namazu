"""Offline report/definition interoperability; no security coverage claims."""
from __future__ import annotations

import copy
import io
import json
import socket
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.bruno import import_report, sanitise
from namazu.bruno_collections import (
    export_collection,
    file_map,
    import_collection,
    operation_matches,
)
from namazu.bruno_routes import prepare

FIXTURES = Path(__file__).parent / "fixtures" / "bruno"
BASE = "http://127.0.0.1:9876"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("Import/export/prepare must not open network connections")
    # Windows asyncio uses a loopback socketpair for its own wakeup pipe.
    # Block HTTP transports and connection helpers without breaking that IPC.
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", denied)


@pytest.fixture
def report():
    return json.loads((FIXTURES / "report.json").read_text())


def bru(extra="", *, url=BASE + "/widgets/42", method="get", mode="none"):
    return f"meta {{\n  name: Fixture\n  type: http\n  seq: 1\n}}\n{method} {{\n  url: {url}\n  body: {mode}\n  auth: none\n}}\n{extra}"


def file(path, content):
    return {"path": path, "content": content}


def spec():
    return {"openapi": "3.0.3", "info": {"title": "Local fixture", "version": "1"}, "servers": [{"url": BASE}], "paths": {"/widgets/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {"200": {"description": "ok"}}}}}}


def test_real_report_counts_iterations_assertions_and_no_findings(report):
    result = import_report(report)
    evidence = result["bruno"]
    assert evidence["recorded_executions"] == 14
    assert evidence["observed_responses"] == 12
    assert evidence["assertion_counts"]["assertionResults"] == {"pass": 10, "fail": 2, "unknown": 0}
    assert evidence["assertion_counts"]["testResults"] == {"pass": 2, "fail": 0, "unknown": 0}
    assert result["findings"] == []
    assert result["scope"]["requests_sent"] is None
    assert result["provenance"]["requests_sent_during_current_action"] == 0
    assert result["started_at"] is None
    assert result["coverage"]["probes"] == result["coverage"]["baselines"] == []
    assert len({r["id"] for r in evidence["executions"]}) == 14


def test_real_report_classifications(report):
    rows = import_report(report)["bruno"]["executions"]
    assert rows[2]["observation"] == rows[3]["observation"] == "application-denial; downstream handling unknown"
    assert rows[4]["observation"] == "validation-observation"
    assert rows[5]["observation"] == "explicit-edge-block"
    assert rows[6]["observation"] == "timeout/incomplete"
    assert rows[6]["request_sent"] is None
    assert all("vulnerability" not in row["observation"] for row in rows)


def test_duplicate_import_is_stable_and_retains_iteration_executions(report):
    first, second = import_report(report), import_report(copy.deepcopy(report))
    assert first["bruno"]["source_id"] == second["bruno"]["source_id"]
    assert first["requests"] == second["requests"]
    assert first["requests"][0]["exchange_id"] != first["requests"][7]["exchange_id"]
    assert first["requests"][0]["evidence_ref"]["pointer"] == "/0/results/0"


def test_omitted_and_partial_reports_remain_unknown(report):
    omitted = import_report(json.loads((FIXTURES / "omitted.json").read_text()))
    row = omitted["requests"][0]
    assert row["response_body"] is None and row["truncated"]
    assert row["missing_evidence"] and row["observation"] == "incomplete"
    partial = [report[0]]
    partial[0].pop("summary")
    partial[0]["futureMetadata"] = {"thing": 4}
    partial[0]["results"][0]["response"]["truncated"] = True
    result = import_report(partial)
    assert result["bruno"]["source"][0]["futureMetadata"] == {"thing": 4}
    assert result["requests"][0]["truncated"]
    assert result["scope"]["endpoints_in_scope"] is None


@pytest.mark.parametrize("payload", [{}, [], {"results": []}, [{"iterationIndex": 0, "results": [None]}], [{"iterationIndex": 0, "results": [{"request": {}, "response": {}}]}]])
def test_reject_unsupported_or_malformed_reports(payload):
    with pytest.raises(ValueError, match=r"Expected|expected"):
        import_report(payload)


def test_version_and_size_are_bounded(report):
    with pytest.raises(ValueError, match=r"4\.2\.1"):
        import_report(report, version="9.0")
    with pytest.raises(ValueError, match="8 MiB"):
        import_report([{"huge": "x" * (8 * 1024 * 1024)}])


def test_redaction_preserves_counts_classifications_and_header_differences(report):
    row = report[0]["results"][0]
    row["request"]["headers"]["Authorization"] = "Bearer short-test-secret"
    row["request"]["headers"]["X-Custom-Cred"] = "403"
    row["response"]["data"]["echo"] = "short-test-secret"
    report[0]["results"][1]["response"]["headers"]["x-frame-options"] = "SAMEORIGIN"
    report[0]["results"][2]["response"]["data"]["echo"] = "short-test-secret"
    result = import_report(report, credential_names=["x-custom-cred"])
    assert "short-test-secret" not in json.dumps(result)
    assert result["requests"][2]["status"] == 403
    assert result["requests"][0]["response_headers"]["x-frame-options"] == "DENY"
    assert result["requests"][1]["response_headers"]["x-frame-options"] == "SAMEORIGIN"
    assert result["bruno"]["assertion_counts"]["assertionResults"]["pass"] == 10
    assert "application-denial" in result["requests"][2]["observation"]


def test_static_variables_follow_official_precedence():
    files = [file("collection.bru", "vars:pre-request {\n value: collection\n}\n"), file("environments/Local.bru", "vars {\n value: environment\n base: " + BASE + "\n}\n"), file("nested/folder.bru", "vars:pre-request {\n value: folder\n}\n"), file("nested/request.bru", bru("vars:pre-request {\n value: request\n}\n", url="{{base}}/{{value}}")), file("nested/second.bru", bru(url="{{base}}/{{value}}")), file("third.bru", bru(url="{{base}}/{{value}}"))]
    assert import_collection(files)["requires_environment"]
    result = import_collection(files, environment="Local")
    assert [row["request"]["url"] for row in result["requests"]] == [BASE + "/request", BASE + "/folder", BASE + "/environment"]
    with pytest.raises(ValueError, match="absent"):
        import_collection(files, environment="Missing")


def test_scripts_dynamic_and_missing_variables_are_inert_and_block_preparation(tmp_path):
    marker = tmp_path / "must-not-exist"
    code = 'script:pre-request {\n require("fs").writeFileSync(' + json.dumps(str(marker)) + ', "executed");\n}\n'
    result = import_collection([file("a.bru", bru(code, url="{{process.env.SECRET}}/{{missing}}/{{$randomUUID}}"))], environment="")
    row = result["requests"][0]
    assert not marker.exists()
    assert not row["can_prepare"]
    assert set(row["unresolved"]) == {"process.env.SECRET", "missing", "$randomUUID"}
    assert result["source"]["definitions"]["a.bru"]["script"] == "[source omitted; never executed]"


def test_auth_is_only_a_reference_and_custom_secret_header_is_removed():
    text = bru("headers {\n X-Custom-Cred: live-fixture-credential\n X-Mode: reader\n}\n")
    result = import_collection([file("a.bru", text)], environment="", credential_names=["x-custom-cred"])
    row = result["requests"][0]
    assert row["request"]["headers"] == {"X-Mode": "reader"}
    assert row["authentication"][0]["header"] == "X-Custom-Cred"
    assert "live-fixture-credential" not in json.dumps(result)


@pytest.mark.parametrize("path", ["../x.bru", "/tmp/x.bru", "C:/x.bru", "a\\x.bru", "a//x.bru", "a/./x.bru", "collection.zip"])
def test_file_boundaries(path):
    with pytest.raises(ValueError):
        file_map([file(path, bru())])


def test_file_limits_and_duplicates():
    with pytest.raises(ValueError, match="256 KiB"):
        file_map([file("a.bru", "x" * 262145)])
    with pytest.raises(ValueError, match="Duplicate"):
        file_map([file("a.bru", bru()), file("A.bru", bru())])


def test_unsupported_bodies_and_query_mismatch_are_visible():
    row = import_collection([file("a.bru", bru("body:file {\n file: ../../sensitive.txt\n}\n", mode="file"))], environment="")["requests"][0]
    assert not row["can_prepare"]
    row = import_collection([file("a.bru", bru("params:query {\n q: wrong\n}\n", url=BASE + "/ok?q=right"))], environment="")["requests"][0]
    assert row["request"]["url"].endswith("q=right")
    assert any("Query table" in reason for reason in row["blockers"])


def prepared_payload():
    return {"files": [file("a.bru", bru())], "environment": "", "selection": "a.bru", "spec": spec(), "operation_id": "GET /widgets/{id}", "identity_ref": "primary", "identity_confirmed": True, "expectation": {"status": "200"}, "assertions": [{"purpose": "resource", "pointer": "/id", "operator": "equals", "expected": "42"}, {"purpose": "content", "pointer": "/owner", "operator": "equals", "expected": "local-user"}]}


def test_operation_mapping_and_explicit_baseline_requirements():
    assert operation_matches({"method": "GET", "url": BASE + "/widgets/42"}, spec()) == ["GET /widgets/{id}"]
    assert operation_matches({"method": "GET", "url": "http://127.0.0.1:9999/widgets/42"}, spec()) == []
    data = prepared_payload()
    result = prepare(data)
    assert result["requests_sent"] == 0 and result["prepared"]["positive_control"] is False
    assert len(result["expectation"]["business_assertions"]) == 2
    for changes in ({"assertions": []}, {"identity_confirmed": False}, {"operation_id": "POST /widgets/{id}"}, {"spec": None}):
        with pytest.raises(ValueError):
            prepare({**data, **changes})
    data["expectation"] = {"status": "403", "negative": True}
    assert not prepare(data)["prepared"]["positive_control"]


def test_export_official_parser_roundtrip_and_secret_free_environment():
    requests = [{"method": "POST", "url": BASE + "/widgets?api_key=fixture-query", "headers": {"Authorization": "Bearer fixture-token", "Cookie": "sid=fixture-cookie", "Content-Type": "application/json", "X-Frame-Options": "DENY"}, "body": '{"password":"fixture-password","enabled":true,"count":403}'}]
    exported = export_collection(requests)
    text = json.dumps(exported)
    for secret in ("fixture-token", "fixture-cookie", "fixture-password", "fixture-query"):
        assert secret not in text
    assert "NAMAZU_1_AUTHORIZATION" in text and "NAMAZU_1_COOKIE" in text
    parsed = import_collection(exported["files"], environment="Local")
    assert parsed["requests"][0]["request"]["method"] == "POST"
    assert parsed["requests"][0]["request"]["headers"]["X-Frame-Options"] == "DENY"
    assert "403" in parsed["requests"][0]["request"]["body"]
    assert exported["requests_sent"] == 0 and exported["warnings"]


def test_http_routes_offline_host_origin_and_zip(report):
    client = TestClient(app, base_url="http://127.0.0.1")
    result = client.post("/api/bruno/report", json={"report": report}).json()
    assert result["provenance"]["requests_sent_during_current_action"] == 0
    assert client.post("/api/bruno/report", json={"report": report}, headers={"Origin": "http://unrelated.test"}).status_code == 403
    assert client.post("/api/bruno/collection", json={"files": [file("a.bru", bru())], "environment": ""}).status_code == 200
    payload = {"requests": [{"method": "GET", "url": BASE + "/ok", "headers": {}, "body": None}]}
    assert client.post("/api/bruno/download", json=payload).status_code == 400
    response = client.post("/api/bruno/download", json={**payload, "reviewed": True})
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {"bruno.json", "request-001.bru", "environments/Local.bru"}


def test_redaction_does_not_rewrite_metadata_or_probe_markers():
    result = sanitise({"Authorization": "Bearer pass", "status": "pass", "classification": "application-denial", "count": 403, "body": '{"ok":true,"message":"pass","probe":"namazu-inert-marker"}'})
    assert result["status"] == "pass" and result["count"] == 403
    body = json.loads(result["body"])
    assert body["ok"] is True and body["message"] == "<credential>"
    assert body["probe"] == "namazu-inert-marker"


def test_prepared_assertions_are_enforced_by_existing_baseline_gate():
    from namazu.audit.baseline import Expectation, classify
    from namazu.audit.coverage import Ledger
    from namazu.audit.model import Exchange

    prepared = prepare(prepared_payload())
    expectation = Expectation.from_dict(prepared["expectation"])
    exchange = Exchange(label="local", method="GET", url=BASE + "/widgets/42", status=200, body='{"id":"wrong","owner":"local-user"}')
    assert not classify(exchange, expectation=expectation).usable
    exchange.body = '{"id":"42","owner":"wrong-owner"}'
    assert not classify(exchange, expectation=expectation).usable
    exchange.body = '{"id":"42","owner":"local-user"}'
    assert classify(exchange, expectation=expectation).positive_control
    expectation.negative, expectation.status, exchange.status = True, "403", 403
    verdict = classify(exchange, expectation=expectation)
    assert verdict.usable and not verdict.positive_control
    ledger = Ledger()
    ledger.block_dependents(verdict)
    assert ledger.state("authorization") == "blocked"


def test_environment_inheritance_and_external_references_are_not_guessed():
    files = [file("a.bru", bru()), file("environments/Local.bru", "extends: Parent\nvars {\n  value: child\n}\n")]
    row = import_collection(files, environment="Local")["requests"][0]
    assert not row["can_prepare"]
    assert any("flattened" in message for message in row["blockers"])


def test_report_source_preserves_failed_tests_unknown_outcomes_and_errors(report):
    row = report[0]["results"][0]
    row["testResults"].extend([{"name": "failed synthetic test", "status": "fail", "error": "expected 201"}, {"status": "future"}])
    result = import_report(report)
    assert result["bruno"]["assertion_counts"]["testResults"] == {"pass": 2, "fail": 1, "unknown": 1}
    assert result["bruno"]["source"][0]["results"][0]["testResults"][1]["error"] == "expected 201"
    assert result["findings"] == []


def test_named_array_credentials_and_body_slots_never_export_values():
    request = {"method": "POST", "url": BASE + "/ok", "headers": {"Authorization": ["Bearer array-credential"]}, "body": '{"password":"one-secret","token":"two-secret"}'}
    assert "array-credential" not in json.dumps(sanitise(request))
    request["headers"] = {"Content-Type": "application/json"}
    exported = export_collection([request])
    text = json.dumps(exported)
    assert "one-secret" not in text and "two-secret" not in text
    assert "BODY_SECRET_1" in text and "BODY_SECRET_2" in text


def test_export_rejects_structural_injection_and_malformed_requests():
    for request in (None, {"method": "GET", "url": BASE + "/ok\n}\nscript:pre-request {\n require('fs')\n}\nget {\n url: " + BASE}, {"method": "GET", "url": "http://"}):
        with pytest.raises(ValueError):
            export_collection([request])


def test_secondary_identity_and_secret_assertions_cannot_be_prepared():
    for changes in ({"identity_ref": "secondary"}, {"expectation": {"status": "garbage"}}, {"assertions": [{"purpose": "resource", "pointer": "/token", "operator": "equals", "expected": "a"}, {"purpose": "content", "pointer": "/id", "operator": "equals", "expected": "x"}]}):
        with pytest.raises(ValueError):
            prepare({**prepared_payload(), **changes})


def test_body_metadata_names_do_not_hide_credential_echoes():
    result = sanitise({"Authorization": "Bearer pass", "status": "pass", "body": '{"status":"pass","operator":"pass","purpose":"pass"}'})
    assert result["status"] == "pass"
    assert set(json.loads(result["body"]).values()) == {"<credential>"}
    result = sanitise({"body": {"design": "distinct", "assignment": "reader", "author": "fixture", "probe": "namazu-inert-marker"}})
    assert result["body"] == {"design": "distinct", "assignment": "reader", "author": "fixture", "probe": "namazu-inert-marker"}


def test_secret_environment_variable_shadows_lower_static_value():
    files = [file("collection.bru", "vars:pre-request {\n baseUrl: " + BASE + "\n}\n"), file("environments/Local.bru", "vars:secret [\n baseUrl\n]\n"), file("a.bru", bru(url="{{baseUrl}}/ok"))]
    row = import_collection(files, environment="Local")["requests"][0]
    assert row["unresolved"] == ["baseUrl"]
    assert not row["can_prepare"]


def test_redaction_preserves_generated_identifiers(report):
    report[0]["results"][0]["request"]["headers"]["Authorization"] = "Bearer bruno"
    result = import_report(report)
    assert result["requests"][0]["exchange_id"] == result["bruno"]["executions"][0]["id"]
