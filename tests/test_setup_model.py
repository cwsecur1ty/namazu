"""The guided setup explains real prerequisites without sending target requests."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

MODULE = Path("namazu/static/setup-model.js").resolve()


def model(function, value):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    source = (f"const model = require({json.dumps(str(MODULE))});"
              "const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              f"process.stdout.write(JSON.stringify(model.{function}(input)));")
    result = subprocess.run(["node", "-e", source], input=json.dumps(value),
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def fixture():
    operation = {"id": "POST /summaries", "method": "POST", "path": "/summaries",
                 "request_body": {"required": True, "content": {"application/json": {
                     "schema": {"$ref": "#/components/schemas/SummaryRequest"}}}},
                 "responses": {"200": {"content": {"application/json": {"schema": {
                     "type": "object", "required": ["responseOnly"], "properties": {
                         "responseOnly": {"type": "string"}}}}}}}}
    return {"spec": {"title": "Local fixture", "servers": ["http://127.0.0.1:9876"],
                     "operations": [operation], "document": {"components": {"schemas": {
                         "SummaryRequest": {"allOf": [
                             {"$ref": "#/components/schemas/Resource"},
                             {"type": "object", "required": ["enabled", "count", "stored"],
                              "properties": {"enabled": {"type": "boolean", "example": False},
                                             "count": {"type": "integer", "example": 0},
                                             "stored": {"$ref": "#/components/schemas/Stored"}}}]},
                         "Resource": {"type": "object", "required": ["documentUri"],
                                      "properties": {"documentUri": {"type": "string", "example": "string",
                                                                     "description": "Document this identity may summarize."}}},
                         "Stored": {"type": "string", "readOnly": True}}}}},
            "operation": operation, "base_url": "http://127.0.0.1:9876",
            "credentials_configured": True, "identity_ref": "primary"}


def by_id(result):
    return {item["id"]: item for item in result["items"]}


def test_url_and_credentials_without_business_data_keep_independent_prerequisites():
    result = model("deriveSetup", fixture())
    items = by_id(result)
    assert items["specification"]["state"] == "loaded"
    assert items["target"]["state"] == "selected"
    assert items["credentials"]["state"] == "configured"
    assert items["authentication"]["state"] == "unverified"
    assert items["business-baseline"]["state"] == "missing"
    assert items["second-identity"]["state"] == "missing"
    assert items["permissions"]["state"] == "missing"
    assert result["suggested_profile"] == "passive"
    assert {item["pointer"] for item in result["unresolved"]} == {"/documentUri", "/enabled", "/count"}
    assert "responseOnly" not in json.dumps(result)
    assert "stored" not in json.dumps(result["fields"])
    fields = {item["pointer"]: item for item in result["fields"]}
    assert fields["/documentUri"]["description"] == "Document this identity may summarize."
    assert fields["/documentUri"]["examples"][0]["probable_placeholder"]
    assert fields["/enabled"]["examples"][0]["value"] is False
    assert fields["/count"]["examples"][0]["value"] == 0
    assert "Inputs to confirm: body /documentUri" in result["owner_request"]
    assert "writes profile" in " ".join(result["requires"])


def test_supplied_false_zero_and_real_resource_are_not_missing_or_invented():
    data = fixture()
    data["request"] = {"body": {"documentUri": "fixture-resource", "enabled": False, "count": 0}}
    result = model("deriveSetup", data)
    assert not result["unresolved"]
    assert all(field["provided"] for field in result["fields"])
    assert all("value" not in field for field in result["fields"])
    assert by_id(result)["business-baseline"]["state"] == "missing"


@pytest.mark.parametrize("authentication", [
    {"status": "verified", "token_decoded": True},
    {"status": "verified", "token_obtained": True},
    {"status": "verified", "oauth_redirect": True},
    {"status": "verified", "basis": "identity-response", "identity_match": True,
     "response_status": 200, "current_credentials_match": False},
])
def test_token_steps_cannot_verify_authentication(authentication):
    data = fixture()
    data["authentication"] = authentication
    assert by_id(model("deriveSetup", data))["authentication"]["state"] == "unverified"


def test_specific_identity_evidence_is_separate_from_business_baseline():
    data = fixture()
    data["authentication"] = {"status": "verified", "basis": "identity-response", "identity_match": True,
                              "response_status": 200, "current_credentials_match": True}
    items = by_id(model("deriveSetup", data))
    assert items["authentication"]["state"] == "verified"
    assert items["business-baseline"]["state"] == "missing"


@pytest.mark.parametrize("authentication", [{"status": "failed", "error": "invalid_grant"}, {"expired": True}])
def test_expired_or_failed_token_is_unverified(authentication):
    data = fixture()
    data["authentication"] = authentication
    item = by_id(model("deriveSetup", data))["authentication"]
    assert item["state"] == "unverified"
    assert "No authenticated API access" in item["detail"]


def test_uniform_denial_never_identifies_the_failing_layer_or_unlocks_success():
    data = fixture()
    data["baseline"] = {"exchange": {"status": 403}}
    data["prepared"] = {"positive_control": True, "expectation": {"negative": True}}
    data.update(profile="writes", allow_writes=True)
    result = model("deriveSetup", data)
    items = by_id(result)
    assert items["authentication"]["state"] == "inconclusive"
    assert items["authentication"]["detail"] == (
        "The request was denied. Credentials, endpoint roles or resource permissions may be responsible. "
        "This response does not distinguish them.")
    assert items["business-baseline"]["state"] == "missing"
    assert any("even when the baseline is denied" in item for item in result["can_run"])


def test_http_success_alone_does_not_establish_business_success():
    data = fixture()
    data["baseline"] = {"status": 200, "response_body": '{"error":"not entitled"}'}
    assert by_id(model("deriveSetup", data))["business-baseline"]["state"] == "missing"


def test_successful_business_baseline_with_one_identity_keeps_second_identity_gap():
    data = fixture()
    data["prepared"] = {"positive_control": True, "expectation": {"status": "200"},
                        "recorded_response": {"status": 200}, "missing_prerequisites": [],
                        "identity_ref": "primary", "operation": "POST /summaries",
                        "request": {"url": "http://127.0.0.1:9876/summaries"}}
    data["operation"]["method"] = "GET"
    result = model("deriveSetup", data)
    items = by_id(result)
    assert items["business-baseline"]["state"] == "established"
    assert items["second-identity"]["state"] == "missing"
    assert result["suggested_profile"] == "readonly"
    assert items["authentication"]["state"] == "unverified"


@pytest.mark.parametrize(("key", "value"), [("identity_ref", "secondary"), ("operation", "POST /other"),
                                          ("request", {"url": "http://127.0.0.1:9999/summaries"})])
def test_a_business_control_cannot_transfer_to_another_identity_operation_or_target(key, value):
    data = fixture()
    data["prepared"] = {"positive_control": True, "expectation": {"status": "200"},
                        "recorded_response": {"status": 200}, "missing_prerequisites": [],
                        "identity_ref": "primary", "operation": "POST /summaries",
                        "request": {"url": "http://127.0.0.1:9876/summaries"}}
    data["prepared"][key] = value
    assert by_id(model("deriveSetup", data))["business-baseline"]["state"] == "missing"


def test_second_identity_and_permission_matrix_are_independent():
    data = fixture()
    data["second_identity"] = "secondary"
    data["permission_matrix"] = [{"identity_ref": "secondary", "expect": "deny"}]
    result = model("deriveSetup", data)
    assert by_id(result)["second-identity"]["state"] == "configured"
    assert by_id(result)["permissions"]["state"] == "configured"
    assert by_id(result)["business-baseline"]["state"] == "missing"
    data["second_identity"] = "identity a"
    assert by_id(model("deriveSetup", data))["second-identity"]["state"] == "missing"
    data["permission_matrix"][0]["expect"] = "unknown"
    assert by_id(model("deriveSetup", data))["permissions"]["state"] == "missing"


def test_multiple_servers_require_explicit_choice_and_documentation_is_not_target():
    data = fixture()
    data["spec"]["servers"].append("http://127.0.0.1:9877")
    assert by_id(model("deriveSetup", data))["target"]["state"] == "missing"
    data["target_selected"] = True
    assert by_id(model("deriveSetup", data))["target"]["state"] == "selected"
    data.pop("target_selected")
    data["spec"]["servers"] = []
    data["spec"]["source_url"] = data["base_url"]
    assert by_id(model("deriveSetup", data))["target"]["state"] == "missing"


def test_schema_alternatives_do_not_require_both_branches_or_response_fields():
    data = fixture()
    data["operation"]["request_body"]["content"]["application/json"]["schema"] = {
        "oneOf": [{"required": ["uri", "common"], "properties": {
            "uri": {"type": "string"}, "common": {"type": "boolean"}}},
            {"required": ["id", "common"], "properties": {
                "id": {"type": "number"}, "common": {"type": "boolean"}}}]}
    result = model("deriveSetup", data)
    fields = {item["pointer"]: item for item in result["fields"]}
    assert fields["/common"]["required"] and not fields["/common"]["conditional"]
    assert fields["/uri"]["conditional"] and fields["/id"]["conditional"]
    assert {item["pointer"] for item in result["unresolved"]} == {"/common"}


def test_schema_request_examples_and_secret_examples_are_handled_without_echoing_credentials():
    data = fixture()
    data["request"] = {"body": {"password": "never-echo-submitted-secret"}}
    data["operation"]["request_body"]["content"]["application/json"]["schema"] = {
        "type": "object", "example": {"resource": "record-one", "nested": {"access_token": "never-echo-example"}},
        "properties": {"resource": {"type": "string"}, "password": {"type": "string", "writeOnly": True, "example": "never-echo-password"},
                       "nested": {"type": "object"}}}
    result = model("deriveSetup", data)
    assert "never-echo" not in json.dumps(result)
    fields = {item["pointer"]: item for item in result["fields"]}
    assert fields["/resource"]["examples"][0]["value"] == "record-one"
    assert fields["/password"]["sensitive"] and fields["/password"]["provided"]
    assert fields["/password"]["examples"] == []
    assert fields["/nested"]["examples"][0]["value"]["access_token"] == "<redacted>"


def test_parameters_preserve_locations_and_escaped_json_pointers():
    data = fixture()
    data["operation"]["parameters"] = [
        {"in": "path", "name": "resource/id", "schema": {"type": "string"}, "description": "An existing resource."},
        {"in": "query", "name": "enabled", "required": True, "schema": {"type": "boolean"}},
        {"in": "header", "name": "X-API-Key", "required": True, "example": "never-echo-header"}]
    data["request"] = {"parameters": {"path.resource/id": "fixture-one", "query.enabled": False, "header.X-API-Key": "secret"}}
    fields = {item["id"]: item for item in model("deriveSetup", data)["fields"]}
    assert fields["path:/resource~1id"]["provided"]
    assert fields["query:/enabled"]["provided"]
    assert fields["header:/X-API-Key"]["examples"] == []
    assert "never-echo" not in json.dumps(fields)


def test_external_refs_remain_visible_without_fetching():
    data = fixture()
    data["operation"]["request_body"]["content"]["application/json"]["schema"] = {"$ref": "https://invalid.local/request.json"}
    result = model("deriveSetup", data)
    assert result["warnings"][0]["code"] == "unresolved-schema"
    assert "not bundled" in result["warnings"][0]["detail"]


def test_required_names_without_property_schema_are_not_lost():
    data = fixture()
    data["operation"]["request_body"]["content"]["application/json"]["schema"] = {
        "type": "object", "required": ["documentId"]}
    result = model("deriveSetup", data)
    assert result["unresolved"][0]["pointer"] == "/documentId"
    assert result["unresolved"][0]["type"] == "unspecified"
    assert result["unresolved"][0]["examples"] == []


@pytest.mark.parametrize(("value", "action", "kind"), [
    ({"state": "not-applicable", "reason_codes": ["requires-get"]}, "none", "not-applicable"),
    ({"reason_codes": ["second-identity-missing"]}, "permissions", "missing-setup"),
    ({"code": "successful-business-baseline-required"}, "baseline", "missing-setup"),
    ({"code": "credential-missing"}, "identity", "missing-setup"),
    ({"code": "timeout"}, "replay", "incomplete"),
    ({"code": "write-not-authorized"}, "plan", "policy"),
])
def test_blocker_actions_do_not_treat_non_applicability_as_bad_credentials(value, action, kind):
    result = model("blockerAction", value)
    assert result["id"] == action
    assert result["kind"] == kind


def test_traffic_is_a_budget_bound_with_separate_unknown_inventory():
    result = model("trafficSummary", {"profile": "writes", "operation_count": 3, "request_budget": 10,
                                      "inventory": True, "concurrency": 2})
    assert result["endpoint_upper_bound"] == 30
    assert result["inventory_requests"] is None and result["total_upper_bound"] is None
    assert result["concurrency"] == 2
    assert result["requests_sent"] == 0
    assert "upper bound, not a coverage target" in result["label"]
    result = model("trafficSummary", {"profile": "passive", "operation_count": 3, "request_budget": 900,
                                      "inventory": True, "inventory_planned_requests": 50})
    assert result["endpoint_upper_bound"] == 3 and result["total_upper_bound"] == 53
