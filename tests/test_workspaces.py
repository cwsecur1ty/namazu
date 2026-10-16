"""Deterministic workspace boundaries: fixtures and mock HTTP only."""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from namazu import discovery
from namazu.spec import build_request
from namazu.workspaces import WorkspaceService, normalise_target, url_in_scopes


def document(target="http://127.0.0.1:9123/api/v1", *, path="/items/{id}", method="get", field_type="string", title="Items"):
    operation = {"operationId": "sameOperation", "parameters": [
        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "example": 7}}
    ] if "{id}" in path else [], "responses": {"200": {"description": "OK", "content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}}}
    if method == "post":
        operation["requestBody"] = {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}
    return {"openapi": "3.0.3", "info": {"title": title, "version": "1"},
            "servers": [{"url": target}], "paths": {path: {method: operation}},
            "components": {"schemas": {"Item": {"type": "object", "properties": {"value": {"type": field_type}}}}}}


@pytest.fixture
def service(tmp_path):
    service = WorkspaceService(tmp_path / "workspaces.db")
    yield service
    service.close()


def imported(service, *documents):
    workspace = service.create("Fixture workspace")
    return service.import_contracts(workspace["id"], [{"raw_spec": doc, "filename": f"contract-{index}.json"} for index, doc in enumerate(documents)])


def profile(service, workspace, name="Shared", token="local-shared-token"):
    value = service.set_profile(workspace["id"], {"name": name, "token": token})
    return value["profiles"][-1]["id"]


def assign(service, workspace, contract, pid, **kwargs):
    return service.assign_identity(workspace["id"], contract["id"], {"profile_id": pid, "allowed_scopes": [contract["target"]], **kwargs})


def separate(service, workspace):
    for overlap in service.get(workspace["id"])["overlaps"]:
        if overlap["requires_review"]:
            service.decide_overlap(workspace["id"], {"overlap_id": overlap["id"], "action": "separate"})


def test_plan_separates_schema_case_count_from_conditional_traffic_and_runtime_ceiling(service):
    workspace = imported(service, document())
    plan = service.plan(workspace["id"], {"profile": "readonly", "budget": 25, "concurrency": 2})
    review = plan["operations"][0]["traffic_review"]
    assert review["baseline_requests"] == 1
    assert review["schema_input_cases"] > 0
    assert review["conditional_families"] > 0
    assert review["operation_request_ceiling"] > review["schema_input_cases"]
    assert plan["traffic"]["shared_request_budget"] == 25
    assert plan["traffic"]["concurrency"] == 2
    assert service.execution_config(workspace["id"], plan["id"])["concurrency"] == 2
    for invalid in (True, 0, 17, 2.5, "4"):
        with pytest.raises(ValueError, match="concurrency"):
            service.plan(workspace["id"], {"concurrency": invalid})


def test_contract_namespace_isolates_schema_operation_and_configuration(service):
    workspace = imported(service, document(method="post"), document(method="post", field_type="integer", title="Other"))
    left, right = workspace["contracts"]
    assert left["operations"][0]["operation_id"] == right["operations"][0]["operation_id"]
    assert left["operations"][0]["id"] != right["operations"][0]["id"]
    assert isinstance(build_request(left["spec"], "POST /items/{id}")["body"]["value"], str)
    assert isinstance(build_request(right["spec"], "POST /items/{id}")["body"]["value"], int)
    unchanged = copy.deepcopy(right)
    service.update_contract(workspace["id"], left["id"], {"config": {
        "examples": {"POST /items/{id}": {"body": {"value": "left-only"}}},
        "expectations": {"POST /items/{id}": {"statuses": [201]}},
        "assertions": {"POST /items/{id}": [{"pointer": "/value", "value": "left-only"}]},
        "baselines": {"POST /items/{id}": {"status": 201}}, "allow_mutating": True}})
    changed = service.get(workspace["id"])
    assert changed["contracts"][1] == unchanged
    assert not changed["contracts"][1]["config"]["allow_mutating"]


def test_relative_references_are_rebased_per_origin_and_never_cross_contracts(service):
    raw = document(method="post")
    raw["components"]["schemas"]["Item"] = {"$ref": "./types.yaml#/Item"}
    workspace = service.create()
    workspace = service.import_contracts(workspace["id"], [
        {"raw_spec": raw, "filename": "alpha/openapi.yaml", "documents": {"alpha/types.yaml": {"Item": {"type": "string", "example": "alpha"}}}},
        {"raw_spec": raw, "filename": "beta/openapi.yaml", "documents": {"beta/types.yaml": {"Item": {"type": "integer", "example": 42}}}},
        {"raw_spec": raw, "filename": "gamma/openapi.yaml"},
    ])
    left, right, missing = workspace["contracts"]
    assert build_request(left["spec"], "POST /items/{id}")["body"] == "alpha"
    assert build_request(right["spec"], "POST /items/{id}")["body"] == 42
    assert not left["unresolved_references"] and not right["unresolved_references"]
    assert missing["unresolved_references"] == ["file:///workspace/gamma/types.yaml#/Item"]
    assert left["hash"] != right["hash"]


@pytest.mark.parametrize("target", ["http://127.0.0.2:9123/api/v1", "http://127.0.0.1:9123/other/v1", "http://127.0.0.1:9123/api/v2"])
def test_identical_paths_at_distinct_hosts_bases_versions_are_separate(service, target):
    workspace = imported(service, document(), document(target))
    assert workspace["overlaps"][0]["kind"] == "similar-path-different-target"
    plan = service.plan(workspace["id"])
    assert plan["ready"]
    assert all("reuse_from" not in row for row in plan["operations"])


def test_duplicate_and_conflicting_contracts_require_explicit_review(service):
    workspace = imported(service, document(), document(), document(field_type="integer"))
    assert {row["kind"] for row in workspace["overlaps"]} == {"identical-contract", "conflicting-endpoint"}
    assert not service.plan(workspace["id"])["ready"]
    separate(service, workspace)
    plan = service.plan(workspace["id"])
    assert plan["ready"]
    assert plan["operations"][1]["reuse_from"] == plan["operations"][0]["operation_key"]
    assert "reuse_from" not in plan["operations"][2]
    assert plan["traffic"]["contract_assessments"] == 3
    assert plan["traffic"]["endpoint_operations"] == 2


@pytest.mark.parametrize("left,right", [
    (document(), document(path="/items/current")),
    (document("http://127.0.0.1:9123/api", path="/v1/items/{id}"), document(path="/items/current")),
    (document(path="/items/{name}"), document(path="/items/{id}")),
])
def test_overlapping_templates_are_reviewed_on_effective_endpoint(service, left, right):
    workspace = imported(service, left, right)
    assert workspace["overlaps"][0]["kind"] == "potential-template-overlap"
    assert not service.plan(workspace["id"])["ready"]


def test_owner_and_explicit_exclusion_keep_accounting_honest(service):
    workspace = imported(service, document(), document())
    overlap = workspace["overlaps"][0]
    service.decide_overlap(workspace["id"], {"overlap_id": overlap["id"], "action": "owner", "owner": overlap["operations"][0]})
    plan = service.plan(workspace["id"])
    assert plan["ready"]
    assert plan["operations"][1]["excluded"]
    assert plan["traffic"]["contract_assessments"] == 1
    service.decide_overlap(workspace["id"], {"overlap_id": overlap["id"], "action": "exclude", "excluded": [overlap["operations"][0]]})
    assert service.plan(workspace["id"])["operations"][0]["excluded"]


def test_bearer_assignments_are_explicit_override_wins_unassigned_gets_none(service):
    workspace = imported(service, document(), document("http://127.0.0.1:9123/api/v2"), document("http://127.0.0.2:9123/public"))
    left, right, third = workspace["contracts"]
    shared = profile(service, workspace)
    assign(service, workspace, left, shared)
    assign(service, workspace, right, shared)
    plan = service.plan(workspace["id"])
    config = service.execution_config(workspace["id"], plan["id"])
    assert config["operations"][0]["identities"] == config["operations"][1]["identities"]
    assert config["operations"][2]["identities"] == {}
    assert config["operations"][2]["identity_source"] == "no identity configured"
    other = profile(service, workspace, "Override", "local-other-token")
    assign(service, workspace, right, other, override=True)
    plan = service.plan(workspace["id"])
    config = service.execution_config(workspace["id"], plan["id"])
    assert config["operations"][1]["identity_source"] == "contract-specific override"
    assert config["operations"][1]["identities"]["primary"]["headers"]["Authorization"] == "Bearer local-other-token"
    assert service.get(workspace["id"])["contracts"][0]["readiness"]["status"] == "unestablished"
    assert third["config"]["baselines"] == {}


def test_assignment_removal_and_rotation_stop_existing_dispatch_and_stale_plans(service):
    workspace = imported(service, document())
    contract = workspace["contracts"][0]
    shared = profile(service, workspace)
    assign(service, workspace, contract, shared)
    plan = service.plan(workspace["id"])
    config = service.execution_config(workspace["id"], plan["id"])
    guard = config["operations"][0]["scope_guard"]
    assert guard()
    service.set_profile(workspace["id"], {"id": shared, "token": "rotated-local-token"})
    assert not guard()
    with pytest.raises(ValueError, match="stale"):
        service.execution_config(workspace["id"], plan["id"])
    plan = service.plan(workspace["id"])
    guard = service.execution_config(workspace["id"], plan["id"])["operations"][0]["scope_guard"]
    service.assign_identity(workspace["id"], contract["id"], {"remove": True})
    assert not guard()
    plan = service.plan(workspace["id"])
    assert service.execution_config(workspace["id"], plan["id"])["operations"][0]["identities"] == {}


def test_target_change_demands_scope_review_even_inside_previous_scope(service):
    workspace = imported(service, document())
    contract = workspace["contracts"][0]
    shared = profile(service, workspace)
    service.assign_identity(workspace["id"], contract["id"], {"profile_id": shared, "allowed_scopes": ["http://127.0.0.1:9123/api"]})
    plan = service.plan(workspace["id"])
    service.update_contract(workspace["id"], contract["id"], {"target": "http://127.0.0.1:9123/api/v2"})
    changed = service.plan(workspace["id"])
    assert not changed["ready"]
    assert any(b["code"] == "identity-scope-review-required" for b in changed["blockers"])
    with pytest.raises(ValueError, match="stale"):
        service.execution_config(workspace["id"], plan["id"])


@pytest.mark.parametrize("difference", ["identity", "input", "assertion", "baseline", "expectation"])
def test_distinct_execution_context_is_never_deduplicated(service, difference):
    workspace = imported(service, document(), document())
    left, right = workspace["contracts"]
    if difference == "identity":
        first = profile(service, workspace)
        second = profile(service, workspace, "Other", "other-fixture-token")
        assign(service, workspace, left, first)
        assign(service, workspace, right, second)
    else:
        settings = {"input": ("examples", {"method": "GET", "url": right["target"] + "/items/9", "headers": {}}),
                    "assertion": ("assertions", [{"pointer": "/value", "operator": "equals", "value": "different"}]),
                    "baseline": ("baselines", {"status": 200, "source": "separate-contract-control"}),
                    "expectation": ("expectations", {"statuses": [204]})}
        key, value = settings[difference]
        service.update_contract(workspace["id"], right["id"], {"config": {key: {"GET /items/{id}": value}}})
    separate(service, workspace)
    plan = service.plan(workspace["id"])
    assert plan["ready"], plan["blockers"]
    assert all("reuse_from" not in op for op in plan["operations"])


def test_partial_import_failure_keeps_valid_contract_and_never_guesses_docs_target(service):
    raw = document()
    raw.pop("servers")
    workspace = service.create()
    workspace = service.import_contracts(workspace["id"], [{"raw_spec": "invalid"}, {"raw_spec": raw, "source_url": "http://127.0.0.1:9123/docs/openapi.json"}])
    assert len(workspace["contracts"]) == len(workspace["import_errors"]) == 1
    assert workspace["contracts"][0]["target"] == ""
    assert workspace["contracts"][0]["target_review_required"]
    assert not service.plan(workspace["id"])["ready"]


def test_documentation_resolution_and_references_receive_no_profile_credential(service, monkeypatch):
    workspace = imported(service, document())
    pid = profile(service, workspace)
    assign(service, workspace, workspace["contracts"][0], pid)
    attempts = []
    raw = document()
    raw["components"]["schemas"]["Item"] = {"$ref": "http://127.0.0.2:9123/reference.json#/Item"}
    def handler(request):
        attempts.append(request)
        assert "authorization" not in request.headers
        if request.url.path == "/docs":
            return httpx.Response(302, headers={"Location": "http://127.0.0.2:9123/spec.json"})
        return httpx.Response(200, json=raw)
    original = discovery.fetch_document
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        monkeypatch.setattr(discovery, "fetch_document", lambda url, **kwargs: original(url, client=client, **kwargs))
        current = service.import_contracts(workspace["id"], [{"url": "http://127.0.0.1:9123/docs"}])
    assert len(attempts) == 2
    assert current["contracts"][-1]["unresolved_references"] == ["http://127.0.0.2:9123/reference.json#/Item"]
    count = len(attempts)
    service.plan(workspace["id"])
    assert len(attempts) == count


def test_write_permissions_and_limits_are_contract_specific(service):
    workspace = imported(service, document(method="post"), document("http://127.0.0.1:9123/api/v2", method="post"))
    left, right = workspace["contracts"]
    pid = profile(service, workspace)
    assign(service, workspace, left, pid)
    assign(service, workspace, right, pid)
    service.update_contract(workspace["id"], left["id"], {"config": {"allow_mutating": True, "budget": 7}})
    plan = service.plan(workspace["id"], {"profile": "writes", "allow_mutating": True, "budget": 13})
    assert not plan["ready"]
    assert plan["operations"][0]["allow_mutating"]
    assert plan["operations"][1]["excluded"]
    assert plan["traffic"]["shared_request_budget"] == 13
    assert plan["operations"][0]["request_budget"] == 7


def test_replace_remove_and_roundtrip_retain_historical_hashes_and_secrets_never_persist(service):
    workspace = imported(service, document(), document("http://127.0.0.1:9123/api/v2"))
    left, right = workspace["contracts"]
    pid = profile(service, workspace)
    assign(service, workspace, left, pid)
    plan = service.plan(workspace["id"])
    service.update_contract(workspace["id"], left["id"], {"raw_spec": document(field_type="integer")})
    updated = service.get(workspace["id"])
    assert left["hash"] in updated["contracts"][0]["snapshots"]
    assert updated["contracts"][0]["hash"] != left["hash"]
    assert updated["contracts"][1] == right
    service.remove_contract(workspace["id"], left["id"])
    exported = service.export(workspace["id"])
    assert "local-shared-token" not in json.dumps(exported)
    assert b"local-shared-token" not in service.path.read_bytes()
    restored = service.restore(exported)
    assert restored["contracts"][0]["id"] == right["id"]
    assert restored["archived_contracts"][0]["id"] == left["id"]
    assert restored["plans"][0]["id"] == plan["id"]
    assert restored["plans"][0]["status"] == "invalidated"
    assert not restored["profiles"][0]["credential_available"]


def test_offline_engine_field_plans_are_retained(service):
    workspace = imported(service, document())
    plan = service.plan(workspace["id"])
    engine = plan["operations"][0]["engine_plan"]
    assert engine["target_requests_sent"] == 0
    assert "test_plan" in engine
    assert "request_breakdown" in engine


@pytest.mark.parametrize("url", ["http://127.0.0.1:9123/api-evil/items", "http://127.0.0.2:9123/api/items",
                                "http://127.0.0.1:9123/api/%2e%2e/private", "http://127.0.0.1:9123/api/%252e%252e/private",
                                "http://127.0.0.1:9123/api/%5cprivate"])
def test_scope_checks_fail_closed_for_unassigned_and_ambiguous_destinations(url):
    assert not url_in_scopes(url, ["http://127.0.0.1:9123/api"])


def test_scope_normalises_default_ports_and_segment_boundaries():
    assert normalise_target("https://EXAMPLE.test:443/api/") == "https://example.test/api"
    assert url_in_scopes("http://127.0.0.1/api/items", ["http://127.0.0.1:80/api"])


def test_tampered_import_snapshot_never_controls_execution(service):
    workspace = imported(service, document())
    exported = service.export(workspace["id"])
    contract = exported["workspace"]["contracts"][0]
    old_hash = contract["hash"]
    # The visible current spec and the historical snapshot disagree.
    contract["spec"]["document"]["paths"] = {"/reviewed": {"get": {"responses": {"200": {"description": "OK"}}}}}
    contract["snapshots"][old_hash]["spec"]["document"]["paths"] = {"/hidden": {"get": {"responses": {"200": {"description": "OK"}}}}}
    restored = service.restore(exported)
    active = restored["contracts"][0]
    assert active["recorded_hash"] == old_hash
    assert active["hash"] != old_hash
    assert old_hash in active["snapshots"]
    service.update_contract(restored["id"], active["id"], {"config": {"operation_ids": ["GET /reviewed"]}})
    plan = service.plan(restored["id"])
    config = service.execution_config(restored["id"], plan["id"])
    assert config["operations"][0]["operation_id"] == "GET /reviewed"
    assert set(config["operations"][0]["spec"]["document"]["paths"]) == {"/reviewed"}


@pytest.mark.parametrize("split", [False, True])
def test_coedited_snapshot_checksums_must_still_derive_from_hashed_material(service, split):
    raw = document()
    item = {"raw_spec": raw, "filename": "alpha/openapi.yaml"}
    if split:
        raw["components"]["schemas"]["Item"] = {"$ref": "./types.yaml#/Item"}
        item["documents"] = {"types.yaml": {"Item": {"type": "string"}}}
    workspace = service.create()
    workspace = service.import_contracts(workspace["id"], [item])
    exported = service.export(workspace["id"])
    contract = exported["workspace"]["contracts"][0]
    old_hash = contract["hash"]
    snapshot = contract["snapshots"][old_hash]
    original_material = copy.deepcopy(snapshot["material"])
    executable = contract["spec"]["document"]
    if split:
        companion = next(iter(executable["x-namazu-documents"].values()))
        companion["Item"]["type"] = "integer"
    else:
        executable["paths"]["/items/{id}"]["get"]["parameters"][0]["schema"]["example"] = 99
    # An edited export can co-edit both executable documents and their displayed
    # document checksum while retaining the older material and contract hash.
    snapshot["spec"]["document"] = copy.deepcopy(executable)
    snapshot["document_hash"] = hashlib.sha256(json.dumps(executable, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    restored = service.restore(exported)
    active = restored["contracts"][0]
    assert active["hash"] != old_hash
    assert active["recorded_hash"] == old_hash
    assert active["snapshots"][old_hash]["material"] == original_material
    plan = service.plan(restored["id"])
    execution = service.execution_config(restored["id"], plan["id"])
    assert execution["operations"][0]["snapshot_hash"] == active["hash"]
    assert execution["operations"][0]["spec"]["document"] == executable


def test_untampered_split_snapshot_roundtrip_retains_verified_contract_hash(service):
    raw = document()
    raw["components"]["schemas"]["Item"] = {"$ref": "./types.yaml#/Item"}
    workspace = service.create()
    workspace = service.import_contracts(workspace["id"], [{"raw_spec": raw, "filename": "alpha/openapi.yaml",
        "documents": {"types.yaml": {"Item": {"$ref": "./nested.yaml#/value"}}, "nested.yaml": {"value": {"type": "string"}}}}])
    restored = service.restore(service.export(workspace["id"]))
    assert restored["contracts"][0]["hash"] == workspace["contracts"][0]["hash"]
    assert "recorded_hash" not in restored["contracts"][0]


def test_control_expectations_do_not_follow_credentials_or_targets(service):
    workspace = imported(service, document())
    contract = workspace["contracts"][0]
    pid = profile(service, workspace)
    assign(service, workspace, contract, pid)
    service.update_contract(workspace["id"], contract["id"], {"config": {"expectations": {"GET /items/{id}": {"status": "200"}}}})
    assert service.plan(workspace["id"])["ready"]
    service.set_profile(workspace["id"], {"id": pid, "token": "rotated-local-token"})
    plan = service.plan(workspace["id"])
    assert any(row["code"] == "control-scope-review-required" for row in plan["blockers"])
    service.update_contract(workspace["id"], contract["id"], {"config": {"budget": 8}})
    assert not service.plan(workspace["id"])["ready"]
    service.update_contract(workspace["id"], contract["id"], {"review_operation_ids": ["GET /items/{id}"],
        "config": {"expectations": {"GET /items/{id}": {"status": "200"}}}})
    assert service.plan(workspace["id"])["ready"]


def test_reference_hashes_are_source_independent_but_preserve_document_mapping(service):
    raw = document()
    raw["components"]["schemas"] = {"Item": {"$ref": "./a.yaml#/value"}, "Other": {"$ref": "./b.yaml#/value"}}
    a, b = {"value": {"type": "string"}}, {"value": {"type": "integer"}}
    workspace = service.create()
    workspace = service.import_contracts(workspace["id"], [
        {"filename": "alpha/openapi.yaml", "raw_spec": raw, "documents": {"a.yaml": a, "b.yaml": b}},
        {"filename": "beta/openapi.yaml", "raw_spec": raw, "documents": {"a.yaml": a, "b.yaml": b}},
        {"filename": "gamma/openapi.yaml", "raw_spec": raw, "documents": {"a.yaml": b, "b.yaml": a}},
    ])
    first, second, swapped = workspace["contracts"]
    assert first["hash"] == second["hash"]
    assert first["hash"] != swapped["hash"]


@pytest.mark.parametrize("options", [{"budget": 0}, {"requests_per_second": 0}, {"allow_mutating": "false"}])
def test_invalid_execution_limits_or_nonboolean_authorization_are_rejected(service, options):
    workspace = imported(service, document())
    with pytest.raises(ValueError):
        service.plan(workspace["id"], options)


def test_selected_media_type_is_part_of_exact_reviewed_deduplication(service):
    left = document(method="post")
    right = copy.deepcopy(left)
    media = {"schema": {"$ref": "#/components/schemas/Item"}}
    left["paths"]["/items/{id}"]["post"]["requestBody"]["content"] = {"application/vnd.first+json": media, "application/vnd.second+json": media}
    right["paths"]["/items/{id}"]["post"]["requestBody"]["content"] = {"application/vnd.second+json": media, "application/vnd.first+json": media}
    workspace = imported(service, left, right)
    for contract in workspace["contracts"]:
        service.update_contract(workspace["id"], contract["id"], {"config": {"allow_mutating": True}})
    separate(service, workspace)
    plan = service.plan(workspace["id"], {"profile": "writes", "allow_mutating": True})
    assert plan["ready"], plan["blockers"]
    assert plan["operations"][0]["built_request_hash"] != plan["operations"][1]["built_request_hash"]
    assert not any(row.get("reuse_from") for row in plan["operations"])


def test_saved_example_aliases_require_overlap_review_for_effective_endpoint(service):
    workspace = imported(service, document(path="/a"), document(path="/b", field_type="integer"))
    assert not workspace["overlaps"]
    for contract in workspace["contracts"]:
        key = contract["operations"][0]["local_id"]
        service.update_contract(workspace["id"], contract["id"], {"config": {"examples": {
            key: {"url": contract["target"] + "/shared"}}}})
    current = service.get(workspace["id"])
    overlap = current["overlaps"][0]
    assert overlap["kind"] == "conflicting-endpoint"
    assert overlap["endpoints"][0] == overlap["endpoints"][1]
    assert overlap["declared_endpoints"][0] != overlap["declared_endpoints"][1]
    assert any(block["code"] == "overlap-review-required" for block in service.plan(workspace["id"])["blockers"])
    separate(service, workspace)
    assert service.plan(workspace["id"])["ready"]
    # Changing the prepared request also changes the overlap review identity.
    contract = current["contracts"][0]
    service.update_contract(workspace["id"], contract["id"], {"config": {"examples": {
        "GET /a": {"url": contract["target"] + "/shared?variant=two"}}}})
    changed = service.get(workspace["id"])["overlaps"][0]
    assert changed["id"] != overlap["id"]
    assert changed["decision"] is None
    assert not service.plan(workspace["id"])["ready"]


def test_saved_example_outside_reviewed_target_remains_blocked(service):
    workspace = imported(service, document(path="/a"), document(path="/b"))
    contract = workspace["contracts"][0]
    service.update_contract(workspace["id"], contract["id"], {"config": {"examples": {
        "GET /a": {"url": "http://127.0.0.2:9123/unassigned"}}}})
    plan = service.plan(workspace["id"])
    assert not plan["ready"]
    assert any(block["code"] == "operation-plan-invalid" for block in plan["blockers"])


def test_slow_document_import_keeps_guards_responsive_and_merges_current_configuration(service, monkeypatch):
    workspace = imported(service, document())
    contract = workspace["contracts"][0]
    plan = service.plan(workspace["id"])
    guard = service.execution_config(workspace["id"], plan["id"])["operations"][0]["scope_guard"]
    entered, release = threading.Event(), threading.Event()
    def blocked_fetch(url, **kwargs):
        assert kwargs["headers"] == {}
        entered.set()
        assert release.wait(5), "Test failed to release the deterministic mock fetch"
        return document("http://127.0.0.1:9123/api/v2"), url, []
    monkeypatch.setattr(discovery, "fetch_document", blocked_fetch)
    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = workers.submit(service.import_contracts, workspace["id"], [{"url": "http://127.0.0.1:9123/docs"}])
        try:
            assert entered.wait(1)
            assert workers.submit(guard).result(timeout=1)
            changed = workers.submit(service.update_contract, workspace["id"], contract["id"], {"config": {"budget": 7}}).result(timeout=1)
            assert changed["contracts"][0]["config"]["budget"] == 7
            assert not workers.submit(guard).result(timeout=1)
        finally:
            release.set()
        completed = pending.result(timeout=2)
    assert len(completed["contracts"]) == 2
    assert completed["contracts"][0]["config"]["budget"] == 7
