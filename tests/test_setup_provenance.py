"""Local guided-setup and saved-evidence provenance regressions."""
import copy
import importlib
import json

import httpx
from fastapi.testclient import TestClient

from namazu.app import app
from namazu.audit import contract
from namazu.audit.engine import audit_inventory, audit_operation
from namazu.audit.provenance import (
    contract_manifest,
    saved_run_provenance,
    snapshot_hash,
)
from namazu.audit.reporting import assess_saved_audit, portable_evidence, render_html
from namazu.audit.transport import Pace
from namazu.discovery import fetch_document, setup_metadata
from namazu.spec import parse_spec


def document():
    return {"openapi": "3.0.3", "info": {"title": "Local setup", "version": "1"},
            "servers": [{"url": "http://127.0.0.1:9123/api"}],
            "paths": {"/items": {"get": {"responses": {"200": {"description": "Success",
                      "content": {"application/json": {"schema": {"type": "object"}}}}}}}}}


def test_setup_exposes_documentation_and_api_addresses_separately(monkeypatch):
    module = importlib.import_module("namazu.app")
    monkeypatch.setattr(module, "fetch_document", lambda *_args, **_kwargs:
                        (document(), "http://127.0.0.1:9000/spec/openapi.yaml", []))
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post("/api/import", json={"url": "http://127.0.0.1:9000/docs"})
    setup = response.json()["setup"]
    assert setup["documentation_url"] == "http://127.0.0.1:9000/docs"
    assert setup["specification_url"] == "http://127.0.0.1:9000/spec/openapi.yaml"
    assert setup["suggested_target"] == "http://127.0.0.1:9123/api"
    assert setup["operation_count"] == 1
    assert not setup["target_selection_required"]


def test_operation_specific_servers_require_explicit_target_choice():
    raw = document()
    raw["paths"]["/items"]["get"]["servers"] = [{"url": "http://127.0.0.1:9124/api"}]
    setup = setup_metadata(parse_spec(raw))
    assert setup["target_selection_required"]
    assert setup["suggested_target"] is None
    assert len(setup["server_choices"]) == 2


def test_missing_server_declaration_does_not_silently_select_documentation_host():
    raw = document()
    del raw["servers"]
    setup = setup_metadata(parse_spec(raw, "http://127.0.0.1:9000/docs"))
    assert setup["server_declarations_missing"]
    assert setup["target_selection_required"]
    assert setup["suggested_target"] is None


def test_explicit_openapi_download_link_is_discovered_without_executing_scripts():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return (httpx.Response(200, json=document()) if request.url.path == "/spec/openapi.yaml"
                else httpx.Response(200, text='<html><a href="/spec/openapi.yaml">Download specification</a></html>'))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result, source, _ = fetch_document("http://127.0.0.1:9000/docs", client=client)
    assert source.endswith("/spec/openapi.yaml")
    assert len(seen) == 2
    assert result["info"]["title"] == "Local setup"


def test_old_export_has_unknown_metadata_and_no_new_traffic(monkeypatch):
    monkeypatch.setattr(httpx.Client, "send", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("offline")))
    saved = {"api": {"base_url": "http://127.0.0.1:9123?token=private"},
             "started_at": "2026-10-09T08:20:43Z", "requests": [], "findings": []}
    before = copy.deepcopy(saved)
    result = assess_saved_audit(saved)["provenance"]
    assert result["kind"] == "offline-reassessment"
    assert result["requests_sent_during_current_action"] == 0
    assert result["source_run"]["status"] == "unknown"
    assert result["source_run"]["tool_version"] is None
    assert "private" not in result["source_run"]["target"]
    assert result["contract"]["availability"] == "unavailable"
    assert result["contract"]["hash"] is None
    assert saved == before


def test_interrupted_source_is_preserved_during_offline_reassessment():
    source = {"target": "http://127.0.0.1:9123", "environment": "local fixture",
              "started_at": "2026-10-09T08:20:43Z", "tool_version": "0.9-test", "status": "interrupted"}
    result = saved_run_provenance({"provenance": {"kind": "live-run", "source_run": source,
                                                "requests_sent_during_current_action": 12}})
    assert result["source_kind"] == "live-run"
    assert result["source_run"] == source
    assert result["requests_sent_during_current_action"] == 0


def test_contract_checksum_is_stable_but_exposes_changed_evidence():
    parsed = parse_spec(document())
    saved = contract.snapshot(parsed, parsed["operations"][0])
    reordered = dict(reversed(list(saved.items())))
    assert snapshot_hash(saved) == snapshot_hash(reordered)
    payload = {"contract_snapshots": {"GET /items": saved}}
    assert contract_manifest(payload)["operations"][0]["hash_status"] == "verified"
    saved["operation"]["responses"]["418"] = {"description": "Changed after export"}
    assert contract_manifest(payload)["operations"][0]["hash_status"] == "mismatch"


def test_hash_describes_redacted_export_and_offline_artifact_retains_snapshot():
    raw = document()
    raw["paths"]["/items"]["get"]["responses"]["200"]["description"] = "knownsecret123"
    with httpx.Client(transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={}))) as client:
        result = audit_operation(raw, "GET /items", profile="readonly", request_budget=1,
                                 identities={"primary": {"headers": {"Authorization": "Bearer knownsecret123"}}},
                                 client=client)
    saved = result["contract_snapshot"]
    assert "knownsecret123" not in json.dumps(saved)
    assert saved["integrity"]["hash"] == snapshot_hash(saved)
    source = {"contract_snapshots": {"GET /items": saved}, "requests": [], "findings": []}
    exported = portable_evidence(assess_saved_audit(source), source)
    assert exported["contract_snapshots"]["GET /items"] == saved
    assert exported["provenance"]["contract"]["operations"][0]["hash_status"] == "verified"
    rendered = render_html(exported)
    assert "Offline reassessment" in rendered
    assert "Source tool version</dt><dd>Not recorded" in rendered
    assert exported["provenance"]["contract"]["hash"] in rendered


def test_inventory_rate_and_budget_apply_to_all_attempts(monkeypatch):
    intervals, seen = [], []
    monkeypatch.setattr(Pace, "wait", lambda self: intervals.append(self.interval))

    def handler(request):
        seen.append(request)
        return httpx.Response(404, text="not found")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_inventory(document(), budget=3, requests_per_second=2, concurrency=2, client=client)
    assert result["requests_sent"] == len(seen) == len(intervals) == 3
    assert set(intervals) == {0.5}
    assert result["request_budget"] == 3


def test_inventory_route_passes_explicit_rate_and_budget(monkeypatch):
    captured = {}
    module = importlib.import_module("namazu.app")
    monkeypatch.setattr(module, "audit_inventory", lambda _spec, **kwargs: captured.update(kwargs) or {})
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post("/api/audit/inventory", json={"spec": document(), "budget": 7,
                                                            "requests_per_second": 1.5})
    assert response.status_code == 200
    assert captured["budget"] == 7
    assert captured["requests_per_second"] == 1.5
