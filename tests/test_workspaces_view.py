"""Contract evidence adapters keep existing classification and navigation intact."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx

from namazu.audit.engine import audit_operation
from namazu.spec import parse_spec
from tests.test_audit_results_view import exchange, node, planned, receipt

WORKSPACES = Path("namazu/static/workspaces.js").resolve()


def workspace_node(script, payload):
    return node("document.getElementById = () => null;\n"
                + f"require({json.dumps(str(WORKSPACES))});\n" + script, payload)


def test_plan_review_does_not_present_schema_cases_as_total_endpoint_traffic():
    payload = {"request_budget": 50, "engine_plan": {"request_breakdown": {"baseline": 1, "schema_inputs": 6},
               "test_plan": {"probes": [{"field_pointer": "/callback", "location": "body", "mutation": "null", "status": "planned"}],
                             "supplemental_checks": [{"check": "authentication", "conditional": True, "planned_requests": None,
                                                       "request_ceiling": 43, "prerequisite": "Successful positive control"},
                                                      {"check": "writes", "conditional": False, "planned_requests": 0,
                                                       "missing_prerequisites": ["profile-disallows-check"]}]}}}
    result = workspace_node("""
const summary=NamazuWorkspaces.operationTraffic(input),view=NamazuWorkspaces.planCaseReview(input,'POST /widgets');
const before=view.textContent;view.open=true;view.ontoggle();
process.stdout.write(JSON.stringify({summary,before,text:view.textContent}));
""", payload)
    assert result["summary"]["baseline"] == 1
    assert result["summary"]["schema"] == 6
    assert result["summary"]["conditionalFamilies"] == 1
    assert result["summary"]["ceiling"] == 50
    assert "Successful positive control" not in result["before"]
    assert "Successful positive control" in result["text"]
    assert "Conditional; remaining ceiling 43" in result["text"]
    assert "not promised requests or additive allocations" in result["text"]
    assert "body /callback" in result["text"]


def test_same_operation_names_keep_historical_contract_and_identity_boundaries():
    payload = {
        "evidence": {
            "workspace": {"id": "w"},
            "contracts": [
                {"id": "a", "title": "Accounts", "hash": "original-a", "target": "http://127.0.0.1/v1"},
                {"id": "b", "title": "Orders", "hash": "original-b", "target": "http://127.0.0.1/v2"},
            ],
            "assessments": [
                {"contract_id": "a", "operation_id": "getWidget", "snapshot_hash": "original-a", "identity_ref": "shared", "evidence_refs": ["x1"]},
                {"contract_id": "b", "operation_id": "getWidget", "snapshot_hash": "original-b", "identity_ref": "override", "evidence_refs": ["x2"]},
            ],
        },
        "current": {"contracts": [{"id": "a", "hash": "replacement-a", "target": "http://127.0.0.1/new"}]},
    }
    result = workspace_node("process.stdout.write(JSON.stringify(NamazuWorkspaces.evidenceContracts(input.evidence, input.current)));", payload)
    assert [group["contract"]["hash"] for group in result] == ["original-a", "original-b"]
    assert [group["assessments"][0]["identity_ref"] for group in result] == ["shared", "override"]
    assert [group["assessments"][0]["evidence_refs"] for group in result] == [["x1"], ["x2"]]
    assert "replacement-a" not in json.dumps(result)


def test_missing_historical_hash_never_inherits_current_snapshot_or_target():
    result = workspace_node("process.stdout.write(JSON.stringify(NamazuWorkspaces.evidenceContracts(input.evidence, input.current)));", {
        "evidence": {"assessments": [{"contract_id": "old", "operation_id": "GET /same"}]},
        "current": {"contracts": [{"id": "old", "title": "Current title", "hash": "new-hash", "target": "http://127.0.0.1/new"}]},
    })
    assert "new-hash" not in json.dumps(result)
    assert "http://127.0.0.1/new" not in json.dumps(result)


def test_direct_engine_shape_preserves_single_plan_baseline_and_same_denial_classification():
    probe = planned("null")
    payload = {
        "workspace_id": "w", "contract_id": "a", "operation_key": "a::POST /widgets", "snapshot_hash": "old-a",
        "operation_id": "POST /widgets", "target": "http://127.0.0.1/v1", "identity_ref": "shared",
        "test_plan": {"operation": "createWidget", "probes": [probe]},
        "coverage": {"authorization": {"state": "inconclusive"}},
        "baseline": exchange(name="baseline"), "probes": [receipt(probe, exchange())],
        "log": [], "findings": [],
    }
    result = workspace_node(r"""
const before = JSON.stringify(input);
const audit = NamazuWorkspaces.asAudit(input, input);
const model = NamazuAuditResults.buildResults(audit);
const view = NamazuAuditResultsView.render(audit);
process.stdout.write(JSON.stringify({text:view.textContent, model, fields:byClass(view,'test-field').length,
  unchanged:before===JSON.stringify(input), plans:audit.plans.length, baseline:audit.baselines[0].exchange}));
""", payload)
    assert result["unchanged"] and result["plans"] == 1
    assert result["fields"] == 1
    assert result["baseline"]["status"] == 403
    assert "Same denial as baseline; downstream handling unknown" in result["text"]
    assert result["model"]["operations"][0]["fields"][0]["cases"][0]["comparison"] == "same-denial"


def test_nested_export_receipts_and_business_baseline_are_not_hidden_by_empty_adapters():
    probe = planned("field")
    payload = {"operation_id": "POST /widgets", "test_plan": {"operation": "createWidget", "probes": [probe]},
               "coverage": {"probes": [receipt(probe, exchange())], "fields": [{"operation": "createWidget", "field_pointer": "/enabled", "location": "body"}],
                            "baselines": [{"endpoint": "POST /widgets", "exchange": exchange(name="baseline"), "verdict": {"outcome": "negative-control"}}]}}
    result = workspace_node(r"""
const audit = NamazuWorkspaces.asAudit(input,input);
process.stdout.write(JSON.stringify({probes:audit.probes, fields:audit.fieldCoverage, baselines:audit.baselines,
  rendered:NamazuAuditResultsView.render(audit).textContent}));
""", payload)
    assert len(result["probes"]) == len(result["fields"]) == 1
    assert result["baselines"][0]["verdict"]["outcome"] == "negative-control"
    assert "Same denial as baseline" in result["rendered"]


def test_identical_operation_and_target_get_independent_disclosure_ids_by_contract():
    probe = planned("field")
    assessment = {"workspace_id": "w", "operation_id": "POST /widgets", "target": "http://127.0.0.1/same",
                  "test_plan": {"operation": "createWidget", "probes": [probe]}, "baseline": exchange(name="baseline"),
                  "probes": [receipt(probe, exchange())], "snapshot_hash": "same-hash"}
    result = workspace_node(r"""
const reports = input.map(item => NamazuAuditResultsView.render(NamazuWorkspaces.asAudit(item,item)));
const ids = reports.map(report => all(report, node => !!node.id).map(node => node.id));
process.stdout.write(JSON.stringify({ids, overlap:ids[0].filter(id=>ids[1].includes(id))}));
""", [{**assessment, "contract_id": name, "operation_key": f"{name}::POST /widgets"} for name in ["a", "b"]])
    assert result["ids"][0] and result["ids"][1]
    assert result["overlap"] == []


def test_real_mock_engine_result_renders_field_receipts_without_reclassifying_denials():
    document = {"openapi": "3.0.3", "info": {"title": "Local view fixture", "version": "1"},
                "servers": [{"url": "http://127.0.0.1:9901/v1"}], "paths": {"/widgets": {"get": {
                    "operationId": "sameOperation", "parameters": [{"name": "limit", "in": "query", "example": 1,
                        "schema": {"type": "integer", "minimum": 1, "maximum": 5}}],
                    "responses": {"200": {"description": "OK"}, "403": {"description": "Denied"}}}}}}
    def handler(request):
        return httpx.Response(403, json={"error": "Not entitled"}, headers={"content-type": "application/json"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_operation(parse_spec(document), "GET /widgets", profile="readonly", request_budget=12, client=client)
    original = copy.deepcopy(result)
    result.update(workspace_id="w", contract_id="a", operation_key="a::GET /widgets", snapshot_hash="hash", target="http://127.0.0.1:9901/v1")
    rendered = workspace_node(r"""
const audit = NamazuWorkspaces.asAudit(input,input), model = NamazuAuditResults.buildResults(audit);
const view = NamazuAuditResultsView.render(audit);
process.stdout.write(JSON.stringify({text:view.textContent,fields:byClass(view,'test-field').length,
  plans:audit.plans.length, receipts:audit.probes.length,summary:model.summary}));
""", result)
    assert original["probes"] and rendered["receipts"] == len(original["probes"])
    assert rendered["plans"] == 1 and rendered["fields"] >= 1
    assert "downstream handling unknown" in rendered["text"]
    assert "Uniform application denials" in rendered["text"]


def test_missing_receipts_do_not_become_completed_cases():
    result = workspace_node(r"""
const model = NamazuAuditResults.buildResults(NamazuWorkspaces.asAudit(input,input));
process.stdout.write(JSON.stringify(model.summary));
""", {"operation_id": "POST /widgets", "test_plan": {"operation": "createWidget", "probes": [planned("missing")]}, "coverage": {}})
    assert result["executedCases"] == 0
    assert result["unknownCases"] == 1


def test_pending_save_blocks_contract_navigation_and_unlocks_after_response():
    fixture = {"id": "w", "title": "Local workspace", "revision": 1, "profiles": [], "overlaps": [], "runs": [],
               "contracts": [{"id": name, "title": name, "hash": name, "target": "http://127.0.0.1/" + name,
                              "operations": [], "config": {"budget": None, "operation_ids": []}} for name in ["a", "b"]]}
    result = workspace_node(r"""
const opener = new Element('button');
document.getElementById = id => id === 'workspaces-open' ? opener : null;
document.body = new Element('body');
Element.prototype.querySelector = function() {return all(this,node=>node.attributes['aria-selected']==='true')[0] || null;};
const app = NamazuWorkspaces.mount();
app.state.workspace = input; app.state.selected='a'; app.render();
const editor = all(app.dialog,node=>node.className==='workspace-field' && node.textContent.includes('Contract request limit'))[0];
byTag(editor,'input')[0].value='7';
let finish, captured;
fetch = (_url, options) => {captured=JSON.parse(options.body);return new Promise(resolve=>{finish=resolve;});};
const pending = byTag(app.dialog,'button').find(button=>button.textContent==='Save contract limits').onclick();
const locked = app.state.saving && byClass(app.dialog,'workspace-body')[0].inert
  && byClass(app.dialog,'workspace-tabs')[0].inert && byClass(app.dialog,'workspace-header-actions')[0].inert;
byClass(app.dialog,'workspace-contract-choice')[1].onclick();
byClass(app.dialog,'workspace-tab')[1].onclick();
const during={contract:app.state.selected,view:app.state.view};
input.contracts[0].config.budget=7;
finish({ok:true,json:async()=>input});
pending.then(()=>{
  const unlocked=!app.state.saving && !byClass(app.dialog,'workspace-body')[0].inert;
  byClass(app.dialog,'workspace-contract-choice')[1].onclick();
  process.stdout.write(JSON.stringify({locked,unlocked,during,after:app.state.selected,captured}));
});
""", fixture)
    assert result["locked"] and result["unlocked"]
    assert result["during"] == {"contract": "a", "view": "contracts"}
    assert result["after"] == "b"
    assert result["captured"]["config"] == {"budget": 7, "allow_mutating": False}
