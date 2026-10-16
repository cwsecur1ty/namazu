"""Render assessment evidence and export wiring using a local DOM fixture."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_audit_results_view import DOM, function
from tests.test_reporting import saved_audit


def render_script(script, audit):
    if not shutil.which("node"):
        pytest.skip("node is unavailable")
    module = Path("namazu/static/assessment-view.js").resolve()
    source = DOM + f"require({json.dumps(str(module))});\n" + "const audit = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n" + script
    result = subprocess.run(["node", "-e", source], input=json.dumps(audit), text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_zero_vulnerability_view_has_counts_limits_and_resolvable_evidence():
    from namazu.audit.reporting import assess_saved_audit
    payload = saved_audit()
    audit = {"assessment": assess_saved_audit(payload), "log": payload["requests"], "findings": []}
    result = render_script("""
const before = JSON.stringify(audit);
const view = NamazuAssessmentView.render(audit);
const links = byTag(view, 'a');
links[0].fire('click');
process.stdout.write(JSON.stringify({text:view.textContent, linkCount:links.length,
 opened:byClass(view,'case-evidence').some(entry => entry.open), unchanged:before === JSON.stringify(audit)}));
""", audit)
    assert "No exploitable vulnerability was demonstrated" in result["text"]
    assert "91 85 39 28 15 6" in result["text"]
    assert "9 blocked check families" in result["text"]
    assert "did not retain the response contract" in result["text"]
    assert "second-identity-positive-control" in result["text"]
    assert result["linkCount"] and result["opened"] and result["unchanged"]
    for title in ("What was tested?", "What did we establish?", "What remains unknown?", "What should I do next?"):
        assert title in result["text"]
    for title in ("Validation rejected this input: 28", "Same application denial: 39",
                  "Blocked at the edge: 15", "Timeouts and execution failures: 6"):
        assert title in result["text"]
    assert "Security leads requiring investigation: 0" in result["text"]


def test_security_lead_presentation_does_not_promote_static_or_validation_observations():
    result = render_script("""
const samples = [
 {assessment:{category:'security',origin:'static-declaration',verification:'unverified'}},
 {assessment:{category:'contract',origin:'runtime-observation',verification:'observed'}},
 {assessment:{category:'security',origin:'runtime-observation',verification:'observed'}},
 {assessment:{category:'security',origin:'external-report',verification:'impact-demonstrated'}},
 {assessment:{category:'security',origin:'runtime-observation',verification:'impact-demonstrated'}}];
process.stdout.write(JSON.stringify(samples.map(NamazuAssessmentView.isSecurityLead)));
""", {})
    assert result == [False, False, True, True, False]


def test_assessment_preserves_open_evidence_and_only_invokes_next_actions_on_click():
    from namazu.audit.reporting import assess_saved_audit
    payload = saved_audit()
    audit = {"assessment": assess_saved_audit(payload), "log": payload["requests"], "findings": []}
    helpers = Path("namazu/static/audit-results-view.js").resolve()
    result = render_script(f"require({json.dumps(str(helpers))});\n" + """
const actions=[], before=JSON.stringify(audit);
const first=NamazuAssessmentView.render(audit,{onAction(action){actions.push(action);}});
const link=byTag(first,'a')[0];link.fire('click');
const beforeClick=actions.length;
const button=byClass(first,'result-next-action')[0];button.fire('click');
const second=NamazuAssessmentView.render(audit);
const target=all(second,node=>node.id===link.href.slice(1))[0];
process.stdout.write(JSON.stringify({beforeClick,actions,opened:target.open,text:target.textContent,
 unchanged:JSON.stringify(audit)===before,timeout:first.textContent.includes('No response before timeout')}));
""", audit)
    assert result["beforeClick"] == 0
    assert result["actions"][0]["kind"] in {"configure-permissions", "define-success", "supply-test-data"}
    assert result["opened"] and "response_body" in result["text"]
    assert result["unchanged"] and result["timeout"]


def test_exact_evidence_index_starts_collapsed_and_reference_opens_both_ancestors():
    from namazu.audit.reporting import assess_saved_audit
    payload = saved_audit()
    audit = {"assessment": assess_saved_audit(payload), "log": payload["requests"], "findings": []}
    result = render_script("""
const first=NamazuAssessmentView.render(audit);
const index=byClass(first,'assessment-evidence-index')[0];
const before={open:index.open,records:byClass(index,'case-evidence').length,title:index.firstElementChild.textContent,
 bodyCount:byTag(index,'pre').length};
const link=byTag(first,'a')[0], event=link.fire('click');
const target=all(index,node=>node.id===link.href.slice(1))[0];
const opened={index:index.open,record:target.open,scrolled:target.scrolled,prevented:event.prevented,text:target.textContent};
const second=NamazuAssessmentView.render(audit);
const secondIndex=byClass(second,'assessment-evidence-index')[0];
const secondTarget=all(secondIndex,node=>node.id===link.href.slice(1))[0];
const preserved={index:secondIndex.open,record:secondTarget.open};
secondIndex.open=false;secondIndex.fire('toggle');
const third=NamazuAssessmentView.render(audit);
process.stdout.write(JSON.stringify({before,opened,preserved,
 reopenedIndex:byClass(third,'assessment-evidence-index')[0].open,
 topLevelCaseRows:third.children.filter(node=>node.className==='case-evidence').length}));
""", audit)
    assert result["before"]["open"] is False
    assert result["before"]["records"] > 50
    assert result["before"]["bodyCount"] == 0
    assert result["before"]["title"] == f'Exact retained evidence ({result["before"]["records"]} records)'
    assert result["opened"]["index"] and result["opened"]["record"]
    assert result["opened"]["scrolled"] and result["opened"]["prevented"]
    assert "response_body" in result["opened"]["text"]
    assert result["preserved"]["index"] and result["preserved"]["record"]
    assert result["reopenedIndex"] is False
    assert result["topLevelCaseRows"] == 0


def test_report_wiring_preserves_new_data_and_only_calls_offline_review():
    source = Path("namazu/static/app.js").read_text(encoding="utf-8")
    assert 'api("/api/audit/assess", auditExportPayload())' in source
    for exported, state_name in (("contract_snapshots", "contractSnapshots"), ("response_reviews", "responseReviews"),
                                 ("assessment", "assessment"), ("readiness", "readiness")):
        assert f"{exported}: state.audit.{state_name}" in source
        assert f"{state_name}: payload.{exported}" in source
    view = Path("namazu/static/assessment-view.js").read_text(encoding="utf-8")
    assert "innerHTML" not in view
    assert "fetch(" not in view
    assert 'api("/api/replay"' not in view


def test_prepared_baseline_requires_matching_route_and_primary_identity():
    result = render_script(function("preparedBaselineError") + """
const operation={method:'POST',path:'/reports/{id}'};
const prepared={identity_ref:'primary',request:{method:'POST',url:'http://127.0.0.1/api/reports/one'}};
const check = value => preparedBaselineError(value,operation,'http://127.0.0.1/api');
process.stdout.write(JSON.stringify({matching:check(prepared),
 otherRoute:check({...prepared,request:{...prepared.request,url:'http://127.0.0.1/api/people/one'}}),
 otherOrigin:check({...prepared,request:{...prepared.request,url:'http://localhost/api/reports/one'}}),
 otherIdentity:check({...prepared,identity_ref:'secondary'})}));
""", {})
    assert result["matching"] == ""
    assert "does not match" in result["otherRoute"]
    assert "does not match" in result["otherOrigin"]
    assert "No identity was remapped" in result["otherIdentity"]


def test_legacy_baseline_editor_keeps_prepared_business_assertions_and_headers():
    result = render_script(function("saveBaseline") + """
const assertion={pointer:'/id',operator:'equals',expected:'resource-one',purpose:'resource'};
const state={operation:{id:'create'},examples:{create:{identity_ref:'primary',
 example:{url:'http://127.0.0.1/old',headers:{Accept:'application/json'}},
 expectation:{status:'200',business_assertions:[assertion]}}}};
const values={'baseline-url':'http://127.0.0.1/new','baseline-body':'{}','baseline-status':'201','baseline-contains':''};
const $=id=>({value:values[id]||'',checked:false});
const saveExamples=()=>{},renderBaselineEditor=()=>{},toast=()=>{};
saveBaseline();process.stdout.write(JSON.stringify(state.examples.create));
""", {})
    assert result["expectation"]["status"] == "201"
    assert result["expectation"]["business_assertions"][0]["expected"] == "resource-one"
    assert result["example"]["headers"] == {"Accept": "application/json"}
    assert result["identity_ref"] == "primary"
