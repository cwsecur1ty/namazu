"""Render actual receipt models with a minimal DOM, entirely without network IO."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

MODEL = Path("namazu/static/audit-results.js").resolve()
VIEW = Path("namazu/static/audit-results-view.js").resolve()
APP = Path("namazu/static/app.js").read_text(encoding="utf-8")


DOM = r"""
class Element {
  constructor(tag) {this.tagName = tag; this.children = []; this.dataset = {}; this.events = {};
    this.attributes = {}; this.style = {}; this._text = ''; this.className = ''; this.open = false;}
  set textContent(value) {this._text = String(value); this.children = [];}
  get textContent() {return this._text + this.children.map(child => typeof child === 'string' ? child : child.textContent).join(' ');}
  get childElementCount() {return this.children.length;}
  get firstElementChild() {return this.children[0];}
  get lastElementChild() {return this.children.at(-1);}
  append(...children) {this.children.push(...children);}
  replaceChildren(...children) {this._text = ''; this.children = children;}
  addEventListener(name, callback) {(this.events[name] ||= []).push(callback);}
  setAttribute(name, value) {this.attributes[name] = value;}
  scrollIntoView() {this.scrolled = true;}
  fire(name) {const event = {preventDefault() {this.prevented = true;}};
    for (const callback of this.events[name] || []) callback(event); return event;}
}
const document = {createElement(tag) {return new Element(tag);}};
function all(root, predicate) {
  return [root, ...root.children.filter(child => typeof child !== 'string').flatMap(child => all(child, () => true))].filter(predicate);
}
function byClass(root, name) {return all(root, node => node.className.split(' ').includes(name));}
function byTag(root, name) {return all(root, node => node.tagName === name);}
globalThis.fetch = () => {throw new Error('Rendering must never send requests');};
"""


def function(name):
    match = re.search(r"  function " + name + r"\([^\n]*\) \{(?:[^\n]*\}|.*?^  \})", APP,
                      re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group(0)


def node(script, payload=None):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    prelude = (DOM + f"globalThis.NamazuAuditResults = require({json.dumps(str(MODEL))});\n"
               + f"require({json.dumps(str(VIEW))});\n"
               + "const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n")
    result = subprocess.run(["node", "-e", prelude + script], input=json.dumps(payload),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def exchange(*, name="mutation", body='{"error":"not entitled"}', status=403, **extra):
    return {"label": name, "method": "POST", "url": "http://127.0.0.1:9876/widgets",
            "request_headers": {"Authorization": "<credential>"}, "request_body": '{"enabled":null}',
            "status": status, "response_headers": {"Content-Type": "application/json"},
            "response_body": body, "body_excerpt": "a deliberately shorter excerpt", **extra}


def planned(identifier, mutation="null", pointer="/enabled"):
    return {"id": identifier, "operation": "createWidget", "field_pointer": pointer,
            "location": "body", "mutation": mutation, "status": "planned", "planned_requests": 1}


def receipt(plan, capture=None, **extra):
    return {**plan, "status": "same-denial-as-baseline", "request_sent": capture is not None,
            **({"exchange": capture} if capture else {}), **extra}


def audit(plans=None, receipts=None, baseline=None):
    return {"running": False, "findings": [], "requests": 0,
            "plans": [{"endpoint": "POST /widgets", "operation_id": "createWidget",
                       "test_plan": {"operation": "createWidget", "probes": plans or []}}],
            "probes": receipts or [], "baselines": [{"endpoint": "POST /widgets",
                                                       "exchange": baseline or exchange(name="baseline")}],
            "fieldCoverage": [], "requestBreakdown": {}, "log": []}


def test_equivalent_cases_are_accessible_and_links_open_original_exchange_values():
    cases = [planned("null"), planned("wrong-type", mutation="wrong-type")]
    records = [exchange(name=f"mutation-{index}", body=json.dumps({"error": "not entitled",
               "timestamp": f"2026-10-08T12:0{index}:00Z", "requestId": f"original-request-{index}"}))
               for index in range(2)]
    baseline = exchange(name="baseline", body='{"error":"not entitled","requestId":"original-baseline"}')
    fixture = audit(cases, [receipt(case, record) for case, record in zip(cases, records, strict=True)], baseline)
    result = node(r"""
const before = JSON.stringify(input);
const view = NamazuAuditResultsView.render(input);
const groups = byClass(view, 'test-response-group');
const links = byClass(groups[0], 'case-evidence-links').flatMap(node => byTag(node, 'a')).filter(link => !link.className.includes('compare-request-link'));
const evidence = links.map(link => {
  const event = link.fire('click');
  const target = all(view, node => node.id === link.href.slice(1))[0];
  return {label:link.textContent, opened:target.open, prevented:event.prevented, scrolled:target.scrolled,
    text:target.textContent, id:target.id};
});
process.stdout.write(JSON.stringify({text:view.textContent,groups:groups.length,
  rows:byTag(groups[0],'tbody')[0].children.length,evidence,unchanged:before===JSON.stringify(input)}));
""", fixture)
    assert result["groups"] == 1
    assert result["rows"] == 2
    assert "POST /widgets" in result["text"]
    assert "Same denial as baseline; downstream handling unknown" in result["text"]
    assert result["unchanged"]
    assert len({item["id"] for item in result["evidence"]}) == 4
    for record in result["evidence"]:
        assert record["opened"] and record["prevented"] and record["scrolled"]
        assert "Authorization: <credential>" in record["text"]
        assert "HTTP 403" in record["text"]
        assert "a deliberately shorter excerpt" not in record["text"]
        assert "Original captured values" in record["text"]
    assert records[0]["response_body"] in result["evidence"][0]["text"]
    assert baseline["response_body"] in result["evidence"][1]["text"]
    assert records[1]["response_body"] in result["evidence"][2]["text"]


def test_large_case_groups_are_lazy_paged_and_keep_exact_evidence_links():
    plans = [planned(f"case-{index}", mutation=f"mutation-{index}") for index in range(1200)]
    data = audit(plans, [receipt(plan, exchange(name=plan["id"])) for plan in plans])
    result = node(r"""
const before=JSON.stringify(input);
const view=NamazuAuditResultsView.render(input);
const initialRows=byTag(view,'tbody').length;
const group=byClass(view,'test-response-group')[0];group.open=true;group.fire('toggle');
const firstPage=byTag(group,'tbody')[0].children.length;
const more=byClass(group,'case-page-more')[0];more.fire('click');
const secondPage=byTag(group,'tbody')[0].children.length;
while(!more.hidden) more.fire('click');
const lastRow=byTag(group,'tbody')[0].lastElementChild;
byClass(lastRow,'case-evidence-links')[0].children[0].fire('click');
const rerender=NamazuAuditResultsView.render(input);
process.stdout.write(JSON.stringify({initialRows,firstPage,secondPage,total:byTag(group,'tbody')[0].children.length,
 last:lastRow.dataset.caseId, evidence:byClass(group,'case-evidence').filter(node=>node.open).map(node=>node.textContent),
 restored:byTag(rerender,'tbody')[0].children.length,unchanged:before===JSON.stringify(input)}));
""", data)
    assert result["initialRows"] == 0
    assert (result["firstPage"], result["secondPage"], result["total"], result["restored"]) == (100, 200, 1200, 1200)
    assert result["last"] == "case-1200"
    assert result["unchanged"] and result["evidence"]
    assert "Original captured values" in result["evidence"][0]


def test_plans_skips_errors_and_missing_receipts_stay_distinct_in_rendered_counts():
    plans = [planned(str(index), mutation=f"mutation-{index}") for index in range(6)]
    receipts = [receipt(plans[0], exchange()), receipt(plans[1], exchange()),
                receipt(plans[2], status="blocked-prerequisite", reason_code="positive-control-required",
                        missing_prerequisites=["successful-positive-control", "second-identity"]),
                receipt(plans[3], status="budget-exhausted", reason_code="request-budget-exhausted"),
                receipt(plans[4], exchange(status=0, error="local mock timeout"), status="execution-error")]
    fixture = audit(plans, receipts)
    result = node(r"""
const view = NamazuAuditResultsView.render(input);
process.stdout.write(JSON.stringify({text:view.textContent,
  summary:byClass(view,'test-coverage-summary')[0].textContent,
  cases:byTag(view,'tbody').flatMap(node=>node.children).map(row=>row.dataset.caseId)}));
""", fixture)
    assert "6 planned" in result["summary"]
    assert "2 executed" in result["summary"]
    assert "2 skipped" in result["summary"]
    assert "1 execution errors" in result["summary"]
    assert "1 missing receipts" in result["summary"]
    assert "successful-positive-control" in result["summary"]
    assert "second-identity" in result["summary"]
    assert "request-budget-exhausted" in result["summary"]
    assert len(result["cases"]) == len(set(result["cases"])) == 6
    assert "No request / response recorded" in result["text"]
    assert "No request was sent for this case" in result["text"]


def test_nested_saved_exchanges_display_same_original_values_used_for_comparison():
    nested = {"request": {"method": "POST", "url": "http://127.0.0.1:9876/widgets",
                          "headers": {"Authorization": "<credential>"}, "body": '{"enabled":null}'},
              "response": {"status": 403, "headers": {"X-Request-Id": "nested-original"},
                           "body": '{"error":"not entitled","requestId":"nested-body-original"}'}}
    case = planned("nested")
    result = node(r"""
const view = NamazuAuditResultsView.render(input);
const link = byTag(view,'a')[0]; link.fire('click');
const target = all(view,node=>node.id===link.href.slice(1))[0];
process.stdout.write(JSON.stringify({text:target.textContent,row:byTag(view,'tbody')[0].textContent}));
""", audit([case], [receipt(case, nested)], nested))
    assert "POST http://127.0.0.1:9876/widgets" in result["text"]
    assert "Authorization: <credential>" in result["text"]
    assert '{"enabled":null}' in result["text"]
    assert "HTTP 403" in result["text"] and "HTTP 403" in result["row"]
    assert "X-Request-Id: nested-original" in result["text"]
    assert "nested-body-original" in result["text"]
    assert "excerpt only" not in result["text"]


def test_evidence_display_uses_the_same_response_precedence_as_comparison():
    captured = exchange(body='{"error":"flat-original"}')
    captured["response"] = {"status": 500, "body": '{"error":"nested-other"}',
                            "headers": {"X-Nested": "other"}}
    result = node(r"""
process.stdout.write(JSON.stringify({comparison:NamazuAuditResults.canonicalResponse(input),
  text:NamazuAuditResultsView.exchangeText(input,true)}));
""", captured)
    assert result["comparison"]["status"] == 403
    assert "HTTP 403" in result["text"]
    assert "flat-original" in result["text"]
    assert "HTTP 500" not in result["text"]
    assert "nested-other" not in result["text"]


@pytest.mark.parametrize("truncated,warning", [
    (False, "excerpt only"),
    (True, "Response capture was truncated"),
])
def test_incomplete_evidence_displays_its_limit_without_claiming_equivalence(truncated, warning):
    captured = exchange(truncated=truncated)
    captured.pop("response_body")
    plan = planned("excerpt")
    result = node(r"""
const view = NamazuAuditResultsView.render(input);
byTag(view,'a')[0].fire('click');
process.stdout.write(JSON.stringify({text:view.textContent,groups:byClass(view,'test-response-group').length}));
""", audit([plan], [receipt(plan, captured)]))
    assert warning in result["text"]
    assert "Comparison unavailable" in result["text"]
    assert "a deliberately shorter excerpt" in result["text"]
    assert "Same denial as baseline" not in result["text"]


def test_aggregate_only_coverage_exposes_missing_individual_receipts():
    fixture = audit()
    fixture["fieldCoverage"] = [{"operation": "POST /widgets", "field_pointer": "/enabled",
                                 "location": "body", "planned_requests": 5, "requests_sent": 5}]
    result = node(r"""
const view = NamazuAuditResultsView.render(input);
process.stdout.write(JSON.stringify({text:view.textContent,rows:byTag(view,'tbody').length}));
""", fixture)
    assert "individual" in result["text"].lower()
    assert "not recorded" in result["text"].lower() or "missing" in result["text"].lower()
    assert result["rows"] == 0
    assert "5 executed" not in result["text"]


def test_empty_results_and_existing_findings_do_not_manufacture_test_cases():
    fixture = audit()
    fixture["findings"] = [{"title": "Existing specification observation", "id": "spec.real"}]
    result = node(r"""
const before = JSON.stringify(input);
const view = NamazuAuditResultsView.render(input);
process.stdout.write(JSON.stringify({text:view.textContent,rows:byTag(view,'tbody').length,
  unchanged:JSON.stringify(input)===before}));
""", fixture)
    assert result["rows"] == 0 and result["unchanged"]
    assert "0 executed" in result["text"]
    assert "Existing specification observation" not in result["text"]
    assert "No blocker reasons were recorded. This does not establish complete coverage" in result["text"]


TRAFFIC_HARNESS = r"""
const nodes = new Map(); function $(id) {if (!nodes.has(id)) nodes.set(id,new Element('div')); return nodes.get(id);}
function el(tag,cls,text) {const element = new Element(tag); element.className = cls || '';
  if(text!==undefined) element.textContent = text; return element;}
function paneTabs() {return 'pretty';} function prettyBody(value) {return value;}
function markedInto(node,value) {node.textContent=value;return node;} function bodyHighlights() {return [];}
function pill(text) {return el('span','',text);} function statusKind() {return '';}
function humanBytes(value) {return String(value);} const STATUS_TEXT={403:'Forbidden'};
const RESPONSE_TABS = [];
"""


@pytest.mark.parametrize("body,excerpt,expected", [
    ("full response ending in meaningful-tail", "short excerpt", "full response ending in meaningful-tail"),
    (None, "legacy excerpt", "legacy excerpt"),
    ("", "stale excerpt", "The response has an empty body."),
])
def test_traffic_response_display_prefers_complete_capture_and_falls_back_only_when_absent(body, excerpt, expected):
    entry = exchange(body=body)
    entry["body_excerpt"] = excerpt
    entry["body_length"] = 99
    script = TRAFFIC_HARNESS + "\n".join(function(name) for name in (
        "headerCase", "headerTable", "rawResponse", "bodyNote", "renderResponsePane"))
    result = node(script + r"""
renderResponsePane(input);
process.stdout.write(JSON.stringify({raw:rawResponse(input),pretty:$('log-response-body').textContent,note:bodyNote(input)}));
""", entry)
    assert expected in result["pretty"]
    assert (body if body is not None else excerpt) in result["raw"]
    if body is not None:
        assert excerpt not in result["raw"]
        assert excerpt not in result["pretty"]


EXPORT_HARNESS = r"""
const state = {spec:{title:'Different current document',version:'current-v2'},audit:input};
globalThis.window = {NamazuAuditResults}; const EVIDENCE_LEVELS={};
const SEVERITIES = ['critical','high','medium','low','info'];
function $(id) {throw new Error('Export must not read current UI controls: '+id);}
function auditProfile() {throw new Error('Export must not read current profile');}
function identityB() {throw new Error('Export must not read current identity');}
function redactUrl(value) {return value;}
function coverageState() {return 'blocked';}
""" + "\n".join(function(name) for name in ("assessmentOf", "isVulnerability", "severityTally",
                                                "categoryTally", "verificationTally", "auditNotes", "auditExportPayload"))


@pytest.mark.parametrize("context", [
    {"title": "Saved local fixture", "version": "saved-v1", "base_url": "http://127.0.0.1:9876",
     "profile": "writes", "second_identity": False},
    None,
])
def test_export_uses_recorded_run_context_and_never_current_ui_controls(context):
    fixture = audit()
    fixture.update({"context": context, "done": 1, "total": 1, "notes": [], "coverage": {},
                    "replays": {}, "logTruncated": False, "correlation": None})
    result = node(EXPORT_HARNESS + "process.stdout.write(JSON.stringify(auditExportPayload()));", fixture)
    assert result["api"] == {"title": context["title"] if context else None,
                             "version": context["version"] if context else None,
                             "base_url": context["base_url"] if context else None}
    assert result["scope"]["profile"] == (context["profile"] if context else None)
    assert result["scope"]["second_identity"] is (False if context else None)


def test_export_counts_demonstrated_vulnerabilities_separately_without_dropping_legacy_records():
    fixture = audit()
    fixture.update({"context": {}, "done": 1, "total": 1, "notes": [], "coverage": {},
                    "replays": {}, "logTruncated": False, "correlation": None})
    fixture["findings"] = [
        {"id": name, "severity": severity, "confidence": "confirmed", "assessment": {
            "category": "security", "origin": origin, "verification": verification}}
        for name, severity, origin, verification in [
            ("static", "low", "static-declaration", "unverified"),
            ("observed", "high", "runtime-observation", "observed"),
            ("replayed", "high", "runtime-observation", "reproduced"),
            ("impact", "high", "runtime-observation", "impact-demonstrated"),
            ("external", "critical", "external-report", "impact-demonstrated"),
        ]]
    result = node(EXPORT_HARNESS + "process.stdout.write(JSON.stringify(auditExportPayload()));", fixture)
    summary = result["summary"]
    assert summary["total"] == 5
    assert summary["severity"] == {"critical": 1, "high": 3, "medium": 0, "low": 1, "info": 0}
    assert summary["demonstrated_vulnerabilities"] == 1
    assert summary["observations_and_leads"] == 4
    assert summary["demonstrated_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
    assert "Legacy total and severity include all finding and observation records" in summary["note"]
    assert result["findings"] == fixture["findings"]


def test_report_puts_receipt_coverage_before_security_counts_and_keeps_observations_separate():
    fixture = audit()
    fixture.update({"done": 1, "total": 1, "notes": [], "coverage": {}, "correlation": None,
                    "context": {"profile": "writes", "second_identity": False}})
    fixture["findings"] = [
        {"title": "Static declaration", "confidence": "confirmed", "severity": "low",
         "assessment": {"category": "security", "origin": "static-declaration", "verification": "unverified"}},
        {"title": "Response difference", "confidence": "confirmed", "severity": "high",
         "assessment": {"category": "security", "origin": "runtime-observation", "verification": "observed"}},
    ]
    script = TRAFFIC_HARNESS + r"""
globalThis.window = {NamazuAuditResultsView};
const state = {audit:input}; const SEVERITIES = ['critical','high','medium','low','info'];
function auditHasReport() {return true;} function testPlanCard() {return null;}
function runDiagnostics() {return null;} function requestBreakdownCard() {return null;}
function baselineCard() {return null;} function coverageCard() {return null;}
function runProvenanceCard() {return el('section','run-provenance','Recorded run context');}
function setupAction() {throw new Error('Rendering must not activate an action');}
function reportCard(title,children) {const card = el('section','card',title); card.append(...children); return card;}
""" + "\n".join(function(name) for name in (
        "assessmentOf", "isVulnerability", "severityTally", "auditNotes", "renderAuditReport"))
    result = node(script + r"""
$('view-audit-report').scrollTop=314;
renderAuditReport();
const body = $('audit-report-body');
process.stdout.write(JSON.stringify({first:body.firstElementChild.textContent,text:body.textContent,
  scroll:$('view-audit-report').scrollTop,tallies:byClass(body,'tally').length}));
""", fixture)
    assert result["first"] == "Recorded run context"
    assert result["text"].index("Coverage and blockers") < result["text"].index("Security findings and observations")
    assert result["scroll"] == 314
    assert "0 records demonstrate security impact; 2 other records" in result["text"]
    assert "Test receipts do not create findings" in result["text"]
    assert "No security impact was demonstrated" in result["text"]
    assert result["tallies"] == 0


def test_metadata_policy_is_configurable_offline_and_cannot_hide_security_headers():
    result = node(r"""
let selected = null;
const view = NamazuAuditResultsView.render(input, {onPolicyChange(policy) {selected = policy;}});
const editor = byTag(view, 'textarea')[0];
const button = byTag(view, 'button').find(item => item.textContent === 'Reclassify saved evidence');
editor.value = 'date, fm-correlation-id, x-iinfo'; button.fire('click');
const supported = selected; selected = null;
editor.value = 'set-cookie'; button.fire('click');
process.stdout.write(JSON.stringify({supported, rejected:selected === null, text:view.textContent}));
""", audit())
    assert result["supported"] == {"metadata_headers": ["date", "fm-correlation-id", "x-iinfo"]}
    assert result["rejected"] is True
    assert "exact supported" in result["text"]
    assert "sends no target requests" in result["text"]


def test_validation_and_edge_block_labels_are_observations_and_timeouts_incomplete():
    fixture = json.loads(Path("tests/fixtures/response_classification_export.json").read_text(encoding="utf-8"))
    plans = [planned("validation", pointer="/documentUri"), planned("edge"), planned("timeout"), planned("security")]
    records = [fixture["validation"], fixture["edge_block"], fixture["timeout"], fixture["security_header_change"]]
    data = audit(plans, [receipt(plan, record, status="execution-error" if record.get("error")
                                else "field-specific-response-observed", reason_code="field-response-difference-lead")
                        for plan, record in zip(plans, records, strict=True)], fixture["baseline"])
    result = node("const view=NamazuAuditResultsView.render(input);process.stdout.write(JSON.stringify(view.textContent));", data)
    assert "Validation rejected this input" in result
    assert "Blocked at the edge" in result
    assert "No response before timeout" in result
    assert "incomplete test" in result
    assert "Original receipt reason: field-response-difference-lead" in result
    assert "Meaningful header changes:" in result


def test_request_comparison_shows_one_changed_field_and_preserves_redacted_baseline():
    plan = planned("omit", mutation="omission")
    baseline = exchange(name="baseline", request_body='{"enabled":true,"documentUri":"local-report"}')
    changed = exchange(request_body='{"documentUri":"local-report"}')
    result = node(r"""
const before=JSON.stringify(input);
const view=NamazuAuditResultsView.render(input);
const link=byClass(view,'compare-request-link')[0];link.fire('click');
const target=all(view,node=>node.id===link.href.slice(1))[0];
process.stdout.write(JSON.stringify({text:target.textContent,
 values:byClass(target,'mutation-value').map(node=>node.textContent),
 changes:byTag(target,'mark').map(node=>node.textContent),
 unchanged:JSON.stringify(input)===before}));
""", audit([plan], [receipt(plan, changed)], baseline))
    assert "Saved baseline request" in result["text"]
    assert "Changed request" in result["text"]
    assert "Selected input: body /enabled" in result["text"]
    assert "true" in result["values"][0]
    assert "Field omitted" in result["values"][1]
    assert "Authorization: <credential>" in result["text"]
    assert all("Authorization" not in line for line in result["changes"])
    assert all("documentUri" in line for line in result["changes"])
    assert result["unchanged"]


def test_pointer_comparison_preserves_null_false_zero_and_escaped_keys():
    result = node(r"""
const values=[null,false,0].map(value=>NamazuAuditResultsView.inputValue(
 {request_body:JSON.stringify({'a/b':{'~key':value}})}, {location:'body',pointer:'/a~1b/~0key'}));
const missing=NamazuAuditResultsView.inputValue({request_body:'{}'},{location:'body',pointer:'/enabled'});
process.stdout.write(JSON.stringify({values,missing}));
""")
    assert result["values"] == [{"present": True, "value": value} for value in [None, False, 0]]
    assert result["missing"] == {"present": False}


def test_expanded_field_and_exact_evidence_survive_reclassification_render():
    plan = planned("null")
    fixture = audit([plan], [receipt(plan, exchange())])
    fixture["startedAt"] = "local-run-one"
    result = node(r"""
const first=NamazuAuditResultsView.render(input);
const field=byClass(first,'test-field')[0];field.open=true;field.fire('toggle');
const link=byClass(first,'case-evidence-links')[0].children[0];link.fire('click');
const comparison=byClass(first,'compare-request-link')[0];comparison.fire('click');
const second=NamazuAuditResultsView.render(input);
const other=NamazuAuditResultsView.render({...input,startedAt:'local-run-two'});
process.stdout.write(JSON.stringify({field:byClass(second,'test-field')[0].open,
 evidence:all(second,node=>node.id===link.href.slice(1))[0].open,
 evidenceText:all(second,node=>node.id===link.href.slice(1))[0].textContent,
 comparison:all(second,node=>node.id===comparison.href.slice(1))[0].open,
 otherField:byClass(other,'test-field')[0].open}));
""", fixture)
    assert result["field"] and result["evidence"] and result["comparison"]
    assert "HTTP 403" in result["evidenceText"]
    assert result["otherField"] is False


def test_blocker_actions_are_explicit_and_not_applicable_checks_do_not_request_setup():
    plans = [planned("identity"), planned("budget"), planned("get-only")]
    records = [receipt(plans[0], status="blocked-prerequisite", reason_code="missing-second-identity",
                       missing_prerequisites=["distinct-second-identity"]),
               receipt(plans[1], status="budget-exhausted", reason_code="request-budget-exhausted"),
               receipt(plans[2], status="not-applicable", reason_code="probe-not-applicable")]
    result = node(r"""
const before=JSON.stringify(input),actions=[];
const view=NamazuAuditResultsView.render(input,{onAction(action){actions.push(action);}});
const beforeClicks=actions.length;
const rows=byTag(view,'tbody').flatMap(body=>body.children);
const buttons=rows.flatMap(row=>byTag(row,'button'));
buttons.forEach(button=>button.fire('click'));
const notApplicable=rows.find(row=>row.textContent.includes('Does not apply'));
process.stdout.write(JSON.stringify({beforeClicks,actions,
 notApplicableActions:byTag(notApplicable,'button').length,unchanged:before===JSON.stringify(input)}));
""", audit(plans, records))
    assert result["beforeClicks"] == 0
    assert {action["kind"] for action in result["actions"]} == {"configure-permissions", "prepare-replay"}
    assert result["notApplicableActions"] == 0
    assert result["unchanged"]


def test_timeout_and_other_execution_failures_have_different_plain_labels():
    result = node(r"""
process.stdout.write(JSON.stringify([
 NamazuAuditResultsView.responseLabel({error:'ReadTimeout: local fixture'}),
 NamazuAuditResultsView.responseLabel({response:{error:'Connection refused'}}),
 NamazuAuditResultsView.responseLabel({status:403})]));
""")
    assert result == ["No response before timeout", "Request did not complete", "HTTP 403"]


def test_method_applicability_does_not_send_user_to_identity_or_evidence_setup():
    result = node(r"""
process.stdout.write(JSON.stringify(['GET method','read-only-method'].map(reason=>NamazuAuditResultsView.blockerAction(reason))));
""")
    assert result == [None, None]


def test_original_capture_json_retains_diagnostic_values_and_expansion():
    plan = planned("metadata")
    original = exchange()
    original["response_headers"]["fm-correlation-id"] = "original-correlation-value"
    original["response_headers"]["Date"] = "Fri, 09 Oct 2026 08:20:43 GMT"
    original["elapsed_ms"] = 125
    result = node(r"""
const view=NamazuAuditResultsView.render(input);
byClass(view,'case-evidence-links')[0].children[0].fire('click');
const raw=byClass(view,'case-original-record')[0];raw.open=true;raw.fire('toggle');
const rerender=NamazuAuditResultsView.render(input);
const retained=byClass(rerender,'case-original-record')[0];
process.stdout.write(JSON.stringify({text:retained.textContent,open:retained.open}));
""", audit([plan], [receipt(plan, original)]))
    assert result["open"]
    assert "original-correlation-value" in result["text"]
    assert "Fri, 09 Oct 2026 08:20:43 GMT" in result["text"]
    assert '"elapsed_ms": 125' in result["text"]
