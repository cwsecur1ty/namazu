"""Execute the audit UI's plan, coverage and export logic without a live target."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SOURCE = Path("namazu/static/app.js").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(r"  (?:async )?function " + name + r"\([^\n]*\) \{.*?^  \}",
                      SOURCE, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group(0)


def constant(name: str) -> str:
    match = re.search(r"  const " + name + r" = \{.*?^  \};", SOURCE,
                      re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group(0)


def node(script: str):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    result = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


RUN_HARNESS = r"""
const events = [];
const state = {busy: false, spec: {}, audit: {running: false},
  examples: {a: {example: {body: {enabled: true}}, expectation: {status: '403', negative: true}}}};
const PROFILE_BUDGET = {passive:1, readonly:90, thorough:160, writes:220};
const PROFILE_CONCURRENCY = {passive:1, readonly:4, thorough:6, writes:4};
const SAFE_METHODS = new Set(['GET','HEAD','OPTIONS']);
const operations = [{id:'a', method:'POST', path:'/a'}, {id:'b', method:'POST', path:'/b'}];
const connection = {base_url:'http://127.0.0.1:9876',headers:{},allow_mutating:true};
let profile = 'writes';
const nodes = new Map();
function $(id) {
  if (!nodes.has(id)) nodes.set(id, {checked: id === 'audit-inventory' || id === 'allow-writes',
    value: id === 'audit-budget' ? '150' : id === 'audit-rate' ? '2' : ''});
  return nodes.get(id);
}
function message() {} function toast(value) {events.push(['toast',value]);} function activateSection() {} function showView() {}
function setBusy(value) {state.busy = value;} function renderFindings() {} function renderLog() {}
function renderRunContext() {}
function auditProgress() {} function announce(value) {events.push(['announce',value]);} function updateProfileNote() {}
function absorb(result) {state.audit.requests += result.requests_sent || 0; state.audit.findings.push(...(result.findings || []));}
function absorbLog(result) {state.audit.log.push(...(result.log || []));}
async function runQueuedTools() {events.push(['queued-tools']);}
function renderAuditReport() { events.push(['render', state.audit.plans.length]); }
function requestAnimationFrame(callback) { events.push(['paint', state.audit.plans.length]); callback(); }
function setTimeout(callback, milliseconds) {events.push(['pace-wait',milliseconds]);callback();}
function auditProfile() { return profile; }
function connectionPayload() { return connection; }
function auditScope() { return operations; }
function renewableIdentity(value) { return value; } function identityB() { return {}; }
function routePayload() { return {}; } function auditConcurrency() { return 1; }
function errorText(error) { return error.message; }
function redactUrl(value) {return value;}
"""


def execution_functions():
    return "\n".join(function(name) for name in (
        "auditLimits", "auditFingerprint", "showAuditReview", "runAudit", "executeReviewedAudit",
        "buildRunConfig", "ingestRunSnapshot", "pollRun", "finishRunView"))


def test_all_plans_are_shown_then_one_reviewed_run_is_handed_to_the_server():
    result = node(RUN_HARNESS + execution_functions() + r"""
let runConfig = null;
async function api(route, payload, method) {
  events.push([route, method || 'POST']);
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') { runConfig = payload; return {run_id:'r1', revision:1, active:true, total:2, done:0, requests_sent:0, cases:[]}; }
  return {run_id:'r1', revision:2, active:false, status:'finished', run_status:'finished', total:2, done:2, requests_sent:0, cases:[]};
}
async function exercise() {
  await runAudit();
  const before = events.slice();
  $('audit-write-consent').checked = true;
  await executeReviewedAudit();
  process.stdout.write(JSON.stringify({before, events, runConfig, status: state.audit.runStatus}));
}
exercise();
""")
    # Planning is local, one request per operation; nothing is sent to a target.
    assert [event[0] for event in result["before"] if event[0].startswith("/api/")] == [
        "/api/audit/plan", "/api/audit/plan"]
    assert ["render", 2] in result["before"]
    # Execution hands ONE reviewed run to the server, then polls it. There is no
    # per-operation target call from the browser any more.
    routes = [event[0] for event in result["events"] if event[0].startswith("/api/")]
    assert routes[:2] == ["/api/audit/plan", "/api/audit/plan"]
    assert "/api/runs" in routes and "/api/runs/r1" in routes
    assert "/api/audit" not in routes and "/api/audit/inventory" not in routes
    cfg = result["runConfig"]
    assert [op["operation_id"] for op in cfg["operations"]] == ["a", "b"]
    # The reviewed example and expectation for operation "a" travel in the run.
    assert cfg["operations"][0]["example"] == {"body": {"enabled": True}}
    assert cfg["operations"][0]["expectation"] == {"status": "403", "negative": True}
    assert cfg["inventory"] is True
    assert result["status"] == "finished"


def test_failed_plan_is_absent_from_the_reviewed_run():
    result = node(RUN_HARNESS + execution_functions() + r"""
let runConfig = null;
async function api(route, payload, method) {
  events.push([route, payload && payload.operation_id]);
  if (route.endsWith('/plan') && payload.operation_id === 'a') throw new Error('invalid schema');
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') { runConfig = payload; return {run_id:'r1', revision:1, active:true, total:1, done:0, requests_sent:0, cases:[]}; }
  return {run_id:'r1', revision:2, active:false, status:'finished', run_status:'finished', total:1, done:1, requests_sent:0, cases:[]};
}
async function exercise() {
  await runAudit(); $('audit-write-consent').checked = true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({runConfig, notes:state.audit.notes}));
}
exercise();
""")
    # The operation whose plan failed is simply not in the run the server is given.
    assert result["runConfig"] is not None
    assert [op["operation_id"] for op in result["runConfig"]["operations"]] == ["b"]
    assert any("planning failed; endpoint skipped" in reason for reason in result["notes"])


def test_coverage_export_keeps_zero_finding_denials_and_exact_redacted_exchanges():
    script = r"""
const state = {spec: {title:'Local mock'}, audit: {
  total:1, done:1, requests:53, findings:[], notes:[], coverage:{}, baselines:[],
  fieldCoverage:[{operation:'POST /test',field_pointer:'/body/enabled',requests_sent:3,
    outcomes:{'same-denial':3}}],
  probes:[{field_pointer:'/body/enabled',mutation:'null',request_sent:true,status:'same-denial',
    reason_code:'same-denial-as-baseline'}],
  plans:[{endpoint:'POST /test',request_budget:60,test_plan:{probes:[]}}],
  requestBreakdown:{inventory:50,baseline:1,schema_inputs:2,other_endpoint_tests:0},
  log:[{key:'1',request:{method:'POST',headers:{Authorization:'<redacted>'},
    body:'{"enabled":null}'},response:{status:403,body:'denied'}}], logTruncated:false,
  replays:{},correlation:null,inventoryPlanned:true}};
function $(id) { return {value:'http://127.0.0.1:9876'}; }
function redactUrl(value) {return value;} function auditProfile() {return 'writes';}
function identityB() {return {};} function severityTally() {return {};}
function categoryTally() {return {};} function verificationTally() {return {};}
function assessmentOf(item) {return item.assessment || {};}
function coverageState() {return 'blocked';} const EVIDENCE_LEVELS = {};
"""
    result = node(script + function("isVulnerability") + function("auditNotes") + function("auditHasReport") + function("auditExportPayload") +
                  "process.stdout.write(JSON.stringify({exportable:auditHasReport(),payload:auditExportPayload()}));")
    assert result["exportable"] is True
    payload = result["payload"]
    assert payload["findings"] == []
    assert payload["scope"]["request_breakdown"] == {
        "inventory": 50, "baseline": 1, "schema_inputs": 2, "other_endpoint_tests": 0}
    assert payload["coverage"]["fields"][0]["outcomes"] == {"same-denial": 3}
    assert payload["coverage"]["probes"][0]["request_sent"] is True
    assert payload["test_plans"][0]["request_budget"] == 60
    assert payload["requests"][0]["request"]["body"] == '{"enabled":null}'
    assert payload["requests"][0]["request"]["headers"]["Authorization"] == "<redacted>"
    assert "key" not in payload["requests"][0]
    assert "downstream validation unknown" in payload["coverage"]["note"]


def test_field_coverage_renders_all_distinct_probe_outcomes_without_success_claims():
    script = r"""
const state = {audit:{fieldCoverage:[
  {operation:'POST /test',field_pointer:'/body/enabled',location:'body',category:'writable-input',
    planned_requests:3,requests_sent:2,status_counts:{'same-denial-as-baseline':2,'budget-exhausted':1},
    reason_codes:['downstream-handling-unknown','request-budget-exhausted'],missing_prerequisites:[]},
  {operation:'POST /test',field_pointer:'/body/serverId',category:'read-only-negative',
    planned_requests:1,requests_sent:1,status_counts:{'field-specific-response-observed':1},
    reason_codes:['field-response-difference-lead'],missing_prerequisites:[]}
], probes:[
  {field_pointer:'/body/enabled',mutation:'null',status:'same-denial',request_sent:true},
  {field_pointer:'/body/count',mutation:'maximum-plus-one',status:'field-specific-response',request_sent:true},
  {field_pointer:'/body/title',mutation:'wrong-type',status:'execution-error',reason_code:'connection-error'},
  {field_pointer:'/body/title',mutation:'empty',status:'budget-exhausted',reason_code:'request-budget-exhausted'},
  {field_pointer:'/body/id',mutation:'identity-replay',status:'blocked-prerequisite',missing_prerequisites:['second identity','positive baseline']},
]}};
function stringify(value) {return JSON.stringify(value);}
function el(tag, cls, value) {
  return {tag, text:value ?? '', children:[], append(...nodes) {this.children.push(...nodes);}};
}
"""
    helpers = ["probeStatus", "reportTable", "prerequisiteText", "fieldCoverageCard"]
    result = node(script + constant("PROBE_STATUS_LABEL") + "\n".join(function(name) for name in helpers) +
                  "process.stdout.write(JSON.stringify(fieldCoverageCard()));")
    text = json.dumps(result)
    for expected in ["Same denial as baseline; downstream handling unknown",
                     "Field-specific response observed (lead)", "Execution error", "Budget exhausted",
                     "Blocked prerequisite", "second identity; positive baseline", "/body/enabled",
                     "read-only-negative", "downstream-handling-unknown", "/body/serverId"]:
        assert expected in text


def test_negative_expectation_help_does_not_claim_to_unlock_positive_controls():
    markup = Path("namazu/static/index.html").read_text(encoding="utf-8")
    assert "does not unlock checks that require a successful positive control" in markup


def test_plan_separates_schema_budget_from_conditional_request_upper_bounds():
    script = r"""
const state = {audit:{plans:[{endpoint:'POST /test',request_budget:20,test_plan:{
  baseline_requests:1,budget:19,planned_requests:100,budgeted_requests:19,
  probes:[{field_pointer:'/body/count',mutation:'minimum-below',planned_requests:1,status:'planned'}],
  supplemental_probes:[{operation:'POST /test',field_pointer:'/body/title',mutation:'crlf',
    prerequisite:'Paired controls',planned_requests:2,conditional:true,request_count_kind:'upper-bound'}],
  supplemental_checks:[{title:'Authorization',prerequisite:'Successful positive control; second identity',
    planned_requests:null,conditional:true}]
}}]}};
function stringify(value) {return JSON.stringify(value);}
function el(tag, cls, value) {
  return {tag, text:value ?? '', children:[], append(...nodes) {this.children.push(...nodes);}};
}
"""
    helpers = ["probeStatus", "reportTable", "prerequisiteText", "budgetText",
               "plannedRequestCount", "planProbeRows", "testPlanCard"]
    result = node(script + constant("PROBE_STATUS_LABEL") + "\n".join(function(name) for name in helpers)
                  + "process.stdout.write(JSON.stringify(testPlanCard()));")
    text = json.dumps(result)
    assert "100 eligible schema cases; up to 19 schema requests within budget" in text
    assert "Up to 2 (conditional)" in text
    assert "Conditional; shared remaining budget" in text
    assert "/body/title" in text and "crlf" in text and "Authorization" in text
    assert "Successful positive control; second identity" in text
    assert "not added to a promised request total" in text


def test_operation_results_preserve_pre_execution_plan_and_all_prerequisite_reasons():
    result = node(r"""
const state = {audit:{plans:[{endpoint:'POST /test',test_plan:{supplemental_checks:[{check:'authorization'}]}}],
  fieldCoverage:[],probes:[],baselines:[],coverage:{}}};
function prerequisiteText(value) {return value;}
""" + function("absorbCoverage") + r"""
absorbCoverage({endpoint:'POST /test',test_plan:{probes:[]},
  field_coverage:[{field_pointer:'/enabled',status_counts:{'same-denial-as-baseline':3}}],
  coverage:{checks:[{check:'cross-identity',state:'blocked',requests:0,
    missing_prerequisites:['successful-positive-control','second-identity'],
    reason_codes:['positive-control-required','identity-b-required']}]}
},'POST /test');
process.stdout.write(JSON.stringify(state.audit));
""")
    assert result["plans"][0]["test_plan"]["supplemental_checks"] == [{"check": "authorization"}]
    assert result["fieldCoverage"][0]["status_counts"] == {"same-denial-as-baseline": 3}
    check = result["coverage"]["cross-identity"]
    assert check["requests"] == 0
    assert check["states"] == {"blocked": 1}
    assert check["missingPrerequisites"] == ["successful-positive-control", "second-identity"]
    assert check["reasonCodes"] == ["positive-control-required", "identity-b-required"]


def test_real_denied_operation_result_renders_and_exports_without_credentials():
    """Exercise browser consumers with a current engine result, entirely in memory."""
    import httpx

    from namazu.audit.engine import audit_operation, audit_plan
    from namazu.spec import parse_spec

    base = "http://127.0.0.1:9876"
    secret = "local-ui-fixture-credential-75913"
    parsed = parse_spec({
        "openapi": "3.1.0", "info": {"title": "Local UI fixture", "version": "1"},
        "servers": [{"url": base}], "paths": {"/widgets": {"post": {
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object", "properties": {
                    "enabled": {"type": "boolean"},
                    "quantity": {"type": "integer", "minimum": 1, "maximum": 5},
                },
            }}}}, "responses": {"403": {"description": "Denied"}},
        }}},
    })
    operation = parsed["operations"][0]
    options = {"base_url": base, "profile": "writes", "allow_mutating": True,
               "request_budget": 12, "identities": {"primary": {"Authorization": f"Bearer {secret}"}},
               "example": {"body": {"enabled": True, "quantity": 3, "password": secret}}}
    plan = audit_plan(parsed, operation["id"], **options)
    with httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(403, json={"detail": "Not entitled"}))) as client:
        result = audit_operation(parsed, operation["id"], client=client, **options)
    script = "const serverResult = " + json.dumps(result) + ";\nconst serverPlan = " + json.dumps(plan) + ";\n"
    script += r"""
const state = {spec:{title:'Local UI fixture'},audit:{
  total:1,done:1,requests:0,findings:[],notes:[],coverage:{},baselines:[],
  fieldCoverage:[],probes:[],plans:[serverPlan],requestBreakdown:{},log:[],
  replays:{},correlation:null}};
const MAX_LOG = 2000; const EVIDENCE_LEVELS = {};
const SEVERITIES = ['critical','high','medium','low','info'];
const COVERAGE_ORDER = ['execution-error','budget-exhausted','blocked','inconclusive','completed','skipped','not-applicable','attempted'];
function $(id) {return {value:'http://127.0.0.1:9876'};}
function stringify(value) {return JSON.stringify(value);}
function redactUrl(value) {return value;} function auditProfile() {return 'writes';}
function identityB() {return {};} function severityTally() {return {};}
function categoryTally() {return {};} function verificationTally() {return {};}
function assessmentOf(item) {return item.assessment || {};}
function el(tag, cls, value) {
  return {tag, text:value ?? '', children:[], append(...nodes) {this.children.push(...nodes);}};
}
"""
    helpers = ["probeStatus", "reportTable", "prerequisiteText", "budgetText",
               "plannedRequestCount", "planProbeRows", "testPlanCard", "fieldCoverageCard",
               "requestBreakdownCard", "absorbCoverage", "absorb", "absorbLog", "coverageState",
               "isVulnerability", "auditNotes", "auditExportPayload"]
    result = node(script + constant("PROBE_STATUS_LABEL") + "\n".join(function(name) for name in helpers) + r"""
absorb(serverResult,serverResult.endpoint); absorbLog(serverResult,serverResult.endpoint);
process.stdout.write(JSON.stringify({plan:testPlanCard(),fields:fieldCoverageCard(),
  breakdown:requestBreakdownCard(),export:auditExportPayload()}));
""")
    rendered = json.dumps(result)
    assert secret not in rendered
    assert "Same denial as baseline; downstream handling unknown" in rendered
    assert "Budget exhausted" in rendered
    assert "/enabled" in rendered and "/quantity" in rendered
    exported = result["export"]
    assert exported["scope"]["request_breakdown"]["baseline"] == 1
    assert exported["scope"]["request_breakdown"]["schema_inputs"] > 0
    assert exported["scope"]["request_breakdown"]["inventory"] == 0
    assert len(exported["requests"]) == exported["scope"]["requests_sent"] == 12
    assert exported["coverage"]["fields"]
    assert exported["test_plans"][0]["test_plan"]["supplemental_probes"]
