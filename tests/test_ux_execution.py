"""Exercise explicit review, run limits and interrupted UI state with local receipts."""
from __future__ import annotations

import pytest

from tests.test_frontend_campaign import (
    RUN_HARNESS,
    execution_functions,
    function,
    node,
)


def exercise(body):
    return node(RUN_HARNESS + execution_functions() + body)


@pytest.mark.parametrize("change", [
    "connection.base_url = 'http://127.0.0.1:9999';",
    "connection.headers.Authorization = 'Bearer another-local-fixture';",
    "state.examples.a.example.body.enabled = false;",
    "operations.pop();",
    "$('audit-budget').value = '20';",
    "$('audit-rate').value = '3';",
    "$('audit-inventory').checked = false;",
    "profile = 'readonly';",
    "$('tools-after-audit').checked = true;",
])
def test_changed_scope_credentials_inputs_or_limits_require_a_new_review(change):
    result = exercise(r"""
async function api(route, payload) {events.push([route,payload.operation_id]); return {test_plan:{probes:[]}};}
async function run() {
  await runAudit();
  $('audit-write-consent').checked = true;
""" + change + r"""
  await executeReviewedAudit();
  process.stdout.write(JSON.stringify({events,status:state.audit.runStatus,requests:state.audit.requests}));
}
run();
""")
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == [
        "/api/audit/plan", "/api/audit/plan"]
    assert any("Review a new audit plan" in event[1] for event in result["events"] if event[0] == "toast")
    assert result["status"] == "not-started" and result["requests"] == 0


def test_global_write_switch_is_insufficient_without_reviewed_scope_consent():
    result = exercise(r"""
async function api(route, payload) {events.push([route,payload.operation_id]); return {test_plan:{probes:[]}};}
async function run() {
  await runAudit();
  await executeReviewedAudit();
  process.stdout.write(JSON.stringify({events,consent:$('audit-write-consent').checked,requests:state.audit.requests}));
}
run();
""")
    assert result["consent"] is False
    assert result["requests"] == 0
    assert all(event[0] not in {"/api/audit", "/api/audit/inventory"} for event in result["events"])
    assert any("authorise this plan's target and operations" in event[1] for event in result["events"] if event[0] == "toast")


def test_new_plan_resets_write_consent_and_does_not_start_itself():
    result = exercise(r"""
async function api(route) {events.push([route]); return {test_plan:{probes:[]}};}
async function run() {
  await runAudit(); $('audit-write-consent').checked = true;
  await runAudit();
  process.stdout.write(JSON.stringify({events,consent:$('audit-write-consent').checked,status:state.audit.runStatus}));
}
run();
""")
    assert result["consent"] is False
    assert result["status"] == "not-started"
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/plan"] * 4


def test_setup_changed_during_asynchronous_planning_cannot_execute_the_old_payload():
    result = exercise(r"""
async function api(route, payload) {
  events.push([route,payload.operation_id]);
  if (route.endsWith('/plan') && payload.operation_id === 'a') connection.base_url = 'http://127.0.0.1:9999';
  return {test_plan:{probes:[]},requests_sent:0};
}
async function run() {
  await runAudit(); $('audit-write-consent').checked = true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({events,requests:state.audit.requests}));
}
run();
""")
    assert all(event[0] not in {"/api/audit", "/api/audit/inventory"} for event in result["events"])
    assert result["requests"] == 0
    announcements = [event[1] for event in result["events"] if event[0] == "announce"]
    assert any("No executable plan is available" in text for text in announcements)
    assert not any("Plan prepared locally" in text for text in announcements)


def test_stopping_planning_announces_no_executable_plan_and_no_target_traffic():
    result = exercise(r"""
async function api(route) {
  events.push([route]); state.audit.cancelled=true; return {test_plan:{probes:[]}};
}
runAudit().then(() => process.stdout.write(JSON.stringify({events,pending:Boolean(state.audit.pendingPlan)})));
""")
    assert not result["pending"]
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/plan"]
    announcements = [event[1] for event in result["events"] if event[0] == "announce"]
    assert any("Planning stopped. No target requests were sent" in text for text in announcements)
    assert not any("Plan prepared locally" in text for text in announcements)


def test_browser_hands_one_shared_budget_to_the_server_and_reflects_its_outcome():
    result = exercise(r"""
$('audit-budget').value = '65';
operations.push({id:'c',method:'POST',path:'/c'});
let runConfig = null;
async function api(route, payload, method) {
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') { runConfig = payload; return {run_id:'r1',revision:1,active:true,total:3,done:0,requests_sent:0,cases:[]}; }
  // The one shared budget of 65 was spent across the sweep and the operations
  // the server actually started; the third never ran. The browser does not
  // split or recompute this: it reflects what the server reports.
  return {run_id:'r1',revision:2,active:false,status:'incomplete',run_status:'incomplete',
          total:3, done:2, requests_sent:65,
          notes:['The run-wide request budget was exhausted. Remaining operations were not started.'],
          cases:[{case_id:'inventory',scope:'inventory',result:{requests_sent:50,log:[{status:403,response_body:'same application denial'}]}},
                 {case_id:'op-000',scope:'operation',result:{requests_sent:10,log:[{status:200}]}},
                 {case_id:'op-001',scope:'operation',result:{requests_sent:5,log:[{status:403}]}}]};
}
async function run() {
  await runAudit(); $('audit-write-consent').checked = true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({runConfig,requests:state.audit.requests,done:state.audit.done,
    status:state.audit.runStatus,notes:state.audit.notes,log:state.audit.log}));
}
run();
""")
    cfg = result["runConfig"]
    assert cfg["budget"] == 65 and cfg["inventory"] is True
    assert [op["operation_id"] for op in cfg["operations"]] == ["a", "b", "c"]
    assert result["requests"] == 65 and result["done"] == 2
    assert result["status"] == "incomplete"
    assert any("budget was exhausted" in note for note in result["notes"])
    assert len(result["log"]) == 3


def test_a_stopped_run_is_reflected_as_incomplete_with_partial_evidence_retained():
    result = exercise(r"""
$('audit-inventory').checked = false;
async function api(route, payload, method) {
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') return {run_id:'r1',revision:1,active:true,total:2,done:0,requests_sent:0,cases:[]};
  // The server stopped after the first operation; its evidence is kept and the
  // stop is reported as an incomplete run, not as a finished one.
  return {run_id:'r1',revision:2,active:false,status:'incomplete',run_status:'incomplete',
          cancelled:true, total:2, done:1, requests_sent:3,
          notes:['The run was stopped. No further operations were started; the evidence captured before the stop is retained.'],
          cases:[{case_id:'op-000',scope:'operation',result:{requests_sent:3,baseline_status:403,log:[{sequence:1,status:403,response_body:'denied'}]}}]};
}
async function run() {
  await runAudit(); $('audit-write-consent').checked = true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({audit:state.audit}));
}
run();
""")
    audit = result["audit"]
    assert audit["cancelled"] and not audit["running"]
    assert audit["runStatus"] == "incomplete"
    assert audit["done"] == 1 and audit["requests"] == 3
    assert audit["log"][0]["response_body"] == "denied"


def test_a_failed_operation_is_reflected_honestly_without_being_counted_clean():
    result = exercise(r"""
async function api(route, payload, method) {
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') return {run_id:'r1',revision:1,active:true,total:2,done:0,requests_sent:0,cases:[]};
  // The server could not audit one operation; it records an error case and an
  // incomplete run. The browser reflects that without inventing a clean result.
  return {run_id:'r1',revision:2,active:false,status:'incomplete',run_status:'incomplete',
          total:2, done:1, requests_sent:2,
          notes:['This operation could not be audited: RuntimeError.'],
          cases:[{case_id:'inventory',scope:'inventory',result:{requests_sent:2,log:[{status:404,response_body:'inventory receipt'}]}},
                 {case_id:'op-000',scope:'operation',status:'error',result:{error:'RuntimeError',endpoint:'POST /a',notes:['This operation could not be audited: RuntimeError.']}}]};
}
async function run() {
  await runAudit(); $('audit-write-consent').checked = true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({audit:state.audit}));
}
run();
""")
    audit = result["audit"]
    assert audit["runStatus"] == "incomplete"
    assert audit["requests"] == 2 and len(audit["log"]) == 1
    assert any("could not be audited" in note for note in audit["notes"])


@pytest.mark.parametrize(("control", "value"), [("audit-budget", "0"), ("audit-budget", "10001"),
                                               ("audit-budget", "3.5"), ("audit-rate", "0"),
                                               ("audit-rate", "101")])
def test_invalid_limits_do_not_even_prepare_an_execution_plan(control, value):
    result = exercise(r"""
async function api(route) {events.push([route]);return {};}
""" + f"$({control!r}).value = {value!r};" + r"""
runAudit().then(() => process.stdout.write(JSON.stringify(events)));
""")
    assert all(not event[0].startswith("/api/") for event in result)
    assert any(event[0] == "toast" for event in result)


def test_review_discloses_inventory_bound_costs_and_scoped_write_authorization():
    result = exercise(r"""
async function api() {return {test_plan:{probes:[]}};}
runAudit().then(() => process.stdout.write(JSON.stringify({summary:$('audit-review-summary').textContent,
  costs:$('audit-review-writes').textContent,consent:$('audit-write-consent-text').textContent,status:state.audit.runStatus})));
""")
    assert "POST /a, POST /b" in result["summary"]
    assert "Inventory: up to 60 requests" in result["summary"]
    assert "upper bounds, not a coverage target" in result["summary"]
    assert "Costs and cleanup are not known" in result["costs"]
    assert "http://127.0.0.1:9876" in result["consent"] and "150-request total budget" in result["consent"]
    assert result["status"] == "not-started"


SAVED_HARNESS = r"""
const window = {NamazuAssessmentView:{}};
const KNOWN_EXPORT_KEYS = new Set(['findings','scope','requests','run','coverage','api','provenance',
  'started_at','contract_snapshots','tool_version','assessment']);
const EVIDENCE_LEVELS = {};
function findingKey(item) {return item.id;}
function renderSeverityBar() {}
function severityTally() {return {};}
function categoryTally() {return {};}
function verificationTally() {return {};}
function assessmentOf(item) {return item.assessment || {};}
function coverageState() {return 'blocked';}
function el(tag,cls,text) {return {tag,text:text || '',children:[],append(...items) {this.children.push(...items);}};}
async function api(route, payload) {
  if (route === '/api/audit/import') {events.push([route]);return JSON.parse(JSON.stringify(payload));}
  if (route !== '/api/audit/assess') throw new Error('Unexpected execution while importing: ' + route);
  events.push([route]); return {provenance:{kind:'offline-reassessment'},requests_sent:0};
}
"""


def saved_functions():
    return "\n".join(function(name) for name in (
        "isVulnerability", "auditNotes", "auditExportPayload", "refreshAssessment", "importAudit", "runProvenanceCard"))


def saved_exercise(body):
    return node(RUN_HARNESS + SAVED_HARNESS + saved_functions() + body)


def test_open_old_export_marks_missing_snapshot_and_never_sends_a_target_request():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],scope:{requests_sent:2,endpoints_audited:1,endpoints_in_scope:1},
    requests:[{status:403,request_headers:{Authorization:'<redacted>'},response_body:'denied'},
      {status:0,error:'timeout'}]}),'old-local-export.json');
  await Promise.resolve();
  process.stdout.write(JSON.stringify({events,audit:state.audit,card:runProvenanceCard(),export:auditExportPayload()}));
}
run();
""")
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/import", "/api/audit/assess"]
    assert result["audit"]["currentActionRequests"] == 0
    assert result["audit"]["requests"] == 2
    assert result["audit"]["runStatus"] == "unknown"
    assert result["audit"]["contractSnapshots"] == {}
    assert result["export"]["provenance"]["kind"] == "imported-historical-run"
    assert result["export"]["provenance"]["requests_sent_during_current_action"] == 0
    rendered = str(result["card"])
    assert "Imported historical run" in rendered
    assert "Unavailable in this export" in rendered
    assert "not a fresh test" in rendered
    assert "Not recorded in this export" in rendered


def test_partial_run_round_trip_retains_incomplete_state_evidence_and_zero_current_traffic():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],run:{status:'incomplete',cancelled:true,accounting_uncertain:true,
      environment:'Local fixtures',identity_label:'Primary fixture'},
    tool_version:'fixture-version',started_at:'2026-10-09T08:20:43Z',
    api:{base_url:'http://127.0.0.1:9876',title:'Local mock'},
    scope:{requests_sent:3,endpoints_audited:1,endpoints_in_scope:2,request_budget:20},
    requests:[{status:403,response_body:'denied',request_headers:{Authorization:'<redacted>'}},
      {status:400,response_body:'field rejected'},{status:0,error:'timeout'}]}),'partial.json');
  await Promise.resolve();
  process.stdout.write(JSON.stringify({audit:state.audit,export:auditExportPayload()}));
}
run();
""")
    audit, exported = result["audit"], result["export"]
    assert audit["cancelled"] and audit["runStatus"] == "incomplete" and audit["accountingUncertain"]
    assert audit["done"] == 1 and audit["total"] == 2
    assert exported["run"]["status"] == "incomplete" and exported["run"]["cancelled"]
    assert exported["run"]["accounting_uncertain"]
    assert exported["scope"]["requests_sent"] == 3
    assert len(exported["requests"]) == 3
    assert exported["requests"][2]["error"] == "timeout"
    assert exported["provenance"]["requests_sent_during_current_action"] == 0
    assert exported["tool_version"] == "fixture-version"
    assert exported["run"]["environment"] == "Local fixtures"


def test_export_counts_received_http_responses_separately_from_zero_status_timeouts():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],scope:{requests_sent:5},requests:[
    {status:403,response_body:'denied'},{status:400,response_body:'validation'},
    {status:403,response_body:'<html>edge block</html>'},
    {status:0,error:'timeout'},{status:null,error:'connection error'}]}),'mixed.json');
  await Promise.resolve(); process.stdout.write(JSON.stringify(auditExportPayload()));
}
run();
""")
    assert result["scope"]["requests_sent"] == 5
    assert result["scope"]["responses_received"] == 3


def test_offline_reassessment_opens_as_retained_evidence_not_a_new_live_run():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],provenance:{kind:'offline-reassessment',source_run:{
    target:'http://127.0.0.1:9876',tool_version:'historical-version',environment:'Local mock',status:'incomplete'}},
    requests:[{status:403,response_body:'denied'}]}),'reassessment.json');
  await Promise.resolve();
  process.stdout.write(JSON.stringify({events,card:runProvenanceCard(),export:auditExportPayload()}));
}
run();
""")
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/import", "/api/audit/assess"]
    assert "Offline reassessment" in str(result["card"])
    assert result["export"]["provenance"]["kind"] == "offline-reassessment"
    assert result["export"]["provenance"]["requests_sent_during_current_action"] == 0
    assert result["export"]["api"]["base_url"] == "http://127.0.0.1:9876"
    assert result["export"]["scope"]["requests_sent"] == 1
    assert result["export"]["scope"]["endpoints_audited"] is None
    assert result["export"]["scope"]["endpoints_in_scope"] is None


def test_explicit_offline_review_changes_provenance_without_replaying_requests():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[{status:403,response_body:'denied'}]}),'history.json');
  await Promise.resolve(); await refreshAssessment();
  process.stdout.write(JSON.stringify({events,export:auditExportPayload()}));
}
run();
""")
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/import", "/api/audit/assess", "/api/audit/assess"]
    assert result["export"]["provenance"]["kind"] == "offline-reassessment"
    assert result["export"]["provenance"]["requests_sent_during_current_action"] == 0


def test_import_cannot_overwrite_an_active_run_and_discard_partial_evidence():
    result = saved_exercise(r"""
state.audit.running = true; state.audit.log = [{status:403,response_body:'partial evidence'}];
importAudit(JSON.stringify({findings:[],requests:[]}),'unrelated.json');
process.stdout.write(JSON.stringify({events,audit:state.audit}));
""")
    assert result["audit"]["running"]
    assert result["audit"]["log"][0]["response_body"] == "partial evidence"
    assert all(not event[0].startswith("/api/") for event in result["events"])


def test_failed_local_sanitization_preserves_the_previous_run():
    result = saved_exercise(r"""
async function api(route) {events.push([route]);throw new Error('local sanitizer unavailable');}
state.audit.log = [{status:403,response_body:'preserved evidence'}];
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[]}),'new.json');
  process.stdout.write(JSON.stringify({events,audit:state.audit}));
}
run();
""")
    assert result["audit"]["log"][0]["response_body"] == "preserved evidence"
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/import"]
    assert any("could not be safely opened" in event[1] for event in result["events"] if event[0] == "toast")


def test_late_import_does_not_overwrite_a_run_started_while_sanitizing():
    result = saved_exercise(r"""
async function api(route, payload) {
  events.push([route]);
  state.audit = {running:true,log:[{status:403,response_body:'new live evidence'}]};
  return payload;
}
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[]}),'late.json');
  process.stdout.write(JSON.stringify({events,audit:state.audit}));
}
run();
""")
    assert result["audit"]["running"]
    assert result["audit"]["log"][0]["response_body"] == "new live evidence"
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/import"]


def test_only_sanitized_import_is_assigned_rendered_and_reexported():
    result = saved_exercise(r"""
async function api(route, payload) {
  events.push([route]);
  if (route === '/api/audit/import') {
    const clean = JSON.parse(JSON.stringify(payload));
    clean.requests[0].request_headers.Authorization = '<redacted>';
    clean.requests[0].response_body = 'echo <redacted>';
    return clean;
  }
  return {requests_sent:0};
}
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[{status:403,
    request_headers:{Authorization:'Bearer never-reexport-secret'},
    response_body:'echo never-reexport-secret'}]}),'sanitized.json');
  await Promise.resolve();
  process.stdout.write(JSON.stringify({audit:state.audit,export:auditExportPayload()}));
}
run();
""")
    assert "never-reexport-secret" not in str(result)
    assert result["export"]["requests"][0]["request_headers"]["Authorization"] == "<redacted>"
    assert result["export"]["requests"][0]["response_body"] == "echo <redacted>"


EDITOR_HARNESS = r"""
state.operation = operations[0];
state.spec = {operations};
state.setup = {identityRevision:2,preparedRevision:1};
const editorPayload = {base_url:connection.base_url,operation_id:'a',allow_mutating:false,
  content_type:'application/x-www-form-urlencoded',
  headers:{Authorization:'Bearer local-editor-credential',Accept:'application/json','X-Correlation-Mode':'fixture'},
  body:{documentUri:'fixture-document',enabled:false,count:0,password:'local-editor-body-secret'}};
function requestPayload() {return JSON.parse(JSON.stringify(editorPayload));}
function saveExamples() {events.push(['persist',JSON.parse(JSON.stringify(state.examples))]);}
function renderBaselineEditor() {}
function message(id,text) {events.push(['message',id,text]);}
$('setup-baseline-mount').replaceChildren = () => {};
const localPrepared = {request:{method:'POST',url:'http://127.0.0.1:9876/a',
  headers:{Authorization:'<redacted>',Accept:'application/json','X-Correlation-Mode':'fixture'},
  body:'{"documentUri":"fixture-document","enabled":false,"count":0,"password":"<redacted>"}'},
  expectation:{status:'200'},assertions:[],positive_control:false};
async function api(route,payload) {
  events.push([route,payload]);
  if (route === '/api/prepare') return {method:'POST',url:'http://127.0.0.1:9876/a',
    has_body:true,body:payload.body,headers:payload.headers,content_type:payload.content_type};
  if (route === '/api/readiness/prepare') return {...localPrepared,expectation:payload.expectation,assertions:payload.assertions};
  if (route === '/api/audit/plan') return {test_plan:{probes:[]}};
  throw new Error('Unexpected target call: ' + route);
}
"""


def editor_exercise(body, *, planning=False):
    return node(RUN_HARNESS + EDITOR_HARNESS + function("credentialNames") + function("saveEditorBaseline")
                + (execution_functions() if planning else "") + body)


def test_saving_editor_is_offline_persists_only_redacted_values_and_keeps_request_details():
    result = editor_exercise(r"""
saveEditorBaseline().then(() => process.stdout.write(JSON.stringify({events,saved:state.examples.a,
  prepared:state.audit.readiness,busy:state.busy})));
""")
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == [
        "/api/prepare", "/api/readiness/prepare"]
    prepare = next(event[1] for event in result["events"] if event[0] == "/api/readiness/prepare")
    assert prepare["request"]["method"] == "POST"
    assert prepare["request"]["url"].endswith("/a")
    assert prepare["request"]["body"]["enabled"] is False
    assert prepare["request"]["body"]["count"] == 0
    saved = result["saved"]
    assert saved["example"]["headers"]["Accept"] == "application/json"
    assert saved["example"]["headers"]["X-Correlation-Mode"] == "fixture"
    assert saved["example"]["headers"]["Authorization"] == "<redacted>"
    assert saved["example"]["content_type"] == "application/x-www-form-urlencoded"
    assert saved["expectation"]["status"] == "403" and saved["expectation"]["negative"]
    assert "local-editor-credential" not in str(saved)
    assert "local-editor-body-secret" not in str(saved)
    persisted = next(event[1] for event in result["events"] if event[0] == "persist")
    assert persisted["a"] == saved
    assert result["prepared"]["prepared"]["positive_control"] is False
    assert not result["busy"]


def test_explicitly_saved_body_and_headers_feed_the_next_reviewed_plan():
    result = editor_exercise(r"""
async function run() {
  await saveEditorBaseline(); await runAudit();
  process.stdout.write(JSON.stringify({events,saved:state.examples.a}));
}
run();
""", planning=True)
    plan = next(event[1] for event in result["events"] if event[0] == "/api/audit/plan" and event[1]["operation_id"] == "a")
    assert plan["example"] == result["saved"]["example"]
    assert '"documentUri":"fixture-document"' in plan["example"]["body"]
    assert all(event[0] not in {"/api/run", "/api/audit", "/api/audit/inventory"} for event in result["events"])


@pytest.mark.parametrize("condition", ["state.busy = true;", "state.operation = null;"])
def test_save_editor_requires_idle_state_and_an_operation(condition):
    result = editor_exercise(condition + r"""
saveEditorBaseline().then(() => process.stdout.write(JSON.stringify(events)));
""")
    assert not result


@pytest.mark.parametrize("change", [
    "state.operation = operations[1];",
    "editorPayload.base_url = 'http://127.0.0.1:9999';",
    "editorPayload.headers.Authorization = 'Bearer changed-identity';state.setup.identityRevision++;",
    "editorPayload.body.documentUri = 'changed-resource';",
])
@pytest.mark.parametrize("stage", ["/api/prepare", "/api/readiness/prepare"])
def test_editor_changes_during_offline_prepare_cannot_save_under_new_context(change, stage):
    result = editor_exercise(r"""
async function api(route,payload) {
  events.push([route]);
""" + f"if (route === {stage!r}) {{ {change} }}" + r"""
  if (route === '/api/prepare') {
    return {method:'POST',url:'http://127.0.0.1:9876/a',has_body:true,body:payload.body,headers:payload.headers};
  }
  return localPrepared;
}
saveEditorBaseline().then(() => process.stdout.write(JSON.stringify({events,example:state.examples.a})));
""")
    assert all(event[0] != "persist" for event in result["events"])
    assert result["example"]["example"]["body"] == {"enabled": True}


def test_editor_save_preserves_legacy_business_assertions():
    result = editor_exercise(r"""
state.examples.a = {expectation:{status:'200',business_assertions:[{purpose:'resource',pointer:'/id',operator:'equals',expected:'fixture-document'}]}};
saveEditorBaseline().then(() => process.stdout.write(JSON.stringify(events)));
""")
    prepare = next(event[1] for event in result if event[0] == "/api/readiness/prepare")
    assert prepare["assertions"] == [{"purpose": "resource", "pointer": "/id", "operator": "equals", "expected": "fixture-document"}]
    persisted = next(event[1] for event in result if event[0] == "persist")
    assert persisted["a"]["assertions"] == prepare["assertions"]


def test_editor_forwards_declared_and_selected_credential_names_for_safe_persistence():
    result = editor_exercise(r"""
state.spec.security_schemes = {fixture:{type:'apiKey',in:'header',name:'X-Declared-Identity'}};
$('auth-mode').value = 'apikey'; $('apikey-name').value = 'X-Workspace';
saveEditorBaseline().then(() => process.stdout.write(JSON.stringify(events)));
""")
    prepare = next(event[1] for event in result if event[0] == "/api/readiness/prepare")
    assert set(prepare["credential_names"]) == {"X-Declared-Identity", "X-Workspace"}


def test_editor_sanitization_failure_does_not_replace_saved_request():
    result = editor_exercise(r"""
async function api(route) {events.push([route]);throw new Error('Offline preparation failed');}
saveEditorBaseline().then(() => process.stdout.write(JSON.stringify({events,example:state.examples.a,busy:state.busy})));
""")
    assert all(event[0] != "persist" for event in result["events"])
    assert result["example"]["example"]["body"] == {"enabled": True}
    assert not result["busy"]


def test_empty_selected_scope_never_falls_back_to_all_operations():
    result = node(RUN_HARNESS + function("auditScope") + r"""
state.spec={operations}; state.selected = new Set(); $('audit-selected-only').checked = true;
const empty = auditScope(); state.selected.add('a'); const selected = auditScope();
$('audit-selected-only').checked = false;
process.stdout.write(JSON.stringify({empty,selected,all:auditScope()}));
""")
    assert result["empty"] == []
    assert [row["id"] for row in result["selected"]] == ["a"]
    assert [row["id"] for row in result["all"]] == ["a", "b"]


def test_empty_scope_cannot_plan_or_send_inventory_or_endpoint_traffic():
    result = exercise(r"""
operations.splice(0);
async function api(route) {events.push([route]);return {};}
runAudit().then(() => process.stdout.write(JSON.stringify(events)));
""")
    assert all(not event[0].startswith("/api/") for event in result)
    assert any("No scope was expanded" in event[1] for event in result if event[0] == "toast")


def test_saved_editor_request_uses_live_identity_and_keeps_body_and_non_secret_headers():
    import httpx

    from namazu.audit.engine import audit_operation
    from namazu.spec import parse_spec

    spec = parse_spec({"openapi": "3.1.0", "info": {"title": "Editor fixture", "version": "1"},
        "servers": [{"url": "http://127.0.0.1:9876"}], "paths": {"/a": {"post": {
            "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"403": {"description": "Fixture denial"}}}}}})
    received = []

    def target(request):
        received.append(request)
        return httpx.Response(403, json={"detail": "Fixture denial"})

    with httpx.Client(transport=httpx.MockTransport(target)) as client:
        result = audit_operation(spec, "POST /a", client=client, profile="writes", allow_mutating=True,
            request_budget=1, identities={"primary": {"Authorization": "Bearer current-local-credential"}},
            example={"url": "http://127.0.0.1:9876/a", "body": '{"documentUri":"fixture-document","enabled":false,"count":0}',
                     "headers": {"Authorization": "<redacted>", "Accept": "application/json", "X-Correlation-Mode": "fixture"},
                     "content_type": "application/json"})
    assert len(received) == 1
    assert received[0].method == "POST"
    assert received[0].headers["Authorization"] == "Bearer current-local-credential"
    assert received[0].headers["Accept"] == "application/json"
    assert received[0].headers["X-Correlation-Mode"] == "fixture"
    assert received[0].content == b'{"documentUri":"fixture-document","enabled":false,"count":0}'
    assert "current-local-credential" not in str(result)


def test_offline_editor_save_redacts_a_configured_api_key_header_and_body_echo():
    from fastapi.testclient import TestClient

    from namazu.app import app

    response = TestClient(app, base_url="http://127.0.0.1").post("/api/readiness/prepare", json={
        "request": {"method": "POST", "url": "http://127.0.0.1:9876/a",
                    "headers": {"X-Workspace": "local-arbitrary-header-key", "Accept": "application/json"},
                    "body": {"resource": "fixture-document", "echo": "local-arbitrary-header-key"}},
        "credential_names": ["X-Workspace"], "identity_ref": "primary", "expectation": {"status": "200"}})
    assert response.status_code == 200
    assert "local-arbitrary-header-key" not in response.text
    prepared = response.json()
    assert prepared["request"]["headers"]["Accept"] == "application/json"
    assert prepared["request"]["headers"]["X-Workspace"] in {"<redacted>", "<credential>"}
    assert prepared["requests_sent"] == 0


def test_header_editor_masks_credentials_and_updates_mask_when_name_changes():
    from tests.test_audit_results_view import DOM

    harness = DOM + r"""
Element.prototype.querySelectorAll = function(selector) {
  if (selector.startsWith('.')) return byClass(this,selector.slice(1)).filter(item => item !== this);
  if (selector === 'input[type=checkbox]') return byTag(this,'input').filter(item => item.type === 'checkbox');
  return [];
};
Element.prototype.querySelector = function(selector) {return this.querySelectorAll(selector)[0];};
Object.defineProperty(Element.prototype,'classList',{get() {const element=this;return {
  toggle(name,enabled) {const values=new Set(element.className.split(' ').filter(Boolean));
    if (enabled) values.add(name); else values.delete(name);element.className=[...values].join(' ');}
};}});
const state={spec:{security_schemes:{custom:{type:'apiKey',name:'X-Declared-Identity'}}}};
const elements=new Map();
function $(id) {if(!elements.has(id))elements.set(id,new Element('div'));return elements.get(id);}
function el(tag,cls) {const node=new Element(tag);node.className=cls||'';return node;}
function icon() {return new Element('svg');}
$('auth-mode').value='apikey';$('apikey-name').value='X-Workspace';
"""
    result = node(harness + function("credentialNames") + function("secretHeaderName") + function("createKv") + r"""
let changes=0;
const editor=createKv('second-identity',{noun:'Header',onChange(){changes++;}});
const supplied={Authorization:'Bearer second-local-token','X-Workspace':'custom-local-token',
  'X-Declared-Identity':'declared-local-token',Accept:'application/json'};
editor.setAll(supplied);
const rows=$('second-identity').querySelectorAll('.kv-row');
const initial=rows.filter(row=>row.querySelector('.kv-name').value).map(row=>({
  name:row.querySelector('.kv-name').value,type:row.querySelector('.kv-value').type,
  label:row.querySelector('.kv-value').attributes['aria-label'],autocomplete:row.querySelector('.kv-value').autocomplete}));
const accept=rows.find(row=>row.querySelector('.kv-name').value==='Accept');
const beforeRead=JSON.stringify(editor.read())===JSON.stringify(supplied);
accept.querySelector('.kv-name').value='Cookie';accept.querySelector('.kv-name').fire('input');
const afterType=accept.querySelector('.kv-value').type;
accept.querySelector('.kv-name').value='Accept';accept.querySelector('.kv-name').fire('input');
process.stdout.write(JSON.stringify({initial,beforeRead,afterType,afterRenameType:accept.querySelector('.kv-value').type,
  valuesPreserved:JSON.stringify(editor.read())===JSON.stringify(supplied),changes}));
""")
    types = {row["name"]: row["type"] for row in result["initial"]}
    assert types == {"Authorization": "password", "X-Workspace": "password", "X-Declared-Identity": "password", "Accept": "text"}
    assert result["beforeRead"] and result["valuesPreserved"]
    assert result["afterType"] == "password" and result["afterRenameType"] == "text"
    assert all(row["label"] == "Header value" and row["autocomplete"] == "off" for row in result["initial"])
    assert result["changes"] >= 3


def saved_presentation_exercise(body):
    from tests.test_audit_results_view import DOM

    display = r"""
const COVERAGE_ORDER=['execution-error','budget-exhausted','blocked','inconclusive','completed','skipped','not-applicable','attempted'];
const COVERAGE_LABEL={completed:'Ran',blocked:'Blocked'};
const SEVERITIES=[];
function $(id) {
  if (!nodes.has(id)) {const element=new Element('div');element.removeAttribute=name=>delete element.attributes[name];nodes.set(id,element);}
  return nodes.get(id);
}
function el(tag,cls,text) {const element=new Element(tag);element.className=cls||'';if(text!=null)element.textContent=text;return element;}
function reportCard(title,content) {const element=el('section');element.append(el('h3','',title),...content);return element;}
function testPlanCard() {return null;}
function requestBreakdownCard() {return null;}
function fieldCoverageCard() {return null;}
function baselineCard() {return null;}
function runDiagnostics() {return null;}
function setupAction() {}
window.NamazuAssessmentView.render=()=>el('section');
"""
    actual = "\n".join(function(name) for name in ("auditHasReport", "auditProgress", "coverageState", "coverageCard", "renderAuditReport"))
    return node(RUN_HARNESS + SAVED_HARNESS + DOM + display + saved_functions() + actual + body)


def test_cli_offline_assessment_without_scope_shows_retained_attempts_and_unknown_operation_totals():
    result = saved_presentation_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[
      {status:403,response_body:'denied'},{status:400,response_body:'field rejected'},{status:0,error:'timeout'}],
    coverage:{checks:[{check:'input-handling',title:'Input handling',state:'inconclusive'}],probes:[]},
    provenance:{kind:'offline-reassessment',source_run:{target:'http://127.0.0.1:9876',status:'incomplete'}}}),
    'cli-offline-assessment.json');
  await Promise.resolve(); auditProgress(); renderAuditReport();
  process.stdout.write(JSON.stringify({foot:$('audit-foot').textContent,chip:$('audit-state').textContent,
    report:$('audit-report-body').textContent,attempts:state.audit.requests,done:state.audit.done,total:state.audit.total,
    currentActionRequests:state.audit.currentActionRequests,events}));
}
run();
""")
    assert result["attempts"] == 3
    assert "3 attempts" in result["foot"] and "2 responses" in result["foot"]
    assert "Not run" not in result["foot"]
    assert "offline reassessment" in result["chip"]
    assert "Operation completion totals not retained" in result["report"]
    assert "0 of 0" not in result["report"]
    assert result["done"] == result["total"] == 0
    assert result["currentActionRequests"] == 0
    assert [event[0] for event in result["events"] if event[0].startswith("/api/")] == ["/api/audit/import", "/api/audit/assess"]


def test_missing_family_request_count_stays_unknown_in_view_and_reexport():
    result = saved_presentation_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[{status:403,response_body:'denied'}],
    coverage:{checks:[{check:'unrecorded',title:'Unrecorded count',state:'blocked'},
      {check:'recorded-zero',title:'Recorded zero',state:'blocked',requests:0}]},
    provenance:{kind:'offline-reassessment'}}),'counts-not-retained.json');
  await Promise.resolve();
  const card=coverageCard();
  process.stdout.write(JSON.stringify({unknown:state.audit.coverage.unrecorded.requests,
    known:state.audit.coverage['recorded-zero'].requests,
    text:card.map(part=>part.textContent).join(' '),export:auditExportPayload()}));
}
run();
""")
    assert result["unknown"] is None and result["known"] == 0
    assert "Request count not retained" in result["text"]
    assert result["text"].count("0 requests") == 1
    checks = {entry["check"]: entry for entry in result["export"]["coverage"]["checks"]}
    assert checks["unrecorded"]["requests"] is None
    assert checks["recorded-zero"]["requests"] == 0


def test_import_capping_visible_receipts_does_not_shrink_known_incoming_attempt_count():
    result = saved_exercise("const MAX_LOG=2;\n" + function("absorbLog") + r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[{status:403},{status:400},{status:0,error:'timeout'}],
    provenance:{kind:'offline-reassessment'}}),'long-cli-report.json');
  await Promise.resolve();
  process.stdout.write(JSON.stringify({attempts:state.audit.requests,retained:state.audit.log.length,
    truncated:state.audit.logTruncated,export:auditExportPayload()}));
}
run();
""")
    assert result["attempts"] == 3 and result["retained"] == 2
    assert result["truncated"]
    assert result["export"]["scope"]["requests_sent"] == 3
    assert result["export"]["requests_truncated"]


def test_import_retains_cli_recorded_attempt_count_even_when_receipts_are_incomplete():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[{status:403},{status:400}],requests_truncated:true,
    recorded_request_attempts:42,provenance:{kind:'offline-reassessment'}}),'partial-cli-report.json');
  await Promise.resolve();process.stdout.write(JSON.stringify({attempts:state.audit.requests,export:auditExportPayload()}));
}
run();
""")
    assert result["attempts"] == 42
    assert result["export"]["scope"]["requests_sent"] == 42
    assert result["export"]["requests_truncated"]


def test_empty_legacy_export_keeps_unknown_counts_while_explicit_zero_counts_stay_zero():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[]}), 'unknown.json'); await Promise.resolve();
  const unknown=auditExportPayload();
  await importAudit(JSON.stringify({findings:[],requests:[],scope:{requests_sent:0,endpoints_audited:0,endpoints_in_scope:0}}), 'known-zero.json');
  await Promise.resolve();process.stdout.write(JSON.stringify({unknown,known:auditExportPayload()}));
}
run();
""")
    for name in ("requests_sent", "endpoints_audited", "endpoints_in_scope"):
        assert result["unknown"]["scope"][name] is None
        assert result["known"]["scope"][name] == 0


def test_browser_does_not_pace_the_run_and_hands_the_rate_to_the_server():
    result = exercise(r"""
$('audit-rate').value='2';
let runConfig = null;
async function api(route,payload,method) {
  events.push([route, method || 'POST']);
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') { runConfig = payload; return {run_id:'r1',revision:1,active:true,total:2,done:0,requests_sent:0,cases:[]}; }
  return {run_id:'r1',revision:2,active:false,status:'finished',run_status:'finished',total:2,done:2,requests_sent:3,cases:[]};
}
async function run() {
  await runAudit(); $('audit-write-consent').checked=true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({events,runConfig,status:state.audit.runStatus}));
}
run();
""")
    # Pacing moved to the server with the one shared pacer; the browser inserts
    # no inter-request wait, and passes the configured rate to the run.
    assert not any(event[0] == "pace-wait" for event in result["events"])
    assert result["runConfig"]["requests_per_second"] == 2
    assert result["status"] == "finished"


def test_poll_ignores_out_of_order_snapshots_and_never_double_counts():
    result = exercise(function("ingestRunSnapshot") + function("pollRun") + function("finishRunView") + r"""
function refreshAssessment(){return Promise.resolve();}
state.audit = {runId:'r1', revision:4, absorbedCases:new Set(['op-000']), running:true,
  notes:[], findings:[], log:[], probes:[], coverage:{}, baselines:[], fieldCoverage:[], plans:[],
  requestBreakdown:{}, context:{budget:100}, done:1, total:2, requests:3, statuses:[]};
let calls = 0;
async function api(route) {
  calls++;
  if (calls === 1) return {run_id:'r1',revision:2,active:true,requests_sent:999,done:9,
    cases:[{case_id:'op-000',scope:'operation',result:{requests_sent:50,log:[{status:200}]}}]};
  return {run_id:'r1',revision:6,active:false,status:'finished',run_status:'finished',requests_sent:7,done:2,total:2,cases:[]};
}
pollRun('r1').then(() => process.stdout.write(JSON.stringify(
  {requests:state.audit.requests, done:state.audit.done, logLen:state.audit.log.length, status:state.audit.runStatus})));
""")
    # The stale snapshot (revision 2 < 4) is ignored: op-000 is not re-absorbed
    # and its inflated counts never apply. The later snapshot applies normally.
    assert result["requests"] == 7 and result["done"] == 2
    assert result["logLen"] == 0
    assert result["status"] == "finished"


@pytest.mark.parametrize("where", ["inventory", "operation"])
def test_received_429_is_reflected_as_rate_limited_not_user_cancellation(where):
    result = exercise(f"const where={where!r};\n" + r"""
async function api(route,payload,method) {
  if (route.endsWith('/plan')) return {test_plan:{probes:[]}};
  if (route === '/api/runs') return {run_id:'r1',revision:1,active:true,total:2,done:0,requests_sent:0,cases:[]};
  const invOnly = where === 'inventory';
  return {run_id:'r1',revision:2,active:false,status:'incomplete',run_status:'incomplete',
    rate_limited:true, cancelled:false, total:2, done: invOnly?0:1, requests_sent: invOnly?1:2,
    notes:['The target returned HTTP 429. The run stopped at the observed rate limit; remaining operations were not started. Partial evidence is retained.'],
    cases: invOnly
      ? [{case_id:'inventory',scope:'inventory',result:{requests_sent:1,log:[{status:429}]}}]
      : [{case_id:'inventory',scope:'inventory',result:{requests_sent:1,log:[{status:403}]}},
         {case_id:'op-000',scope:'operation',result:{requests_sent:1,log:[{status:429}]}}]};
}
async function run() {
  await runAudit(); $('audit-write-consent').checked=true; await executeReviewedAudit();
  process.stdout.write(JSON.stringify({audit:state.audit}));
}
run();
""")
    audit = result["audit"]
    assert audit["rateLimited"] and audit["runStatus"] == "incomplete"
    assert not audit["cancelled"] and not audit.get("accountingUncertain")
    assert any("HTTP 429" in note and "remaining operations were not started" in note for note in audit["notes"])


def test_rate_limit_stop_survives_export_import_with_partial_evidence():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[{status:429,response_body:'rate limit'}],
    run:{status:'incomplete',cancelled:false,rate_limited:true},scope:{requests_sent:1,endpoints_audited:1,endpoints_in_scope:2}}),
    'rate-limited.json');
  await Promise.resolve();process.stdout.write(JSON.stringify({audit:state.audit,export:auditExportPayload()}));
}
run();
""")
    assert result["audit"]["rateLimited"] and not result["audit"]["cancelled"]
    assert result["export"]["run"]["rate_limited"] and not result["export"]["run"]["cancelled"]
    assert result["export"]["run"]["status"] == "incomplete"
    assert result["export"]["scope"]["requests_sent"] == 1


@pytest.mark.parametrize("source", ["primary", "mirror"])
def test_withdrawing_write_permission_mid_run_tells_the_server_to_refuse_further_writes(source):
    result = exercise(function("syncWrites") + f"\nconst toggleSource={source!r};\n" + r"""
function updateStatusBar() {}
const posted = [];
async function api(route, payload, method) { posted.push([route, method || 'POST']); return {}; }
// A live, server-owned run on the writes profile.
state.audit = {running:true, runId:'r1', cancelled:false, writesWithdrawn:false,
  context:{profile:'writes'}, notes:[], log:[]};
$(toggleSource==='mirror'?'allow-writes-mirror':'allow-writes').checked=false;
syncWrites(toggleSource);
syncWrites(toggleSource);  // idempotent: one withdrawal only
process.stdout.write(JSON.stringify({posted, audit:state.audit,
  allowWrites:$('allow-writes').checked, mirror:$('allow-writes-mirror').checked}));
""")
    audit = result["audit"]
    # Withdrawing writes is not a full stop: it refuses further writes, nothing more.
    assert audit["writesWithdrawn"] is True and audit["cancelled"] is False
    assert not result["allowWrites"] and not result["mirror"]
    withdrawals = [row for row in result["posted"] if str(row[0]).endswith("/withdraw-writes")]
    assert [row[1] for row in withdrawals] == ["POST"]
    assert len([note for note in audit["notes"] if "withdrawn" in note.lower()]) == 1
    assert "not recalled" in audit["notes"][-1]


@pytest.mark.parametrize("running,profile", [(False, "writes"), (True, "readonly")])
def test_write_toggle_does_not_cancel_an_idle_or_readonly_run(running, profile):
    result = exercise(function("syncWrites") + f"\nconst running={str(running).lower()}, selectedProfile={profile!r};\n" + r"""
function updateStatusBar() {}
state.audit={running,cancelled:false,context:{profile:selectedProfile},notes:[],log:[{status:403}]};
$('allow-writes').checked=false;
syncWrites();
process.stdout.write(JSON.stringify({audit:state.audit,events,mirror:$('allow-writes-mirror').checked}));
""")
    assert not result["audit"]["cancelled"] and result["audit"]["notes"] == []
    assert result["audit"]["log"] == [{"status": 403}] and not result["mirror"]


def test_historical_finish_time_survives_import_reassessment_and_reexport():
    result = saved_exercise(r"""
async function run() {
  await importAudit(JSON.stringify({findings:[],requests:[],started_at:'2026-10-09T08:20:00.000Z',
    run:{status:'incomplete',finished_at:'2026-10-09T08:20:43.982Z'}}),'historical.json');
  await Promise.resolve();
  process.stdout.write(JSON.stringify({finishedAt:state.audit.finishedAt,export:auditExportPayload(),events}));
}
run();
""")
    assert result["finishedAt"] == result["export"]["run"]["finished_at"] == "2026-10-09T08:20:43.982Z"
    assert result["export"]["started_at"] == "2026-10-09T08:20:00.000Z"
    assert result["export"]["provenance"]["requests_sent_during_current_action"] == 0
