"""Consequential baseline-editor behaviour using local DOM and recorded fixtures."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from namazu.audit import readiness
from tests.test_audit_results_view import DOM
from tests.test_readiness import prepared_input


def run_editor(script, initial=None):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    path = Path("namazu/static/readiness.js").resolve()
    prelude = DOM + f"const readiness=require({json.dumps(str(path))});\n"
    prelude += "const initial=JSON.parse(require('fs').readFileSync(0,'utf8'));\n"
    prelude += r"""
Object.defineProperty(Element.prototype,'childNodes',{get(){return this.children;}});
const container=new Element('div');
function labelInput(root,label){return all(root,n=>n.tagName==='label' && n.children[0]?.textContent===label)[0].children[1];}
"""
    result = subprocess.run(["node", "-e", prelude + script], input=json.dumps(initial),
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_simple_assertions_send_typed_values_and_preserve_additional_assertions():
    prepared = readiness.prepare(prepared_input())
    additional = {"purpose": "content", "pointer": "/other", "operator": "contains", "expected": "extra"}
    prepared["assertions"].append(additional)
    result = run_editor(r"""
const calls=[],saved=[];
const editor=readiness.mount(container,{initial,api:async(path,body)=>{calls.push({path,body});return initial.prepared;},onUseBaseline:item=>saved.push(item),context:()=>({})});
const resource=byTag(container,'fieldset')[0];
labelInput(resource,'Response field (JSON pointer)').value='/number';
const format=labelInput(resource,'Value format');format.value='json';
const expected=labelInput(resource,'Expected value');expected.value='23';expected.fire('input');
const use=byTag(container,'button').find(node=>node.textContent==='Use as saved baseline');
const dirty=editor.getState();use.fire('click');
byTag(container,'button').find(node=>node.textContent==='Review baseline readiness').fire('click');
setImmediate(()=>process.stdout.write(JSON.stringify({calls,dirty,saved,basicGroups:byTag(container,'fieldset').length,
 advancedOpen:byClass(container,'readiness-advanced').map(node=>node.open)})));
""", {"prepared": prepared, "configuration": {}})
    assert len(result["calls"]) == 1
    assert result["calls"][0]["path"] == "/api/readiness/prepare"
    assertions = result["calls"][0]["body"]["assertions"]
    assert assertions[0] == {"purpose": "resource", "pointer": "/number", "operator": "equals", "expected": 23}
    assert additional in assertions
    assert result["dirty"]["prepared"] is None and result["dirty"]["draft_dirty"]
    assert result["saved"] == []
    assert result["basicGroups"] == 2 and result["advancedOpen"] == [False, False, False]


def test_invalid_simple_value_cannot_reuse_previous_valid_assertions():
    prepared = readiness.prepare(prepared_input())
    result = run_editor(r"""
let calls=0;
readiness.mount(container,{initial,api:async()=>{calls++;return initial.prepared;},context:()=>({})});
const resource=byTag(container,'fieldset')[0];
labelInput(resource,'Value format').value='json';
const expected=labelInput(resource,'Expected value');expected.value='{';expected.fire('input');
byTag(container,'button').find(node=>node.textContent==='Review baseline readiness').fire('click');
setImmediate(()=>process.stdout.write(JSON.stringify({calls,disabled:byTag(container,'button').find(node=>node.textContent==='Use as saved baseline').disabled,text:container.textContent})));
""", {"prepared": prepared})
    assert result["calls"] == 0
    assert result["disabled"]
    assert "JSON" in result["text"]


def test_edit_during_async_review_prevents_stale_control_and_does_not_replace_draft():
    prepared = readiness.prepare(prepared_input())
    result = run_editor(r"""
let resolve;const changes=[],calls=[];
const editor=readiness.mount(container,{initial,api:(path)=>{calls.push(path);return new Promise(done=>{resolve=done;});},onChange:value=>changes.push(value),context:()=>({})});
byTag(container,'button').find(node=>node.textContent==='Review baseline readiness').fire('click');
const identity=labelInput(container,'Local identity reference');identity.value='different-local-identity';identity.fire('input');
resolve(initial.prepared);
setImmediate(()=>process.stdout.write(JSON.stringify({calls,state:editor.getState(),identity:identity.value,changes,
 disabled:byTag(container,'button').find(node=>node.textContent==='Use as saved baseline').disabled,text:container.textContent})));
""", {"prepared": prepared})
    assert result["calls"] == ["/api/readiness/prepare"]
    assert result["state"]["prepared"] is None
    assert result["state"]["draft_dirty"]
    assert result["identity"] == "different-local-identity"
    assert result["disabled"]
    assert all(change["prepared"] is None for change in result["changes"])
    assert "Inputs changed" in result["text"]


def test_advanced_json_edits_update_simple_controls_without_inventing_expected_values():
    result = run_editor(r"""
readiness.mount(container,{initial:{},context:()=>({})});
const assertions=labelInput(container,'Business assertions (JSON array)');
assertions.value=JSON.stringify([{purpose:'resource',pointer:'/count',operator:'equals',expected:0},{purpose:'content',pointer:'/enabled',operator:'equals',expected:false}]);
assertions.fire('input');
const groups=byTag(container,'fieldset');
process.stdout.write(JSON.stringify(groups.map(group=>({path:labelInput(group,'Response field (JSON pointer)').value,
 type:labelInput(group,'Value format').value,expected:labelInput(group,'Expected value').value}))));
""")
    assert result == [{"path": "/count", "type": "json", "expected": "0"},
                      {"path": "/enabled", "type": "json", "expected": "false"}]


def test_custom_credential_names_reach_preparation_and_only_sanitised_template_is_saved():
    prepared = readiness.prepare(prepared_input())
    prepared["request"]["headers"]["X-Company-Access"] = "<credential>"
    result = run_editor(r"""
const calls=[],saved=[];
const names=['X-Company-Access','X-Schema-Key'];
const editor=readiness.mount(container,{initial,context:()=>({credential_names:names,identity_revision:7}),
 api:async(path,body)=>{calls.push({path,credential_names:body.credential_names});return initial.prepared;},onUseBaseline:value=>saved.push(value)});
const request=labelInput(container,'Known-good request (JSON, one HAR entry, or raw HTTP)');
const value=JSON.parse(request.value);value.headers['X-Company-Access']='local-custom-key-fixture';request.value=JSON.stringify(value);request.fire('input');
byTag(container,'button').find(node=>node.textContent==='Review baseline readiness').fire('click');
setImmediate(()=>{byTag(container,'button').find(node=>node.textContent==='Use as saved baseline').fire('click');
 process.stdout.write(JSON.stringify({calls,saved,state:editor.getState(),request:request.value,names}));});
""", {"prepared": prepared})
    assert result["calls"] == [{"path": "/api/readiness/prepare", "credential_names": ["X-Company-Access", "X-Schema-Key"]}]
    assert result["names"] == ["X-Company-Access", "X-Schema-Key"]
    assert result["saved"][0]["example"]["headers"]["X-Company-Access"] == "<credential>"
    assert "local-custom-key-fixture" not in json.dumps(result)


@pytest.mark.parametrize("header_name", ["content-type", "CoNtEnT-TyPe", None])
def test_saved_baseline_preserves_known_good_media_type_without_inventing_one(header_name):
    prepared = readiness.prepare(prepared_input())
    prepared["request"]["headers"] = {name: value for name, value in prepared["request"]["headers"].items()
                                       if name.lower() != "content-type"}
    if header_name:
        prepared["request"]["headers"][header_name] = "application/vnd.local-report+json; charset=utf-8"
    result = run_editor(r"""
let saved;
readiness.mount(container,{initial,context:()=>({}),onUseBaseline:value=>{saved=value;}});
byTag(container,'button').find(node=>node.textContent==='Use as saved baseline').fire('click');
process.stdout.write(JSON.stringify(saved));
""", {"prepared": prepared})
    if header_name:
        assert result["example"]["content_type"] == "application/vnd.local-report+json; charset=utf-8"
        assert result["example"]["headers"][header_name] == result["example"]["content_type"]
    else:
        assert "content_type" not in result["example"]


@pytest.mark.parametrize("stage", ["prepare", "plan"])
@pytest.mark.parametrize("changed_context", ["base_url", "identity_revision"])
def test_context_change_during_either_review_await_rejects_stale_control(stage, changed_context):
    prepared = readiness.prepare(prepared_input())
    initial = {"prepared": prepared, "stage": stage, "changed_context": changed_context}
    result = run_editor(r"""
const current={base_url:'http://127.0.0.1/original',identity_revision:3,identity_refs:['primary'],credential_names:['X-Company-Access']};
const resolves={},calls=[],changes=[],saved=[];
const editor=readiness.mount(container,{initial,context:()=>current,
 api:(path,body)=>{calls.push({path,base_url:body.base_url,identity_revision:body.identity_revision});return new Promise(resolve=>{resolves[path]=resolve;});},
 onChange:value=>changes.push(value),onUseBaseline:value=>saved.push(value)});
const tick=()=>new Promise(setImmediate);
(async()=>{
 byTag(container,'button').find(node=>node.textContent==='Build follow-up and incomplete-case plan').fire('click');
 if(initial.stage==='plan'){resolves['/api/readiness/prepare'](initial.prepared);await tick();}
 if(initial.changed_context==='base_url') current.base_url='http://127.0.0.1/other';
 else current.identity_revision++;
 resolves['/api/readiness/'+initial.stage](initial.stage==='prepare'?initial.prepared:{});
 await tick();
 const use=byTag(container,'button').find(node=>node.textContent==='Use as saved baseline');use.fire('click');
 process.stdout.write(JSON.stringify({calls,changes,saved,state:editor.getState(),disabled:use.disabled,text:container.textContent}));
})();
""", initial)
    assert len(result["calls"]) == (1 if stage == "prepare" else 2)
    assert all(call["base_url"] == "http://127.0.0.1/original" for call in result["calls"])
    if stage == "plan":
        assert result["calls"][1]["identity_revision"] == 3
    assert result["state"]["prepared"] is None and result["state"]["plan"] is None
    assert result["state"]["draft_dirty"] and result["disabled"]
    assert result["saved"] == []
    assert all(change["prepared"] is None for change in result["changes"])
