"""Exercise the actual pure request-tab model without browser or network IO."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

MODEL = Path("namazu/static/desktop-model.js").resolve()


def model(script):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    prelude = f"const M = require({json.dumps(str(MODEL))});\n" + """
const workspace = {id:'workspace'};
const contract = {id:'accounts',hash:'hash-a',target:'http://127.0.0.1:9138/v1',identity:{profile_id:'shared'}};
const operation = {id:'accounts::GET /widgets/{id}',local_id:'GET /widgets/{id}',method:'GET',path:'/widgets/{id}',operation_id:'getWidget',parameters:[{in:'path',name:'id',required:true,schema:{type:'integer'}},{in:'query',name:'limit',schema:{type:'integer'}}]};
const tab = M.createTab({workspace,contract,operation,id:'a'});
globalThis.fetch = () => { throw Error('Model code must never dispatch'); };
"""
    result = subprocess.run(["node", "-e", prelude + script], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_identity_collision_does_not_join_workspace_contract_hash_environment_drafts():
    result = model("""
const variations = [{workspaceId:'other'}, {contractId:'orders'}, {snapshotHash:'new-hash'},
{operationKey:'accounts::POST /widgets/{id}'}, {environmentId:'staging'}];
process.stdout.write(JSON.stringify([tab.key,...variations.map(patch => M.tabKey({...tab,...patch}))]));
""")
    assert len(set(result)) == 6


def test_request_edits_do_not_mutate_a_sibling_tab_or_saved_draft():
    result = model("""
const sibling = M.createTab({workspace,contract:{...contract,id:'orders'},operation:{...operation,id:'orders::GET /widgets/{id}'},id:'b'});
const changed = M.updateDraft(tab,{parameters:{'path.id':17},headers:{'X-Test':'first'}});
const saved = M.saveDraft(changed);
process.stdout.write(JSON.stringify({changed,saved,original:tab,sibling}));
""")
    assert result["changed"]["dirty"]
    assert not result["saved"]["dirty"]
    assert result["saved"]["savedDraft"]["parameters"] == {"path.id": 17}
    assert result["original"]["draft"]["parameters"] == {}
    assert result["sibling"]["draft"]["headers"] == {}


def test_close_restore_retains_unsaved_draft_and_exact_scope():
    result = model("""
const changed = M.updateDraft(tab,{body:'{"enabled":false}',bodyEntered:true});
const closed = M.closeTab({tabs:[changed],selectedTab:'a',closedTabs:[]},'a');
const restored = M.restoreClosed(closed);
process.stdout.write(JSON.stringify({closed,restored}));
""")
    assert result["closed"]["tabs"] == []
    assert result["closed"]["selectedTab"] is None
    restored = result["restored"]["tabs"][0]
    assert restored["dirty"]
    assert restored["draft"]["body"] == '{"enabled":false}'
    assert restored["contractId"] == "accounts"


def test_missing_path_value_stays_unspecified_and_optional_query_is_omitted():
    result = model("process.stdout.write(JSON.stringify(M.requestPayload(tab,contract)));" )
    assert result["request"]["parameters"] == {}
    assert "body" not in result["request"]
    assert "url" not in result["request"]
    assert not result["allow_mutating"]
    assert "identity_ref" not in result


def test_parameter_change_rebuilds_url_but_explicit_url_override_is_preserved():
    result = model("""
let edited = M.updateDraft(tab,{parameters:{'path.id':17},url:'http://127.0.0.1:9138/v1/widgets/old',manualUrl:false});
const generated = M.requestPayload(edited,contract);
edited = M.updateDraft(edited,{url:'http://127.0.0.1:9138/v1/widgets/custom',manualUrl:true});
process.stdout.write(JSON.stringify({generated,manual:M.requestPayload(edited,contract)}));
""")
    assert "url" not in result["generated"]["request"]
    assert result["generated"]["request"]["parameters"] == {"path.id": 17}
    assert result["manual"]["request"]["url"].endswith("/custom")


def test_body_absence_empty_string_null_and_json_remain_distinct():
    result = model("""
const bodies = [{}, {body:'',bodyEntered:true}, {body:'null',bodyEntered:true}, {body:'{"id":17}',bodyEntered:true}];
process.stdout.write(JSON.stringify(bodies.map(patch => M.requestPayload(M.updateDraft(tab,patch),contract).request)));
""")
    assert "body" not in result[0]
    assert result[1]["body"] == ""
    assert result[2]["body"] is None
    assert result[3]["body"] == {"id": 17}


@pytest.mark.parametrize("patch", ["{assertionsInvalid:true}", "{body:'{invalid',bodyEntered:true}"])
def test_invalid_body_and_assertions_block_payload(patch):
    result = model(f"try {{ M.requestPayload(M.updateDraft(tab,{patch}),contract); process.stdout.write('false'); }} catch {{ process.stdout.write('true'); }}")
    assert result


def test_environment_resolution_is_scoped_and_unknown_variables_or_target_require_review():
    result = model("""
const edited = M.updateDraft(tab,{parameters:{'path.id':'{{resource}}'}});
let missing=false, changedTarget=false;
try { M.requestPayload(edited,contract,{variables:{}}); } catch { missing=true; }
try { M.requestPayload(edited,contract,{variables:{resource:17},targets:{accounts:'http://127.0.0.1:9138/v2'}}); } catch { changedTarget=true; }
process.stdout.write(JSON.stringify({missing,changedTarget,request:M.requestPayload(edited,contract,{variables:{resource:17},targets:{accounts:contract.target}}).request}));
""")
    assert result["missing"] and result["changedTarget"]
    assert result["request"]["parameters"]["path.id"] == "17"


def test_nonsecret_persistence_retains_refs_but_never_evidence_tokens_or_write_consent():
    result = model("""
const dirty = M.updateDraft(tab,{headers:{Authorization:'Bearer secret-one','X-Trace':'keep'},body:'{"password":"secret-two"}',assertionsText:'{"token":"secret-three"}',identityRef:'shared'});
dirty.writeConsent = true; dirty.record = {result:{body:'retained evidence must be stored only in history'}};
dirty.result = {body:'also not a draft'};
process.stdout.write(JSON.stringify(M.serialise({tabs:[dirty],closedTabs:[dirty],selectedTab:'a',environments:[{variables:{api_key:'secret-four'}}]})));
""")
    encoded = json.dumps(result)
    for secret in ("secret-one", "secret-two", "secret-three", "secret-four", "retained evidence", "also not a draft", "writeConsent"):
        assert secret not in encoded
    assert result["tabs"][0]["draft"]["identityRef"] == "shared"
    assert result["tabs"][0]["draft"]["headers"]["X-Trace"] == "keep"


def test_large_contract_tab_creation_keeps_only_one_operation_draft():
    result = model("""
contract.operations = Array.from({length:5000},(_,i)=>({...operation,id:'op-'+i}));
const chosen = M.createTab({workspace,contract,operation:contract.operations[3210],id:'large'});
process.stdout.write(JSON.stringify({operation:chosen.operationKey,bytes:JSON.stringify(chosen).length}));
""")
    assert result["operation"] == "op-3210"
    assert result["bytes"] < 2000
