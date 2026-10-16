"""Exercise real callback draft edits with network dispatch forbidden."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path("namazu/static").resolve()


def edit(script):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    prelude = f"require({json.dumps(str(STATIC / 'desktop-model.js'))});\n"
    prelude += f"const T = require({json.dumps(str(STATIC / 'desktop-testing.js'))});\n"
    prelude += "global.fetch=()=>{throw Error('Offline editing must never dispatch');};\n"
    result = subprocess.run(["node", "-e", prelude + script], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_body_callback_preserves_other_fields_and_draft_without_mutation():
    result = edit("""
const original={body:JSON.stringify({callbacks:[{url:'old',mode:'async'}],owner:'accounts'}),parameters:{},headers:{'X-Check':'one'}};
const changed=T.applyCallback(original,{location:'body',pointer:'/callbacks/0/url'},'https://n-one.session.callback.test/namazu/n-one');
process.stdout.write(JSON.stringify({original,changed}));
""")
    assert json.loads(result["original"]["body"])["callbacks"][0]["url"] == "old"
    body = json.loads(result["changed"]["body"])
    assert body["callbacks"][0]["mode"] == "async"
    assert body["owner"] == "accounts"
    assert body["callbacks"][0]["url"].startswith("https://n-one.")
    assert result["changed"]["bodyEntered"]
    assert result["changed"]["headers"] == {"X-Check": "one"}


def test_query_callback_updates_manual_url_and_preserves_unrelated_inputs():
    result = edit("""
const draft={manualUrl:true,url:'http://127.0.0.1:9138/v1/widgets?id=17&callback=old',parameters:{'path.id':17,'query.limit':2}};
const changed=T.applyCallback(draft,{location:'query',name:'callback'},'https://n-one.callback.test/path?a=1');
process.stdout.write(JSON.stringify({changed,url:Object.fromEntries(new URL(changed.url).searchParams),original:draft}));
""")
    assert result["url"] == {"id": "17", "callback": "https://n-one.callback.test/path?a=1"}
    assert result["changed"]["parameters"]["path.id"] == 17
    assert result["changed"]["parameters"]["query.limit"] == 2
    assert "query.callback" not in result["original"]["parameters"]


@pytest.mark.parametrize("name", ["Authorization", "Cookie", "X-Api-Key"])
def test_callback_cannot_be_inserted_into_credential_header(name):
    result = edit(f"""
let error='';try{{T.applyCallback({{headers:{{}}}},{{location:'header',name:{json.dumps(name)}}},'https://callback.test');}}catch(e){{error=e.message;}}
process.stdout.write(JSON.stringify(error));
""")
    assert "noncredential" in result


@pytest.mark.parametrize("pointer", ["/missing/url", "/__proto__/polluted", "/items/9", "/items/-1"])
def test_invalid_body_pointer_does_not_create_unreviewed_structure(pointer):
    result = edit(f"""
let error='';try{{T.applyCallback({{body:'{{"items":["old"]}}'}},{{location:'body',pointer:{json.dumps(pointer)}}},'https://callback.test');}}catch(e){{error=e.message;}}
process.stdout.write(JSON.stringify({{error,polluted:{{}}.polluted||false}}));
""")
    assert result["error"]
    assert not result["polluted"]


def test_escaped_json_pointer_targets_the_exact_field():
    result = edit("""
const changed=T.applyCallback({body:JSON.stringify({'a/b':{'~name':'old'}})},
 {location:'body',pointer:'/a~1b/~0name'},'https://callback.test');
process.stdout.write(changed.body);
""")
    assert result == {"a/b": {"~name": "https://callback.test"}}


def test_delayed_case_load_exposes_no_editor_that_a_late_response_can_erase():
    result = edit("""
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.attributes={};this.value='';}
 append(...items){this.children.push(...items);}
 replaceChildren(...items){this.children=items;}
 setAttribute(key,value){this.attributes[key]=value;}
}
const host=new Element('section');
global.document={getElementById:()=>host,createElement:tag=>new Element(tag)};
const all=node=>[node,...node.children.flatMap(all)];
let finish;
const workspace={id:'w',contracts:[{id:'c',title:'Contract',target:'http://127.0.0.1/api',config:{operation_ids:[]},operations:[]}]};
const view=T.create({workspace:()=>workspace,activeTab:()=>({id:'tab',contractId:'c',localOperationId:'GET /x',snapshotHash:'hash'}),
 show(){},status(){},api:()=>new Promise(resolve=>{finish=resolve;})});
(async()=>{
 const opening=view.open();
 const before={busy:host.attributes['aria-busy'],inputs:all(host).filter(node=>['input','textarea','select'].includes(node.tagName)).length};
 finish({cases:[]});await opening;
 const input=all(host).find(node=>node.attributes['aria-label']==='Explicit callback base URL');
 input.value='https://typed.session.callback.test';input.oninput();
 await Promise.resolve();await new Promise(setImmediate);
 process.stdout.write(JSON.stringify({before,ready:host.attributes['aria-busy'],same:all(host).includes(input),value:input.value}));
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
""")
    assert result["before"] == {"busy": "true", "inputs": 0}
    assert result["ready"] == "false"
    assert result["same"] and result["value"] == "https://typed.session.callback.test"
