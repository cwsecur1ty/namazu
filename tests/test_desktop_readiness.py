"""Fixed startup receipts must prove usable rendering without reflecting secrets."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HELPER = Path("namazu/static/desktop-readiness.js").resolve()


def receipt(action):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    script = r"""
const {create}=require(HELPER);
const nodes=new Map(),frames=[],events={};
function element(id){
 if(!nodes.has(id))nodes.set(id,{id,hidden:false,inert:false,disabled:false,dataset:{},childElementCount:1,textContent:'Workspace',
 style:{display:id==='desktop-workbench'?'grid':id==='toolbar'?'flex':'block',visibility:'visible',opacity:'1'},
 onclick(){},onchange(){},closest(selector){return selector==='[inert]'&&this.inert?this:null;},contains(node){return node===this;},
 getBoundingClientRect(){return {left:0,top:0,width:900,height:600,right:900,bottom:600};}});
 return nodes.get(id);
}
let build='source',missingStyle=false;
const doc={getElementById:element,querySelector(selector){
 if(selector.startsWith('meta'))return {content:build};
 if(selector.startsWith('link'))return missingStyle?null:{sheet:{cssRules:[{}]}};
 if(selector==='.desktop-toolbar')return element('toolbar');
},querySelectorAll(){return [element('view')];},elementFromPoint(){return currentHit;}};
let currentHit;
const win={innerWidth:1200,innerHeight:800,getComputedStyle(node){currentHit=node;return node.style;},
 requestAnimationFrame(fn){frames.push(fn);},addEventListener(name,fn){events[name]=fn;}};
for(const name of ['NamazuSetup','NamazuAuditResults','NamazuAuditResultsView','NamazuAssessmentView','NamazuReadiness','NamazuBruno','NamazuBrunoImport','NamazuIdentities','NamazuWorkbench','NamazuWorkspaces','NamazuDesktopModel','NamazuDesktopTesting','NamazuDesktopHeader','NamazuDesktop'])win[name]={};
win.NamazuWorkspaces.instance={};
const startup=create(win,doc);
async function finish(){const pending=startup.complete();frames.shift()();frames.shift()();try{await pending;}catch{}return startup.snapshot();}
(async()=>{ACTION})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
"""
    script = script.replace("HELPER", json.dumps(str(HELPER))).replace("ACTION", action)
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_readiness_waits_for_initialization_and_two_render_frames():
    state = receipt("""
const before=startup.snapshot(),pending=startup.complete();const beforePaint=startup.snapshot();
frames.shift()();const onePaint=startup.snapshot();frames.shift()();await pending;
process.stdout.write(JSON.stringify({before,beforePaint,onePaint,after:startup.snapshot()}));
""")
    assert all(state[name]["status"] == "loading" for name in ("before", "beforePaint", "onePaint"))
    assert state["after"]["status"] == "ready"
    assert all(state["after"]["checks"].values())


@pytest.mark.parametrize(("change", "code"), [
    ("delete win.NamazuDesktopModel;", "dependencies-missing"),
    ("delete win.NamazuBrunoImport;", "dependencies-missing"),
    ("delete win.NamazuIdentities;", "dependencies-missing"),
    ("missingStyle=true;", "styles-missing"),
    ("element('desktop-workbench').style.display='none';", "render-not-visible"),
    ("element('view').childElementCount=0;", "render-not-visible"),
    ("element('desktop-import').onclick=null;", "controls-unbound"),
    ("doc.elementFromPoint=()=>element('blocking-overlay');", "controls-unbound"),
])
def test_missing_or_unusable_surface_never_becomes_ready(change, code):
    state = receipt(change + "process.stdout.write(JSON.stringify(await finish()));")
    assert state["status"] == "failed" and state["code"] == code


@pytest.mark.parametrize("build", ["source", "namazu-0123456789abcdef01234567"])
def test_only_normalized_source_or_packaged_build_ids_are_exposed(build):
    state = receipt("build=" + json.dumps(build) + ";process.stdout.write(JSON.stringify(await finish()));")
    assert state["buildId"] == build and state["status"] == "ready"


def test_untrusted_build_id_and_exception_messages_are_not_reflected():
    state = receipt("""
build='credential-secret-not-a-build';events.error({target:win,message:'Bearer credential-secret'});
const result=startup.snapshot();process.stdout.write(JSON.stringify({result,inert:element('desktop-workbench').inert}));
""")
    assert "credential-secret" not in json.dumps(state)
    assert state["result"]["buildId"] == "invalid"
    assert state["result"]["code"] == "script-error"
    assert state["result"]["status"] == "failed" and state["inert"]


def test_entrypoint_loads_receipt_before_other_assets_and_has_one_build_meta():
    html = Path("namazu/static/index.html").read_text(encoding="utf-8")
    assert html.count('name="namazu-build-id"') == 1
    assert html.index('src="/static/desktop-readiness.js"') < html.index('href="/static/style.css"')
