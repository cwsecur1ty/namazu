"""Deterministic async lifecycle checks for the actual workbench script."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path("namazu/static").resolve()


@pytest.mark.parametrize("edit_tabs", [False, True])
def test_startup_blocks_interaction_and_native_import_waits_for_restoration(edit_tabs):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    script = r"""
class Element {
 constructor(tag='div') {this.tagName=tag;this.children=[];this.dataset={};this.attributes={};this.style={setProperty(){}};this.classList={add(){},remove(){},toggle(){}};this.value='';this.textContent='';this.hidden=false;}
 append(...values){this.children.push(...values);}
 replaceChildren(...values){this.children=values;}
 setAttribute(key,value){this.attributes[key]=value;}
 addEventListener(){}
 querySelectorAll(){return [];}
 get selectedOptions(){return this.children.filter(item=>item.value===this.value);}
}
const elements=new Map();
const element=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
global.document={body:new Element(),documentElement:new Element(),getElementById:element,
 createElement:tag=>new Element(tag),createDocumentFragment:()=>new Element(),querySelectorAll:()=>[],querySelector:()=>null,addEventListener(){}};
global.addEventListener=()=>{};
global.NamazuWorkbench={setTheme:()=>{}};
global.NamazuDesktopHeader={create:()=>({update(){},openImport(){}})};
global.NamazuStartup={complete:async()=>{},fail:()=>{}};
let opened=0;
global.NamazuWorkspaces={instance:{open:async()=>{opened++;}}};
let finishState,finishWorkspace,saves=0,lastSaved;
const response=value=>({ok:true,json:async()=>value});
global.fetch=(path,options)=>{
 if(path==='/api/desktop/state'&&options.method==='GET')return new Promise(resolve=>{finishState=resolve;});
 if(path==='/api/workspaces')return Promise.resolve(response({workspaces:[{id:'w',title:'Saved workspace'}]}));
 if(path==='/api/workspaces/w')return new Promise(resolve=>{finishWorkspace=resolve;});
 if(path==='/api/desktop/state'&&options.method==='PUT'){saves++;lastSaved=JSON.parse(options.body).state;return Promise.resolve(response({revision:8+saves}));}
 throw Error('Unexpected request: '+path);
};
require(MODEL);
require(VIEW);
(async()=>{
 const initialInert=element('desktop-workbench').inert;
 const importing=NamazuDesktop.importContracts();
 finishState(response({revision:8,state:{activeWorkspaceId:'w'}}));
 await new Promise(setImmediate);
 const restoringInert=element('desktop-workbench').inert;
 const openedEarly=opened;
 const operation={id:'c::GET /items',local_id:'GET /items',method:'GET',path:'/items',parameters:[]};
 const contract={id:'c',title:'Contract',hash:'hash',target:'http://127.0.0.1:9138',target_review_required:true,operations:[operation]};
 finishWorkspace(response({id:'w',title:'Saved workspace',contracts:[contract],overlaps:[]}));
 await importing;
 const reviewHidden=element('desktop-workspace-review').hidden;
 await NamazuDesktop.flush();
 let assertionsVisible;
 if(EDIT_TABS){
   await NamazuDesktop.openOperation(contract,operation);
   element('desktop-request-url').value='http://127.0.0.1:9138/items?edited=1';
   element('desktop-request-url').oninput();
   await element('desktop-editor-tabs').children.find(item=>item.textContent==='Assertions').onclick();
   assertionsVisible=element('desktop-editor').children.some(item=>item.attributes['aria-label']==='Response assertions JSON');
   await element('desktop-response-tabs').children.find(item=>item.textContent==='Headers').onclick();
   await NamazuDesktop.flush();
 }
 process.stdout.write(JSON.stringify({initialInert,restoringInert,openedEarly,opened,
   ready:element('desktop-workbench').dataset.ready,inert:element('desktop-workbench').inert,
   reviewHidden,error:element('desktop-error').textContent,saves,assertionsVisible,lastSaved}));
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
"""
    script = script.replace("MODEL", json.dumps(str(STATIC / "desktop-model.js"))).replace("VIEW", json.dumps(str(STATIC / "desktop-workbench.js")))
    script = script.replace("EDIT_TABS", str(edit_tabs).lower())
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    state = json.loads(result.stdout)
    assert state["initialInert"] and state["restoringInert"]
    assert state["openedEarly"] == 0
    assert state["opened"] == 1
    assert state["ready"] == "true" and not state["inert"]
    assert not state["reviewHidden"]
    assert state["error"] == ""
    assert state["saves"] == (2 if edit_tabs else 1)
    if edit_tabs:
        assert state["assertionsVisible"]
        assert state["lastSaved"]["tabs"][0]["requestTab"] == "assertions"
        assert state["lastSaved"]["tabs"][0]["responseTab"] == "headers"
