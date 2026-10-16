"""Exercise evidence labels and finding separation without a live target."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SOURCE = Path("namazu/static/app.js").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(r"  function " + name + r"\([^\n]*\) \{(?:[^\n]*\}|.*?^  \})",
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


HELPERS = constant("VERIFICATION_LABEL") + "\n".join(function(name) for name in (
    "assessmentOf", "presentationLevel", "presentationLabel", "isVulnerability", "findingSections"))


def finding(key, origin="runtime-observation", verification="observed", category="security",
            confidence="confirmed"):
    return {"id": key, "key": key, "title": key, "confidence": confidence, "severity": "low",
            "endpoint": "POST /local-mock", "assessment": {
                "category": category, "origin": origin, "verification": verification}}


@pytest.mark.parametrize("item,expected", [
    (finding("spec.oauth", origin="static-declaration", verification="unverified"),
     "Specification observation"),
    ({"id": "spec.legacy", "confidence": "confirmed"}, "Specification observation"),
    (finding("observed", confidence="possible"), "Observed behaviour"),
    (finding("replayed", verification="reproduced"), "Reproduced behaviour"),
    (finding("impact", verification="impact-demonstrated"), "Demonstrated security impact"),
    ({"id": "legacy", "confidence": "confirmed"}, "Not verified"),
    (finding("static-invalid-level", origin="static-declaration", verification="impact-demonstrated"),
     "Specification observation"),
])
def test_labels_use_evidence_level_never_confidence(item, expected):
    script = HELPERS + "process.stdout.write(JSON.stringify(presentationLabel(" + json.dumps(item) + ")));"
    output = node(script)
    assert output == expected


def test_groups_preserve_every_record_once_and_do_not_promote_security_leads():
    items = [finding("static", "static-declaration", "unverified", "hardening"),
             finding("denial-lead"), finding("replayed", verification="reproduced"),
             finding("external", origin="external-report", verification="reproduced"),
             finding("demonstrated", verification="impact-demonstrated"),
             finding("error", category="reliability"), {"id": "legacy", "confidence": "confirmed"}]
    script = HELPERS + "process.stdout.write(JSON.stringify(findingSections(" + json.dumps(items) + ")));"
    groups = node(script)
    assert groups[0]["title"] == "Demonstrated vulnerabilities"
    assert [item["id"] for item in groups[0]["items"]] == ["demonstrated"]
    assert groups[1]["title"] == "Observations and leads"
    assert [item["id"] for item in groups[1]["items"]] == [
        "static", "denial-lead", "replayed", "external", "error", "legacy"]
    flattened = [item for group in groups for item in group["items"]]
    assert len(flattened) == len(items)
    assert sorted(item["id"] for item in flattened) == sorted(item["id"] for item in items)


DOM = r"""
const nodes = new Map();
function el(tag, cls, value) {
  return {tag, className:cls || '', textContent:value ?? '', dataset:{}, children:[],
    append(...children) {this.children.push(...children);},
    replaceChildren(...children) {this.children = children;},
    addEventListener() {}, setAttribute() {}, focus() {}};
}
function $(id) {if (!nodes.has(id)) nodes.set(id, el('div')); return nodes.get(id);}
function auditHasReport() {return true;}
function renderSeverityBar() {} function sourceTag() {return null;}
function findingSource() {return '';}
function activateSection() {} function showView() {} function announce() {}
function markedInto(node, value) {node.textContent = value; return node;}
function highlightLegend() {return null;} function evidenceTable() {return null;}
function reportCard(title, children) {const node = el('section', '', title); node.append(...children); return node;}
"""


def test_sidebar_and_detail_render_static_claim_without_confirmed_badge():
    item = finding("spec.oauth", origin="static-declaration", verification="unverified",
                   category="hardening")
    item["detail"] = "The document declares a flow. Runtime behaviour remains unknown."
    item["assessment"]["confirmed_claim"] = "Only the imported declaration was established."
    script = DOM + HELPER_RENDER + "const item = " + json.dumps(item) + ";\n"
    script += r"""
const state = {busy:false,audit:{findings:[item],finding:null,running:false}};
$('finding-search').value = ''; $('severity-filter').value = 'all'; $('confidence-filter').value = 'all';
showFinding(item);
process.stdout.write(JSON.stringify({list:$('finding-list'),header:$('finding-severity'),body:$('finding-body')}));
"""
    result = node(script)
    assert result["header"]["textContent"] == "Specification observation"
    assert result["header"]["dataset"] == {"evidence": "specification"}
    rendered = json.dumps(result)
    assert "Specification observation" in rendered
    assert "Observations and leads" in rendered
    assert "What the recorded evidence establishes" in rendered
    assert "confirmed" not in rendered.lower()
    assert "Demonstrated vulnerabilities" not in rendered


HELPER_RENDER = HELPERS + constant("CATEGORY_LABEL") + constant("ORIGIN_LABEL")
HELPER_RENDER += "\n".join(function(name) for name in (
    "evidenceChips", "evidenceCard", "visibleFindings", "renderFindings", "showFinding"))


def test_filter_uses_specific_evidence_level_and_group_counts_follow_filtered_records():
    items = [finding("static", "static-declaration", "unverified", "hardening"),
             finding("runtime"), finding("replayed", verification="reproduced")]
    script = DOM + HELPER_RENDER + "const state = {audit:{findings:" + json.dumps(items) + "}};\n"
    script += r"""
$('finding-search').value = ''; $('severity-filter').value = 'all';
const filtered = {};
for (const level of ['specification','observed','reproduced','impact-demonstrated','all']) {
  $('confidence-filter').value = level;
  filtered[level] = visibleFindings().map(item => item.id);
}
$('confidence-filter').value = 'specification'; renderFindings();
process.stdout.write(JSON.stringify({filtered,list:$('finding-list'),total:$('audit-count').textContent}));
"""
    result = node(script)
    assert result["filtered"] == {"specification": ["static"], "observed": ["runtime"],
                                  "reproduced": ["replayed"], "impact-demonstrated": [],
                                  "all": ["static", "runtime", "replayed"]}
    assert result["total"] == 3
    heading = result["list"]["children"][0]
    assert heading["textContent"] == "Observations and leads"
    assert heading["children"][0]["textContent"] == "1"


def test_empty_results_do_not_invent_or_request_findings():
    result = node(DOM + HELPER_RENDER + r"""
const state = {audit:{findings:[],running:false}};
renderFindings();
process.stdout.write(JSON.stringify($('finding-list')));
""")
    text = json.dumps(result)
    assert "No finding records. Review test observations" in text
    assert "coverage and blockers" in text
    assert "No vulnerabilities or observations recorded" not in text
    assert "populate" not in text
