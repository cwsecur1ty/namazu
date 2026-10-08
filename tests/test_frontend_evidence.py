"""Static checks on the browser code for the evidence, coverage and replay work.

The frontend has no test harness, so these catch the class of bug that reads
as working code: a field the page sends under a name the server does not
expect, a label table that has drifted from the server's vocabulary, or a
display that can present a blocked check as a clean one.

The last of those is the one that matters. The whole point of the coverage
ledger is that a reader cannot mistake "not tested" for "nothing found", and a
frontend that quietly rolled several endpoints' states into a majority would
undo it in one line.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

APP = Path("namazu/static/app.js")
HTML = Path("namazu/static/index.html")
CSS = Path("namazu/static/style.css")


@pytest.fixture(scope="module")
def source():
    return APP.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def markup():
    return HTML.read_text(encoding="utf-8")


def _table(source: str, name: str) -> set:
    """The keys of a `const <name> = { ... }` label table."""
    match = re.search(rf"const {re.escape(name)} = \{{(.+?)\n  \}};", source, re.DOTALL)
    assert match, f"{name} not found in {APP}"
    return set(re.findall(r'^\s{4}"?([a-z-]+)"?:', match.group(1), re.MULTILINE))


# ── the vocabularies have to agree with the server ──────────────────────────

def test_the_category_labels_cover_every_category_the_server_emits(source):
    from namazu.audit.evidence import CATEGORIES
    assert _table(source, "CATEGORY_LABEL") == set(CATEGORIES), (
        "app.js would render a raw category name, or carry a label for one that no longer "
        "exists")


def test_the_origin_labels_cover_every_origin_the_server_emits(source):
    from namazu.audit.evidence import ORIGINS
    assert _table(source, "ORIGIN_LABEL") == set(ORIGINS)


def test_the_verification_labels_cover_every_rung_of_the_ladder(source):
    from namazu.audit.evidence import VERIFICATION
    assert _table(source, "VERIFICATION_LABEL") == set(VERIFICATION)


def test_the_replay_labels_cover_every_outcome(source):
    from namazu.audit.capture import REPLAY_OUTCOMES
    assert _table(source, "REPLAY_LABEL") == set(REPLAY_OUTCOMES)


def test_the_coverage_labels_cover_every_state(source):
    from namazu.audit.coverage import STATES
    assert _table(source, "COVERAGE_LABEL") == set(STATES)


def test_the_coverage_order_lists_every_state_so_none_falls_through(source):
    from namazu.audit.coverage import STATES
    match = re.search(r"const COVERAGE_ORDER = \[(.+?)\];", source, re.DOTALL)
    assert match
    listed = set(re.findall(r'"([a-z-]+)"', match.group(1)))
    assert listed == set(STATES), (
        "coverageState() walks COVERAGE_ORDER and falls back to 'skipped'. A state missing from "
        "it would be displayed as 'Not in this profile', which for a blocked check is the one "
        "wrong answer.")


def test_the_severity_rules_in_the_export_legend_match_the_real_rules(source):
    """The legend travels inside the export, so a reader can argue a severity
    without the application. A stale entry there is worse than none."""
    from namazu.audit.evidence import SEVERITY_RULES
    match = re.search(r"severity_rules: \{(.+?)\n    \},", source, re.DOTALL)
    assert match, "the export no longer carries the severity rules"
    listed = set(re.findall(r'"([a-z-]+)":', match.group(1)))
    assert listed == {rule.id for rule in SEVERITY_RULES}


# ── the worst state wins ────────────────────────────────────────────────────

def test_the_displayed_coverage_state_is_the_worst_one_not_the_commonest(source):
    """A check completed on four endpoints and blocked on a fifth has a gap.
    Reporting the majority state would bury exactly what the reader needs."""
    assert re.search(r"function coverageState\(held\) \{\s*\n\s*for \(const name of COVERAGE_ORDER\)",
                     source), "coverageState no longer walks the order, so it may not pick the worst"
    order = re.search(r"const COVERAGE_ORDER = \[(.+?)\];", source, re.DOTALL).group(1)
    names = re.findall(r'"([a-z-]+)"', order)
    assert names.index("blocked") < names.index("completed")
    assert names.index("inconclusive") < names.index("completed")


def test_the_coverage_report_never_calls_a_check_passed(source):
    """"Passed" is a claim about the target. "Ran" is a statement about the audit.

    Scoped to the coverage rendering. Elsewhere "Contract passed" is the
    response validation label, which describes one response against one
    schema; that is a different claim and it was already there.
    """
    labels = source[source.index("const COVERAGE_LABEL"):source.index("function assessmentOf")]
    assert "pass" not in labels.lower(), (
        "a coverage state is labelled as a pass, which reads as a claim that the target is "
        f"sound rather than a statement that a check ran: {labels}")
    # And the report says so in words, because a reader should not have to
    # infer the distinction from the choice of label.
    card = source[source.index("function coverageCard()"):source.index("function baselineCard()")]
    assert "not as " in card and "passed" in card, (
        "the coverage report no longer explains that a check which ran is not a pass")
    assert "statement that the target is sound" in card


# ── what the page sends has to be what the server reads ─────────────────────

def test_the_tool_run_payload_names_the_tool_in_the_field_the_server_reads(source):
    """It used to travel in `profile`, so one request could not say both which
    tool to run and what traffic policy to run it under."""
    from namazu.app import ToolInput
    assert "tool" in ToolInput.model_fields
    block = re.search(r'api\("/api/tools/run", \{(.+?)\n      \}\);', source, re.DOTALL)
    assert block, "the tool run call was not found"
    assert re.search(r"\btool: name\b", block.group(1))
    assert not re.search(r"\bprofile: name\b", block.group(1))


@pytest.mark.parametrize("route,model,fields", [
    ("/api/replay", "ReplayInput", ["case", "identities", "attempts", "allow_mutating"]),
    ("/api/correlate", "CorrelateInput", ["findings"]),
])
def test_every_field_the_page_sends_exists_on_the_server_model(source, route, model, fields):
    import namazu.app as app_module
    declared = set(getattr(app_module, model).model_fields)
    block = re.search(rf'api\("{re.escape(route)}", \{{(.+?)\n      \}}\)', source, re.DOTALL)
    assert block, f"the {route} call was not found in {APP}"
    for field in fields:
        # Either `field: value` or the shorthand `field,`.
        pattern = r"(^|[\s{,])" + re.escape(field) + r"\s*[:,]"
        assert re.search(pattern, block.group(1), re.MULTILINE), (
            f"{route} no longer sends {field}")
        assert field in declared, f"{model} has no {field} field"


def test_the_audit_call_sends_the_saved_example_and_expectation(source):
    from namazu.app import AuditInput
    assert {"example", "expectation"} <= set(AuditInput.model_fields)
    assert "example: saved.example" in source
    assert "expectation: saved.expectation" in source


# ── replay cannot overstate what it established ─────────────────────────────

def test_a_reproduced_replay_never_raises_a_finding_past_reproduced(source):
    """Replay establishes the behaviour. It is not evidence of impact, and
    "impact-demonstrated" is the rung that unlocks critical."""
    block = re.search(r'if \(result\.outcome === "reproduced"\) \{(.+?)\n      \}',
                      source, re.DOTALL)
    assert block, "the replay promotion branch was not found"
    assert 'verification = "reproduced"' in block.group(1)
    assert "impact-demonstrated" not in block.group(1)


def test_the_replay_view_always_says_what_replay_does_not_establish(source):
    assert re.search(r"box\.append\(el\(\"p\", \"hint\", result\.note", source), (
        "the replay view no longer renders the server's note, which is the sentence saying a "
        "reproduced response is not by itself a security weakness")
    from namazu.audit.capture import ReplayResult
    note = ReplayResult("reproduced").to_dict()["note"]
    assert "does not establish that the behaviour is a security weakness" in note


def test_replay_never_offers_to_send_a_placeholder_credential(source):
    """The server refuses it; the page has to explain why rather than looking
    broken when it does."""
    assert "placeholder" in source
    assert "never sent as a credential" in source


# ── the markup exists for everything the script reaches for ─────────────────

def test_every_element_the_new_code_looks_up_exists_in_the_markup(source, markup):
    ids = set(re.findall(r'\$\("([a-z0-9-]+)"\)', source))
    present = set(re.findall(r'id="([a-z0-9-]+)"', markup))
    missing = sorted(ids - present)
    assert not missing, f"app.js reads elements that index.html does not define: {missing}"


def test_the_baseline_editor_explains_why_a_generated_request_is_a_problem(markup):
    block = re.search(r'id="baseline-block"(.+?)</details>', markup, re.DOTALL)
    assert block, "the baseline editor is not in the markup"
    text = block.group(1)
    assert "<code>string</code>" in text, "it does not name the placeholder value"
    assert "2xx is not always success" in text
    assert "supposed" in text, "it does not explain the negative-test case"
    assert "resource marker" in text.lower()


def test_the_baseline_editor_says_a_saved_example_cannot_change_the_identity(markup):
    block = re.search(r'id="baseline-block"(.+?)</details>', markup, re.DOTALL)
    assert "Credential headers in a saved example are ignored" in block.group(1)


def test_the_import_control_exists_and_accepts_json(markup):
    assert 'id="import-audit"' in markup
    assert re.search(r'id="import-audit-file"[^>]*accept="application/json,\.json"', markup)


# ── the CSS covers the states, so none renders unstyled ────────────────────

@pytest.mark.parametrize("selector", [
    '.cov-row[data-state="blocked"]',
    '.cov-row[data-state="inconclusive"]',
    '.cov-row[data-state="completed"]',
    '.chip[data-cov="blocked"]',
    '.chip[data-replay="reproduced"]',
    '.chip[data-replay="not-reproduced"]',
    '.axis[data-kind="category"]',
    '.axis[data-kind="verification"]',
])
def test_the_styles_distinguish_each_state(selector):
    assert selector in CSS.read_text(encoding="utf-8"), f"{selector} has no style, so it renders flat"


def test_a_reproduced_replay_is_not_styled_as_a_success():
    """It is the finding being confirmed, not a clean result. Green would read
    as the opposite of what happened."""
    css = CSS.read_text(encoding="utf-8")
    reproduced = re.search(r'\.chip\[data-replay="reproduced"\] \{([^}]+)\}', css).group(1)
    not_reproduced = re.search(r'\.chip\[data-replay="not-reproduced"\] \{([^}]+)\}', css).group(1)
    assert "--bad" in reproduced
    assert "--ok" in not_reproduced


# ── the export round trip, through the real parser ─────────────────────────

def test_the_export_legend_and_coverage_survive_a_javascript_round_trip(tmp_path):
    """The export is built in the browser and read back by whatever the client
    uses. This runs the structure through node, because that is the consumer
    that destroyed a seed once already.
    """
    from namazu.audit.model import json_safe
    seed = 231519461134919091197611956279382553858
    payload = json_safe({
        "export": "security-audit",
        "coverage": {"checks": [{"check": "authorization", "state": "blocked",
                                 "reasons": ["the baseline did not succeed"]}]},
        "findings": [{"id": "schemathesis.content-type",
                      "evidence": {"seed": seed},
                      "cases": [{"seed": str(seed), "status": 403}]}],
    })
    source = tmp_path / "export.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    script = tmp_path / "read.js"
    script.write_text(
        "const fs = require('fs');\n"
        "const d = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
        "process.stdout.write(JSON.stringify({\n"
        "  blocked: d.coverage.checks.filter(c => c.state === 'blocked').length,\n"
        "  seed: d.findings[0].evidence.seed,\n"
        "  caseSeed: d.findings[0].cases[0].seed,\n"
        "}));\n", encoding="utf-8")
    try:
        done = subprocess.run(["node", str(script), str(source)], capture_output=True,
                              text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"node is not available: {exc}")
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout)
    assert result["blocked"] == 1
    assert result["seed"] == str(seed)
    assert result["caseSeed"] == str(seed)


def test_the_import_path_lists_the_keys_it_knows(source):
    """Anything else is reported as unrecognised rather than dropped silently."""
    match = re.search(r"const KNOWN_EXPORT_KEYS = new Set\(\[(.+?)\]\);", source, re.DOTALL)
    assert match
    known = set(re.findall(r'"([a-z_]+)"', match.group(1)))
    # Every key exportAudit writes has to be in the set, or opening Namazu's
    # own export would report its own fields as unrecognised.
    written = set(re.findall(r"^      ([a-z_]+):", source, re.MULTILINE))
    for key in ("coverage", "replays", "duplicates", "evidence_levels", "findings",
                "summary", "notes", "scope"):
        assert key in known, f"the importer does not know about {key}"
    assert "evidence_levels" in written


# ── the access testing view ─────────────────────────────────────────────────

def test_the_matrix_and_sequence_calls_match_the_server_models(source):
    from namazu.app import MatrixInput, SequenceInput
    for route, model, fields in (
        ("/api/matrix", MatrixInput, ["rows", "identities", "allow_mutating"]),
        ("/api/sequence", SequenceInput, ["steps", "identities", "allow_mutating"]),
    ):
        block = re.search(rf'api\("{re.escape(route)}", \{{(.+?)\n      \}}\)', source, re.DOTALL)
        assert block, f"the {route} call was not found"
        for field in fields:
            assert re.search(r"(^|[\s{,])" + re.escape(field) + r"\s*[:,]",
                             block.group(1), re.MULTILINE), f"{route} no longer sends {field}"
            assert field in model.model_fields


def test_the_matrix_outcome_labels_cover_every_outcome(source):
    from namazu.audit.matrix import MATRIX_OUTCOMES
    assert _table(source, "MATRIX_OUTCOME_LABEL") == set(MATRIX_OUTCOMES)


def test_the_sequence_view_never_shows_an_extracted_value(source):
    """The server sends names only, and the page says why rather than looking
    as though it lost the values."""
    block = source[source.index("function renderSequenceResult()"):
                   source.index("function wireAccess()")]
    assert "result.variables.join" in block
    assert "often a credential" in block
    assert "result.values" not in block


def test_a_write_sequence_is_refused_in_the_browser_before_it_is_sent(source):
    """The server refuses it too. Checking here as well means the operator is
    told why instead of watching a step come back blocked."""
    block = source[source.index("async function runSequence()"):
                   source.index("function renderSequenceResult()")]
    assert 'connection.allow_mutating' in block
    assert "Allow writes" in block


def test_the_matrix_template_includes_a_positive_control_row(source):
    """A template that produced only deny rows would hand the operator a matrix
    that cannot conclude anything."""
    block = source[source.index("function matrixTemplate()"):
                   source.index("function accessIdentities(")]
    assert block.count('expect: "allow"') >= 2
    assert 'expect: "deny"' in block


def test_the_access_view_explains_the_positive_control_and_the_marker(markup):
    block = re.search(r'id="view-access"(.+?)\n    </section>', markup, re.DOTALL)
    assert block, "the access view is not in the markup"
    text = block.group(1)
    assert "positive control has passed" in text
    assert "refuses everybody looks exactly like" in text
    assert "not the status code" in text
    assert "not a workflow language" in text
    assert "nothing is ever deleted" in text.lower()


def test_the_access_view_is_registered_as_a_section_and_a_view(source, markup):
    assert 'access: { view: "view-access" }' in source
    assert '"view-access"' in source.split("const VIEWS")[1].split("]")[0]
    assert 'data-section="access"' in markup
