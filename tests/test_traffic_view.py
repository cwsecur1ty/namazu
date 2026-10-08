"""The traffic view: three panes over the request history, and what feeds them.

The browser code has no runtime harness, so the page and the script are checked
against each other statically. That catches the one failure mode here that
looks exactly like working code: a pane the script renders into through an id
the page does not carry, or a CSS variable one file writes and the other no
longer reads. Both leave the view blank or the gutters dead, and neither shows
up in ``node --check``.

The engine side is tested for real, because the traffic view is the only place
an operator reads a request that produced no finding, and how much of the body
reaches it is a deliberate number rather than an accident of the proof format.
"""
import inspect
import json
import re
from pathlib import Path

import httpx
import pytest

from namazu.audit import audit_operation
from namazu.audit.engine import LOG_BODY_CHARS
from namazu.audit.model import Exchange
from namazu.spec import parse_spec

STATIC = Path("namazu/static")
BASE = "https://api.example.test"
TOKEN = "alice-secret-token"


@pytest.fixture(scope="module")
def script():
    return (STATIC / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def page():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def stylesheet():
    return (STATIC / "style.css").read_text(encoding="utf-8")


# ── the page and the script agree ───────────────────────────────────────────

def test_every_element_the_script_reads_exists_in_the_page(script, page):
    """``$("id")`` on an element the page lacks throws on the first use.

    The page is one file and the script is another, so renaming an id in one
    of them is a silent break: the view that reads it stops rendering at the
    first access, and every handler wired after that line never runs.
    """
    read = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', script))
    present = set(re.findall(r'id="([A-Za-z0-9_-]+)"', page))
    missing = sorted(read - present)
    assert read, "no element ids parsed out of app.js"
    assert not missing, (
        "app.js reads elements the page does not have: " + ", ".join(missing))


def test_the_three_traffic_panes_are_in_the_page(page):
    """History, request and response, plus the handles between them."""
    for element in ("log-panes", "log-table-wrap", "log-rows",
                    "log-request-tabs", "log-request-body", "log-request-copy",
                    "log-response-tabs", "log-response-body", "log-response-copy",
                    "log-gutter-a", "log-gutter-b"):
        assert f'id="{element}"' in page, f"{element} is missing from the traffic view"


def test_the_findings_and_traffic_switch_goes_both_ways(page):
    """Either half of the audit result reaches the other without the panel."""
    assert 'id="report-traffic"' in page
    assert 'id="log-back"' in page


def test_the_pane_width_variables_are_written_and_read(script, stylesheet):
    """The script sets the widths; the grid is the only thing that reads them.

    Renaming the variable in one file leaves the panes stuck at the stylesheet
    default and the gutters apparently dead, with nothing raised anywhere.
    """
    for name in ("--pane-a", "--pane-b"):
        assert f'setProperty("{name}"' in script, f"app.js no longer sets {name}"
        assert f"var({name}" in stylesheet, f"style.css no longer reads {name}"


def test_the_stacking_breakpoint_is_the_same_in_both_files(script, stylesheet):
    """One width decides whether the panes are columns or rows.

    The stylesheet stacks them and the drag handler refuses to resize them;
    if the two disagree, dragging a hairline rewrites the widths of a layout
    that is not using them.
    """
    checked = re.search(r"function stackedPanes\(\) \{ return "
                        r"window\.matchMedia\(\"\(max-width: (\d+)px\)\"\)", script)
    assert checked, "stackedPanes no longer reads a max-width media query"
    assert f"@media (max-width: {checked.group(1)}px)" in stylesheet, (
        f"app.js stacks the panes below {checked.group(1)}px but style.css does not")


def test_the_traffic_view_keeps_a_row_selected(script):
    """The panes always describe a row the table is showing.

    Without this the panes keep rendering a request the filter has hidden,
    which reads as the selected row's request and response and is not.
    """
    assert "selectLogEntry(held || shown[0])" in script, (
        "renderLog no longer moves the selection onto a visible row")
    assert "selectLogEntry(null)" in script, (
        "an empty history no longer clears the request and response panes")


def test_the_raw_views_are_labelled_as_reconstructions(script):
    """Raw HTTP here is rebuilt from the parsed exchange, not captured bytes."""
    assert "RAW_NOTE" in script
    assert "not the bytes on the wire" in script


# ── what the engine sends to the panes ──────────────────────────────────────

def _spec():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "Shop", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/orders": {"get": {
            "security": [{"bearer": []}],
            "responses": {"200": {"description": "Orders", "content": {"application/json": {
                "schema": {"type": "object"}}}}},
        }}},
        "components": {"securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"}}},
    })


def _audit(handler, **kwargs):
    with httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE) as client:
        return audit_operation(_spec(), "GET /orders", base_url=BASE, client=client, **kwargs)


def test_the_log_carries_more_of_the_body_than_a_proof_excerpt():
    """A request with no finding behind it is only readable in the traffic view.

    The proof excerpt in a finding is short because a report quotes the part
    that matters. The log has no such help: whatever it keeps is all an
    operator can inspect.
    """
    filler = "x" * 9000
    result = _audit(lambda request: httpx.Response(200, json={"note": filler}))
    entry = result["log"][0]
    proof_width = inspect.signature(Exchange.excerpt).parameters["limit"].default
    assert proof_width < LOG_BODY_CHARS, (
        "the log excerpt is no wider than a finding's proof excerpt")
    # The ellipsis the excerpt appends is the one extra character.
    assert len(entry["body_excerpt"]) <= LOG_BODY_CHARS + 1
    assert len(entry["body_excerpt"]) > proof_width


def test_the_log_states_the_whole_body_length_it_is_excerpting():
    """The pane says "the first N of M characters", so M has to be the real M."""
    filler = "y" * 9000
    result = _audit(lambda request: httpx.Response(200, json={"note": filler}))
    entry = result["log"][0]
    assert entry["body_length"] > len(entry["body_excerpt"]), (
        "body_length was trimmed to the excerpt, so the pane cannot say how "
        "much of the body it is withholding")
    assert entry["body_length"] >= 9000


def test_the_wider_excerpt_did_not_widen_what_is_disclosed():
    """More body in the log must not mean the credential travels with it."""
    result = _audit(lambda request: httpx.Response(200, json={"ok": True}),
                    identities={"primary": {"Authorization": f"Bearer {TOKEN}"}})
    rendered = json.dumps(result["log"])
    assert TOKEN not in rendered
    assert "<credential>" in rendered
