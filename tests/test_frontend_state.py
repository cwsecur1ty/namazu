"""Static checks on the browser code, which has no test harness of its own.

These catch one specific class of bug: a piece of client state that several
branches read but nothing ever writes. That reads as working code, passes
``node --check``, and silently disables whatever depended on it. It is how the
OAuth refresh token came to be declared, commented, and read in three places
while always holding the empty string, which quietly turned every
authorization code identity into a static header that expires mid-audit.
"""
import re
from pathlib import Path

import pytest

APP = Path("namazu/static/app.js")
# Client state whose only job is to be handed to the server later, so a missing
# assignment cannot be caught by anything the page itself does.
CARRIED_STATE = ("oauthState",)


@pytest.fixture(scope="module")
def source():
    return APP.read_text(encoding="utf-8")


def _fields(source: str, holder: str) -> set:
    """The keys declared in `const <holder> = { ... }`."""
    match = re.search(rf"const {re.escape(holder)} = \{{(.+?)\}};", source, re.DOTALL)
    assert match, f"{holder} declaration not found in {APP}"
    return set(re.findall(r"(\w+)\s*:", match.group(1)))


@pytest.mark.parametrize("holder", CARRIED_STATE)
def test_every_field_of_carried_state_is_assigned_somewhere(source, holder):
    declared = _fields(source, holder)
    assert declared, f"no fields parsed out of {holder}"
    unassigned = sorted(
        field for field in declared
        if not re.search(rf"\b{re.escape(holder)}\.{field}\s*(=[^=]|\+=|\|\|=)", source)
    )
    assert not unassigned, (
        f"{holder} fields are read but never assigned: {', '.join(unassigned)}. "
        "A field nothing writes always holds its initial value, so every branch "
        "that reads it takes the wrong path.")


def test_the_oauth_refresh_token_reaches_the_audit(source):
    """The specific wiring the server-side renewal path depends on.

    namazu/audit/identity.py can only keep an authorization code identity alive
    if the browser sends the refresh token the flow returned. Losing either end
    of that is silent: the audit just starts returning 401 partway through.
    """
    assert re.search(r"oauthState\.refreshToken\s*=\s*token\.refresh_token", source), (
        "applyToken no longer stores the refresh token the authorization code "
        "flow returned, so renewableIdentity cannot build a renewable identity.")
    assert "refresh_token: carried" in source, (
        "the oauth payload sent to /api/audit no longer carries a refresh token.")
    # It must not leak between identities: B is a different account.
    assert re.search(r'target !== "secondary" && token\.refresh_token', source), (
        "the refresh token is no longer scoped to the primary identity, so the "
        "second identity's credential could be used to mint the first's.")


def test_the_external_tool_tags_match_the_ids_the_server_emits(source):
    """The findings list tags an external finding by its id prefix.

    external.py builds every one as f"<tool>.<template or check>", and the
    browser reads that prefix to decide whether to show the tool's name beside
    the finding. Renaming the prefix on either side loses the tag silently: a
    nuclei match would then sit in the list looking like something Namazu
    established itself, which is the one thing the tag exists to prevent.
    """
    declared = re.search(r"const EXTERNAL_TOOLS = \[(.+?)\]", source)
    assert declared, "app.js no longer declares which tools it tags"
    tools = set(re.findall(r'"([a-z]+)"', declared.group(1)))
    assert tools, "no tool names parsed out of EXTERNAL_TOOLS"
    external = (APP.parent.parent / "audit" / "external.py").read_text(encoding="utf-8")
    for tool in sorted(tools):
        assert f'f"{tool}.' in external, (
            f"app.js tags {tool} findings by prefix, but external.py no longer "
            f'builds ids as f"{tool}.<...>"')
