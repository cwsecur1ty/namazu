"""Whether the traffic names this tool, and what that must not cost.

The feature is one claim: in quiet mode nothing Namazu sends says "namazu".
That claim is only worth making if it is checked against everything that went
on the wire rather than against the user agent, which was one of about twenty
places the name appeared: header names, path segments, query values, body
fields, cookie values, an Origin and a redirect target.

So the central test here captures every byte of every request a full audit
makes, across the read and write batteries and the surface sweep, and asserts
the name appears nowhere in any of it. Its sibling asserts the same traffic
does carry the name in the default mode, because a test that only proves
absence would also pass if the probes had stopped running.

The third thing these pin is the cost: quiet mode changes what the traffic is
called, not what it does, so the same target must yield the same findings
either way. A stealth mode that quietly disables a check is worse than no
stealth mode.
"""
import json
import re

import httpx
import pytest

from namazu.audit import audit_inventory, audit_operation
from namazu.discovery import DEFAULT_USER_AGENT, Connection, client_headers
from namazu.signature import BROWSER_USER_AGENT, Signature
from namazu.spec import parse_spec

BASE = "https://api.example.test"
ALICE = {"Authorization": "Bearer alice-token"}
BOB = {"Authorization": "Bearer bob-token"}
NAME = re.compile(r"(?i)namazu")


def _spec():
    """One readable operation and one writable one, to reach both batteries."""
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "Shop", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {
            "/search": {"get": {
                "security": [{"bearer": []}],
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                    {"name": "url", "in": "query", "schema": {"type": "string"}},
                    {"name": "next", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "Hits", "content": {"application/json": {
                    "schema": {"type": "object"}}}}},
            }},
            "/users": {"post": {
                "security": [{"bearer": []}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["email"], "properties": {
                        "email": {"type": "string", "example": "a@example.test"},
                        "role": {"type": "string"},
                        "is_admin": {"type": "boolean"}}}}}},
                "responses": {"201": {"description": "Created", "content": {"application/json": {
                    "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}},
            }},
        },
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }, BASE)


def _recorder():
    """A handler that answers plausibly and keeps every request verbatim."""
    seen: list[str] = []

    def handler(request):
        body = ""
        try:
            body = (request.content or b"").decode("utf-8", "replace")
        except (UnicodeDecodeError, AttributeError):  # pragma: no cover - defensive
            body = ""
        seen.append("\n".join([
            f"{request.method} {request.url}",
            *(f"{name}: {value}" for name, value in request.headers.items()),
            body,
        ]))
        if request.method == "POST":
            payload = {}
            try:
                payload = json.loads(request.content or b"{}")
            except ValueError:
                payload = {}
            # Echoing the body back is what makes the write battery conclusive,
            # so the probes that look for their own marker actually find it.
            return httpx.Response(201, json={"id": 7, **payload})
        return httpx.Response(200, json={"hits": 1, "next": "/search?page=2"})

    return handler, seen


def _traffic(*, quiet: bool) -> str:
    """Everything a full audit of both operations and the sweep put on the wire."""
    handler, seen = _recorder()
    link = Connection(verify_tls=True, quiet=quiet)
    with httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE) as client:
        for operation in ("GET /search", "POST /users"):
            audit_operation(_spec(), operation, base_url=BASE, profile="writes",
                            allow_mutating=True, connection=link, client=client,
                            identities={"primary": ALICE, "secondary": BOB})
        audit_inventory(_spec(), base_url=BASE, connection=link, client=client,
                        identities={"primary": ALICE})
    assert seen, "the audit sent nothing, so there is no traffic to judge"
    return "\n".join(seen)


# ── the claim ───────────────────────────────────────────────────────────────

def test_a_quiet_run_never_names_the_tool():
    """No request line, header, parameter or body says "namazu"."""
    traffic = _traffic(quiet=True)
    hits = sorted({match.group(0) for match in NAME.finditer(traffic)})
    offending = [line for line in traffic.splitlines() if NAME.search(line)]
    assert not hits, (
        f"quiet mode still named the tool {len(offending)} times, first: "
        f"{offending[0] if offending else ''}")


def test_the_default_run_does_name_the_tool():
    """The control. Without it, a probe that stopped running would pass above."""
    traffic = _traffic(quiet=False)
    assert NAME.search(traffic), "the announced run did not name the tool anywhere"
    # Not only the user agent: the probes sign their markers too.
    without_user_agent = "\n".join(line for line in traffic.splitlines()
                                   if not line.lower().startswith("user-agent:"))
    assert NAME.search(without_user_agent), (
        "only the user agent named the tool, so the probe markers are not covered")


def test_quiet_mode_costs_no_findings():
    """The same target, the same findings. Stealth must not disable a check."""
    handler, _seen = _recorder()

    def run(quiet):
        link = Connection(verify_tls=True, quiet=quiet)
        with httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE) as client:
            result = audit_operation(_spec(), "GET /search", base_url=BASE, profile="readonly",
                                     connection=link, client=client,
                                     identities={"primary": ALICE, "secondary": BOB})
        return sorted(item["id"] for item in result["findings"])

    announced, quiet = run(False), run(True)
    assert announced == quiet, (
        "the two modes found different things: "
        f"only announced {sorted(set(announced) - set(quiet))}, "
        f"only quiet {sorted(set(quiet) - set(announced))}")
    assert announced, "neither mode found anything, so this proves nothing"


def test_a_quiet_report_names_the_token_it_used():
    """A run that signs nothing still has to be attributable afterwards."""
    handler, seen = _recorder()
    link = Connection(verify_tls=True, quiet=True)
    with httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE) as client:
        result = audit_operation(_spec(), "GET /search", base_url=BASE, connection=link,
                                 client=client, identities={"primary": ALICE})
    note = next((line for line in result["notes"] if "User-Agent" in line), "")
    assert note, f"the report did not disclose the mode: {result['notes']}"
    token = re.search(r"token ([a-z][0-9a-f]{8})", note)
    assert token, f"the note names no token to search for: {note}"
    # The token has to be the one the traffic actually carried, or the operator
    # searches the target's logs for a string that is not in them.
    assert token.group(1) in "\n".join(seen)


def test_an_announced_report_discloses_nothing():
    """The default needs no disclosure, so it does not make one."""
    assert Signature(quiet=False).describe() == ""
    assert Signature(quiet=True).describe() != ""


# ── the user agent ──────────────────────────────────────────────────────────

def test_quiet_mode_sends_a_browser_user_agent():
    assert client_headers(quiet=True)["User-Agent"] == BROWSER_USER_AGENT
    assert client_headers()["User-Agent"] == DEFAULT_USER_AGENT
    assert not NAME.search(BROWSER_USER_AGENT)


def test_an_operator_user_agent_wins_over_both_defaults():
    """Turning the mode on must not discard a value chosen for the engagement."""
    chosen = "Mozilla/5.0 (engagement agreed client)"
    assert client_headers(chosen, quiet=True)["User-Agent"] == chosen
    assert client_headers(chosen)["User-Agent"] == chosen


def test_the_mode_travels_on_the_connection():
    """The spec fetch and the token exchange have to be as quiet as the probes."""
    link = Connection.build(quiet=True)
    assert link.quiet is True
    assert link.open().headers["user-agent"] == BROWSER_USER_AGENT
    assert Connection.build().quiet is False


# ── the markers themselves ──────────────────────────────────────────────────

def test_each_run_draws_its_own_token():
    """A fixed quiet marker would be a fingerprint of its own."""
    assert Signature(quiet=True).token != Signature(quiet=True).token


def test_one_signature_answers_consistently():
    """A control and its probe must carry the same marker to be comparable."""
    signature = Signature(quiet=True)
    assert signature.marker("a") == signature.marker("a")
    assert signature.host == signature.host


@pytest.mark.parametrize("quiet", [False, True])
def test_a_probe_host_can_never_resolve(quiet):
    """The host these probes use must not be able to reach anyone's server."""
    assert Signature(quiet=quiet).host.endswith(".invalid")
    assert Signature(quiet=quiet).origin.startswith("https://")


def test_quiet_markers_stay_usable_where_they_are_sent():
    """Each marker lands in a place with its own rules about characters.

    This caught a token beginning with a digit, which is not a valid GraphQL
    field name: the suggestion probe would have become a syntax error for most
    runs, and the check would have gone quiet along with the traffic.
    """
    signature = Signature(quiet=True)
    # A GraphQL field name, and a JSON property name.
    assert re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", signature.marker("ProbeFieldZz"))
    assert re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", signature.field_name)
    # A header name, which cannot carry a separator or whitespace.
    assert re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", signature.header("Probe"))
    # A path segment, which must survive being put in a URL unencoded.
    assert re.fullmatch(r"[A-Za-z0-9._~-]+", signature.slug("probe"))

# ── the authorization server probes ─────────────────────────────────────────

def test_the_authorization_server_probe_is_quiet_too():
    """It has its own client, so it is the one path that can be left behind."""
    from namazu import oauth

    seen = []

    def handler(request):
        seen.append(str(request.url))
        target = request.url.params.get("redirect_uri", "")
        return httpx.Response(302, headers={"location": f"{target}?code=abc"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        findings = oauth.probe_authorization_server(
            authorization_endpoint="https://id.example.test/authorize", client_id="an-app",
            redirect_uri="http://localhost:8010/oauth/callback", client=client,
            connection=Connection(quiet=True))
    assert seen, "the probe sent nothing"
    assert not NAME.search(" ".join(seen))
    # The finding still stands on a redirect to a host that cannot be registered.
    hit = next(f for f in findings if f.id == "oauth.redirect-not-validated")
    assert ".invalid" in hit.evidence["location"]
