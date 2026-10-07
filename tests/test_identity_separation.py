"""Two identities have to be two accounts, and one list decides what a credential is.

Both of these were false positives at critical severity, which is the worst
kind this tool can produce: an operator reads a confirmed BOLA, writes it into
a report, and the finding is one account asking twice.

The suppressions here are therefore paired with the firing case throughout. A
guard that silences a real authorization failure is a worse bug than the one it
replaced, so every test that asserts nothing fired has a sibling proving the
same handler still gets caught when the identities really are two accounts.
"""
import json
import pathlib
import secrets
import time

import httpx
import pytest

from namazu.audit import audit_operation, inputs, jwtlab
from namazu.audit.identity import (
    CREDENTIAL_HEADERS,
    same_principal,
    strip_credentials,
    subject,
)
from namazu.spec import parse_spec

BASE = "https://api.example.test"
ORDER = {"id": 1, "owner": "alice", "total": 42, "note": "first order"}

# Long enough that the weak-secret recovery does not find it and add findings
# this file is not about.
SECRET = "6f2a9c41d8b7e35f0a1c6d94b28e7f350c9a1b6d4e8f2a7c3b5d9e1f4a8c2b6d"


def token(**claims) -> str:
    """A fresh token. The jti differs every call, the caller claims do not.

    Two mints for one account produce two different strings, which is the case
    that has to be told apart by reading the claims rather than comparing the
    credentials.
    """
    return jwtlab.forge_hmac(
        {"exp": int(time.time()) + 3600, "jti": secrets.token_hex(8), **claims}, SECRET)


def bearer(**claims) -> dict:
    return {"Authorization": f"Bearer {token(**claims)}"}


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE)


def _json(payload, status=200):
    return httpx.Response(status, json=payload)


def _read_spec():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "Shop", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/orders/{orderId}": {"get": {
            "security": [{"bearer": []}],
            "parameters": [{"name": "orderId", "in": "path", "required": True,
                            "schema": {"type": "integer", "example": 1}}],
            "responses": {"200": {"description": "Order", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}},
        }}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }, BASE)


def broken_read(accepted: set):
    """An endpoint that authenticates the caller and never checks ownership."""
    def handler(request):
        if request.headers.get("authorization") in accepted:
            return _json(ORDER)
        if request.headers.get("x-auth-token") in accepted:
            return _json(ORDER)
        return _json({"detail": "unauthorized"}, 401)
    return handler


def read_audit(identities, accepted):
    with _client(broken_read(accepted)) as client:
        return audit_operation(_read_spec(), "GET /orders/{orderId}", base_url=BASE,
                               identities=identities, client=client)


def ids(result):
    return [item["id"] for item in result["findings"]]


def notes(result):
    return " ".join(result["notes"])


def attempted(result, label_fragment):
    return any(label_fragment in entry["label"] for entry in result["log"])


# ── one account presented twice is not a broken boundary ────────────────────

def test_the_same_credential_in_both_slots_is_not_reported_as_bola():
    """The cheapest mistake to make: paste the one token you have into both."""
    headers = {"Authorization": "Bearer alice-token"}
    result = read_audit({"primary": headers, "secondary": dict(headers)},
                        {"Bearer alice-token"})
    assert "authz.bola-confirmed" not in ids(result)
    assert "both identities send the same credential" in notes(result)
    assert not attempted(result, "second identity"), (
        "the request should not have been sent at all")


def test_the_same_handler_is_still_caught_with_two_real_accounts():
    """The control for the test above: the guard must not be what hides a BOLA."""
    result = read_audit({"primary": {"Authorization": "Bearer alice-token"},
                         "secondary": {"Authorization": "Bearer bob-token"}},
                        {"Bearer alice-token", "Bearer bob-token"})
    hit = next(item for item in result["findings"] if item["id"] == "authz.bola-confirmed")
    assert hit["severity"] == "critical" and hit["confidence"] == "confirmed"


def test_the_same_secret_under_two_header_names_is_recognised():
    """A token moved from Authorization to X-Auth-Token is still that token."""
    result = read_audit({"primary": {"Authorization": "Bearer shared-token"},
                         "secondary": {"X-Auth-Token": "shared-token"}},
                        {"Bearer shared-token", "shared-token"})
    assert "authz.bola-confirmed" not in ids(result)
    assert "same credential" in notes(result)


def test_two_tokens_for_one_subject_are_not_two_identities():
    """The client credentials case: one service account, two minted tokens."""
    first, second = bearer(sub="svc-reporting"), bearer(sub="svc-reporting")
    assert first != second, "two distinct tokens, so only the claims can tell"
    result = read_audit({"primary": first, "secondary": second},
                        {first["Authorization"], second["Authorization"]})
    assert "authz.bola-confirmed" not in ids(result)
    assert 'both tokens carry the subject “svc-reporting”' in notes(result)


def test_two_subjects_are_two_identities():
    """The control: different subjects, same handler, finding still fires."""
    first, second = bearer(sub="alice"), bearer(sub="bob")
    result = read_audit({"primary": first, "secondary": second},
                        {first["Authorization"], second["Authorization"]})
    assert "authz.bola-confirmed" in ids(result)


def test_the_confirmed_finding_names_the_two_callers_it_compared():
    """A critical finding should let a reader check that claim themselves."""
    first, second = bearer(sub="alice"), bearer(sub="bob")
    result = read_audit({"primary": first, "secondary": second},
                        {first["Authorization"], second["Authorization"]})
    hit = next(item for item in result["findings"] if item["id"] == "authz.bola-confirmed")
    assert hit["evidence"]["identity_a_subject"] == "alice"
    assert hit["evidence"]["identity_b_subject"] == "bob"


# ── the rule the guard obeys: only positive evidence suppresses ─────────────

def test_two_opaque_tokens_that_differ_are_let_through():
    assert same_principal({"Authorization": "Bearer one"},
                          {"Authorization": "Bearer two"}) is None


def test_a_credential_under_an_unknown_header_name_does_not_suppress():
    """``Private-Token`` is not on the list, so nothing here is evidence of sameness.

    This is the direction that matters. Reading "no credential I recognise" as
    "the same credential" would silence a real finding on every target that
    names its credential something this tool has not heard of.
    """
    assert same_principal({"Private-Token": "alice"}, {"Private-Token": "bob"}) is None
    assert same_principal({"Private-Token": "same"}, {"Private-Token": "same"}) is None


def test_a_cookie_sent_to_both_accounts_does_not_suppress_the_finding():
    """Two bearer tokens and one shared theme cookie is still two accounts.

    This is the direction that hides a real finding rather than inventing one,
    and a preference cookie handed to every caller is the ordinary way to
    arrive at it.
    """
    alice = {"Authorization": "Bearer alice-token", "Cookie": "theme=dark"}
    bob = {"Authorization": "Bearer bob-token", "Cookie": "theme=dark"}
    assert same_principal(alice, bob) is None
    result = read_audit({"primary": alice, "secondary": bob},
                        {"Bearer alice-token", "Bearer bob-token"})
    assert "authz.bola-confirmed" in ids(result)


def test_two_cookie_sessions_that_differ_reach_the_probe():
    assert same_principal({"Cookie": "session=alice; theme=dark"},
                          {"Cookie": "session=bob; theme=dark"}) is None


def test_one_cookie_session_used_twice_is_one_account():
    assert same_principal({"Cookie": "session=alice"},
                          {"Cookie": "session=alice"}) is not None


def test_reusing_the_token_and_adding_a_cookie_is_still_one_account():
    """A token header is one credential whatever is sent beside it.

    An operator varying a tenant cookie while reusing the one token they have
    is a plausible way to configure a second identity, and on a server that
    ignores the cookie it would otherwise produce a confirmed BOLA.
    """
    reason = same_principal({"Authorization": "Bearer alice"},
                            {"Authorization": "Bearer alice", "Cookie": "tenant=2"})
    assert reason == "both identities send the same credential"


def test_a_second_identity_that_brings_nothing_of_its_own_is_the_first_one():
    reason = same_principal({"Authorization": "Bearer alice", "Cookie": "theme=dark"},
                            {"Cookie": "theme=dark"})
    assert reason is not None and "no credential the first one did not" in reason


def test_one_token_naming_a_subject_and_one_not_is_inconclusive():
    assert same_principal(bearer(sub="alice"), bearer(scope="read")) is None


def test_the_same_client_counts_only_when_neither_token_names_a_subject():
    same_client = same_principal(bearer(client_id="portal"), bearer(client_id="portal"))
    assert same_client is not None and "same client" in same_client
    # Two users of one OAuth client are two callers, and the subject says so.
    assert same_principal(bearer(sub="alice", client_id="portal"),
                          bearer(sub="bob", client_id="portal")) is None


def test_an_empty_identity_is_not_a_match():
    assert same_principal({}, {"Authorization": "Bearer x"}) is None
    assert same_principal({"Authorization": "Bearer x"}, {}) is None


def test_a_subject_is_read_from_a_token_in_a_cookie():
    assert subject({"Cookie": f"session={token(sub='carol')}; theme=dark"}) == "carol"


# ── one credential list, read by every probe ────────────────────────────────

WRITE_SPEC = {
    "openapi": "3.0.3", "info": {"title": "Users", "version": "1"},
    "servers": [{"url": BASE}],
    "paths": {"/users": {"post": {
        "security": [{"bearer": []}],
        "requestBody": {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "required": ["email"],
            "properties": {"email": {"type": "string", "example": "a@example.test"}}}}}},
        "responses": {"201": {"description": "Created", "content": {"application/json": {
            "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}},
    }}},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
}


def write_audit(primary, secondary, accepted=("alice-session",)):
    """A target that authorises writes on X-Auth-Token and nothing else."""
    def handler(request):
        if request.method != "POST":
            return _json({"detail": "not found"}, 404)
        if request.headers.get("x-auth-token") not in accepted:
            return _json({"detail": "unauthorized"}, 401)
        return _json({"id": 7, **json.loads(request.content or b"{}")}, 201)

    with _client(handler) as client:
        return audit_operation(parse_spec(WRITE_SPEC, BASE), "POST /users", base_url=BASE,
                               profile="writes", allow_mutating=True,
                               identities={"primary": primary, "secondary": secondary},
                               client=client)


def test_the_write_probe_strips_the_credentials_the_read_probe_strips():
    """The second identity's write must not succeed on the first one's credential.

    X-Auth-Token was on the read probe's list and missing from the write
    probe's. The first identity's credential therefore survived into the
    request, the server honoured it, the write succeeded, and that was reported
    as the second identity writing another account's resource: a confirmed
    critical finding describing something that never happened.
    """
    result = write_audit({"X-Auth-Token": "alice-session"},
                         {"Authorization": "Bearer bob-token"})
    assert "authz.write-bfla" not in ids(result)
    assert attempted(result, "write attempted as the second identity"), (
        "the probe has to have run, or this passes for the wrong reason")


def test_a_real_write_boundary_failure_is_still_confirmed():
    """The control: the server honours the second identity, so it must fire.

    Stripping more than before must not stop the second identity's own
    credential from arriving.
    """
    result = write_audit({"X-Auth-Token": "alice-session"},
                         {"X-Auth-Token": "bob-session"},
                         accepted=("alice-session", "bob-session"))
    hit = next(item for item in result["findings"] if item["id"] == "authz.write-bfla")
    assert hit["severity"] == "critical" and hit["mutating"] is True


def test_the_write_is_not_replayed_for_one_account_twice():
    result = write_audit({"X-Auth-Token": "alice-session"},
                         {"X-Auth-Token": "alice-session"})
    assert "authz.write-bfla" not in ids(result)
    assert "write was not replayed" in notes(result)
    assert not attempted(result, "write attempted as the second identity")


def test_every_credential_name_the_read_probe_dropped_is_still_dropped():
    """The union, not the shorter of the two lists."""
    for name in ("authorization", "cookie", "x-api-key", "api-key", "apikey",
                 "x-auth-token", "x-access-token", "x-session-token", "authentication"):
        assert name in CREDENTIAL_HEADERS, name
    assert strip_credentials({"X-Auth-Token": "t", "Accept": "application/json"}) == {
        "Accept": "application/json"}


def test_the_probes_do_not_keep_their_own_credential_lists():
    """Four lists had drifted apart. They cannot drift again if there is one."""
    root = pathlib.Path(__file__).resolve().parent.parent / "namazu" / "audit"
    allowed = {"identity.py", "model.py"}
    offenders = [path.name for path in root.glob("*.py")
                 if path.name not in allowed and "x-api-key" in path.read_text(encoding="utf-8")]
    assert offenders == [], f"{offenders} name credential headers instead of importing the list"


def test_report_redaction_covers_every_credential_that_gets_stripped():
    """model.py keeps its own list on purpose, and it has to be the wider one.

    Redacting a header that is not a credential costs a reader nothing.
    Failing to redact one leaks a token into a report, so that list is allowed
    to be broader but never narrower than this one.
    """
    from namazu.audit.model import REDACTED_HEADERS

    assert set(REDACTED_HEADERS) >= CREDENTIAL_HEADERS


def test_an_invalid_credential_is_still_formed_for_cookie_authentication():
    """The corruption list knew five names, so cookie auth skipped the check."""
    from namazu.audit.contract import INVALID_TOKEN, _corrupt_cookies

    corrupted = _corrupt_cookies("session=abc123; theme=dark")
    assert corrupted == f"session={INVALID_TOKEN}; theme={INVALID_TOKEN}"
    # Still a syntactically valid cookie header, or the server discards it and
    # the probe becomes the anonymous replay it is meant to differ from.
    assert all("=" in part for part in corrupted.split("; "))


class _Spender:
    """Enough of an executor to prove the guard runs before anything is sent."""

    def __init__(self):
        self.sent = 0

    def affordable(self, _count):
        return True

    def send(self, *_args, **_kwargs):
        self.sent += 1
        raise AssertionError("the guard should have returned before sending")


@pytest.mark.parametrize("probe_notes", [None, []])
def test_the_write_guard_does_not_need_somewhere_to_write_a_note(probe_notes):
    executor = _Spender()
    assert inputs.write_authorization(
        executor, built={"method": "POST", "url": f"{BASE}/users"}, endpoint="POST /users",
        base_headers={"Authorization": "Bearer same"},
        identity_b={"Authorization": "Bearer same"}, notes=probe_notes) == []
    assert executor.sent == 0
