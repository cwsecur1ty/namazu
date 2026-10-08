"""The five different things "the implicit flow is enabled" can mean.

A shipped report carried ``OAuth2 implicit flow is offered`` at medium
severity and confirmed confidence, on the strength of an ``implicit`` object in
an OpenAPI document. Nothing had contacted the authorization server. The
finding's own limitations text said so, which made the report internally
contradictory rather than merely optimistic.

The problem is that one claim was being used for five, and they are not the
same claim:

1. **advertised**: the specification declares the flow. A static read.
2. **client-configured**: this client is set up to use it.
3. **server-accepts**: the authorization server does not reject the request.
4. **token-issued**: a token actually came back, in the fragment or the query.
5. **weakness-demonstrated**: a concrete security consequence was shown.

Each rung needs different evidence, and the evidence for one is not evidence
for the next. A login page is not a token. An HTTP 200 is certainly not a
token: an authorization server that renders a sign-in form for an
unauthenticated browser returns 200 whether or not it would ever issue through
this grant. A 302 to the redirect URI is closer but still not proof unless the
fragment or query actually carries ``access_token``.

This module decides which rung the available evidence reaches and nothing
higher. It sends no credentials and completes no authorization: reaching rung 4
requires a browser and a consenting user, so that rung is reported as
*requiring* interactive verification, with the prerequisites named, rather than
guessed at.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

RUNGS = ("advertised", "client-configured", "server-accepts", "token-issued",
         "weakness-demonstrated")
RUNG_RANK = {name: index for index, name in enumerate(RUNGS)}

RUNG_MEANING = {
    "advertised": "The specification declares the flow. Nothing about the authorization server "
                  "was established.",
    "client-configured": "This client is configured for the flow, as far as the configuration "
                         "supplied to Namazu shows.",
    "server-accepts": "The authorization server did not reject a request for this flow. It may "
                      "still never issue a token through it.",
    "token-issued": "A token was returned through this flow, and where it was returned is known.",
    "weakness-demonstrated": "A concrete security consequence of the flow was demonstrated.",
}

# What it takes to move up, named so a report can say what is missing.
NEXT_STEP = {
    "advertised": "Send one authorization request with response_type=token and read the "
                  "response, without following it. Namazu's Auth tab does this under Test "
                  "authorization server.",
    "client-configured": "Send the authorization request for this client and read what the "
                         "server answers.",
    "server-accepts": "Complete the flow in a browser as a consenting user and read the "
                      "redirect. This needs a real account, so it cannot be automated from "
                      "here, and the token it returns is a live credential.",
    "token-issued": "Show a concrete consequence, such as the token being readable from a "
                    "context that should not have it. That is an engagement activity, not "
                    "something a scanner concludes.",
}


@dataclass
class Evidence:
    """What is known about one flow of one security scheme."""

    scheme: str
    flow: str = "implicit"
    # Rung 1.
    declared: bool = False
    json_pointer: str = ""
    authorization_url: str = ""
    scopes: list = field(default_factory=list)
    # Rung 2.
    client_configured: bool = False
    client_id: str = ""
    # Rung 3 and 4, from an authorization-server probe.
    probe_status: int | None = None
    probe_location: str = ""
    probe_error: str = ""
    server_rejected: bool = False
    token_location: str = ""      # "fragment", "query" or ""
    token_present: bool = False
    # Rung 5.
    demonstrated: str = ""

    def to_dict(self) -> dict:
        return {key: value for key, value in {
            "scheme": self.scheme, "flow": self.flow, "declared": self.declared,
            "json_pointer": self.json_pointer, "authorization_url": self.authorization_url,
            "scopes": self.scopes, "client_configured": self.client_configured,
            "client_id": self.client_id, "probe_status": self.probe_status,
            "probe_location": self.probe_location, "probe_error": self.probe_error,
            "server_rejected": self.server_rejected,
            "token_location": self.token_location, "token_present": self.token_present,
            "demonstrated": self.demonstrated,
        }.items() if value not in (None, "", False, [])}


@dataclass
class Assessment:
    """The highest rung the evidence reaches, and why it stops there."""

    rung: str
    claim: str
    why: str
    missing: str = ""
    severity: str = "info"
    verification: str = "unverified"
    category: str = "hardening"

    def to_dict(self) -> dict:
        return {"rung": self.rung, "rung_meaning": RUNG_MEANING.get(self.rung, ""),
                "claim": self.claim, "why": self.why, "missing": self.missing,
                "severity": self.severity, "verification": self.verification,
                "category": self.category,
                "ladder": [{"rung": name, "reached": RUNG_RANK[name] <= RUNG_RANK[self.rung],
                            "meaning": RUNG_MEANING[name]} for name in RUNGS]}


def token_in(location: str) -> tuple[bool, str]:
    """Whether a redirect target actually carries an access token, and where.

    This is the check that separates rung 3 from rung 4, and it is the one that
    was missing. A Location header is not a token; a Location header whose
    fragment contains ``access_token`` is.
    """
    if not location:
        return False, ""
    try:
        parts = urlsplit(location)
    except ValueError:
        return False, ""
    if "access_token" in parse_qs(parts.fragment or ""):
        return True, "fragment"
    if "access_token" in parse_qs(parts.query or ""):
        return True, "query"
    return False, ""


def assess(evidence: Evidence) -> Assessment:
    """The highest rung this evidence supports."""
    if evidence.demonstrated:
        return Assessment(
            "weakness-demonstrated",
            f"A security consequence of the {evidence.flow} flow was demonstrated: "
            f"{evidence.demonstrated}",
            "Recorded by the operator, with the evidence attached to this finding.",
            severity="high", verification="impact-demonstrated", category="security")

    if evidence.token_present:
        where = evidence.token_location or "an unknown part of the URL"
        # The location decides which exposure routes apply, which is exactly
        # what the static finding could not determine and claimed anyway.
        extra = ("A URL fragment is not sent to the server, so this is not exposed through the "
                 "Referer header, proxy logs or server access logs. It is exposed to anything "
                 "with access to the browser context."
                 if evidence.token_location == "fragment" else
                 "A query string is sent to the server, so this token can reach the Referer "
                 "header, proxy logs and server access logs as well as the browser."
                 if evidence.token_location == "query" else "")
        return Assessment(
            "token-issued",
            f"The authorization server returned an access token through the {evidence.flow} "
            f"flow, in the {where}.",
            f"The redirect carried access_token in the {where}. {extra}".strip(),
            missing=NEXT_STEP["token-issued"],
            severity="medium", verification="observed", category="security")

    if evidence.probe_status is not None and not evidence.server_rejected:
        return Assessment(
            "server-accepts",
            f"The authorization server did not reject a request for the {evidence.flow} flow.",
            f"It answered HTTP {evidence.probe_status}"
            + (f" with Location: {evidence.probe_location}" if evidence.probe_location else "")
            + ". No access token was returned in that response, so this does not establish "
              "that the grant issues tokens. An authorization server renders a sign-in page to "
              "an unauthenticated browser whether or not it would ever issue through this flow.",
            missing=NEXT_STEP["server-accepts"],
            severity="low", verification="observed", category="hardening")

    if evidence.probe_status is not None and evidence.server_rejected:
        return Assessment(
            "advertised",
            f"The specification advertises the {evidence.flow} flow, and the authorization "
            "server refused a request for it.",
            f"The server answered HTTP {evidence.probe_status}"
            + (f": {evidence.probe_error}" if evidence.probe_error else "")
            + ". The declaration appears to be stale rather than live, which is still worth "
              "correcting so the document stops advertising a grant that is not offered.",
            missing="Remove the flow from the specification, or confirm with the identity team "
                    "that it is disabled for every client.",
            severity="info", verification="unverified", category="contract")

    if evidence.client_configured:
        return Assessment(
            "client-configured",
            f"This client is configured for the {evidence.flow} flow.",
            "Taken from the configuration supplied to Namazu. The authorization server was not "
            "contacted, so nothing here establishes that it would honour the request.",
            missing=NEXT_STEP["client-configured"],
            severity="low", verification="unverified", category="hardening")

    return Assessment(
        "advertised",
        f"The specification advertises the {evidence.flow} flow for scheme "
        f"“{evidence.scheme}”.",
        f"Read from {evidence.json_pointer or 'the security scheme'} in the imported document. "
        "No request was sent to the authorization server, so this describes the document and "
        "not the running system.",
        missing=NEXT_STEP["advertised"],
        severity="medium", verification="unverified", category="hardening")


def from_probe(scheme: str, *, flow: str = "implicit", json_pointer: str = "",
               authorization_url: str = "", scopes: list | None = None,
               client_id: str = "", exchange=None, declared: bool = True) -> Evidence:
    """Build evidence from a specification reading plus an optional probe exchange."""
    evidence = Evidence(
        scheme=scheme, flow=flow, declared=declared, json_pointer=json_pointer,
        authorization_url=authorization_url, scopes=list(scopes or []),
        client_configured=bool(client_id), client_id=client_id)
    if exchange is None:
        return evidence
    if not exchange.ok:
        evidence.probe_error = exchange.error
        return evidence
    evidence.probe_status = exchange.status
    location = exchange.header("location")
    evidence.probe_location = location
    present, where = token_in(location)
    evidence.token_present = present
    evidence.token_location = where
    body = (exchange.body or "")[:2000]
    # A rejection is what the server says it is. Both the parameter error the
    # RFC defines and a plain refusal count; a sign-in page does not.
    #
    # The error has to be looked for in the fragment as well as the query. An
    # implicit response is delivered in the fragment by definition, and RFC
    # 6749 section 4.2.2.1 puts its errors there too, so a server correctly
    # refusing response_type=token answers with
    # "...#error=unsupported_response_type". Reading only the query string
    # misses every well-behaved refusal and reports the server as accepting
    # the grant it had just rejected.
    rejected_params = {"unsupported_response_type", "invalid_request", "unauthorized_client",
                       "invalid_client", "access_denied", "unsupported_grant_type"}
    errors: set = set()
    if location:
        parts = urlsplit(location)
        for piece in (parts.query, parts.fragment):
            errors |= set(parse_qs(piece or "").get("error") or [])
    if errors & rejected_params or any(word in body for word in rejected_params):
        evidence.server_rejected = True
        evidence.probe_error = ", ".join(sorted(errors & rejected_params)) or evidence.probe_error
    elif exchange.status in (400, 401, 403) and not present:
        evidence.server_rejected = True
    return evidence
