"""Credential resolution for an audit run.

An identity can be a set of headers, or an OAuth configuration the engine mints
a token from. The second form is what makes a long audit survivable: a token
pasted into a header expires partway through a run across forty operations and
every request after that point returns 401, which reads like a finding rather
than a stale credential.

A minted token is cached for the configuration that produced it and reused
until shortly before it expires, so a run mints once rather than once per
operation. Tokens live in memory only and are never written to disk.
"""
from __future__ import annotations

import hashlib
import json
import time

from .. import oauth
from ..discovery import Connection
from . import jwtlab

# Mint a replacement this long before the server's own expiry, so a token does
# not lapse between being handed out and being used.
REFRESH_MARGIN = 30
# A token with no stated lifetime is still reused, but only briefly.
DEFAULT_TTL = 300

_tokens: dict[str, dict] = {}


class CredentialError(RuntimeError):
    """A configured identity could not be turned into a usable credential."""


# ── what counts as a credential, and who is holding it ───────────────────────

# Header names that carry a credential. One list, read by every probe that
# takes credentials off a request or recognises the credential a second
# identity carries, so the read battery and the write battery cannot disagree
# about what a credential is.
CREDENTIAL_HEADERS = frozenset({
    "authorization", "cookie", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-access-token", "x-session-token", "authentication",
})

# Claims that name the caller. "sub" is the subject proper; the rest name a
# machine caller, which is what a client credentials grant produces.
CLIENT_CLAIMS = ("client_id", "azp", "appid", "oid")


def strip_credentials(headers: dict) -> dict:
    """``headers`` with every credential this tool recognises removed."""
    return {name: value for name, value in (headers or {}).items()
            if str(name).lower() not in CREDENTIAL_HEADERS}


def _credentials(headers: dict) -> tuple[set[str], set[str]]:
    """Credential material these headers carry, as (token values, cookies).

    The two are kept apart because they compare differently. A token header
    holds one credential, so a shared value is a shared credential. A cookie
    header holds a bag of unrelated values, any one of which two different
    accounts may legitimately be sent.
    """
    tokens: set[str] = set()
    cookies: set[str] = set()
    for name, value in (headers or {}).items():
        lowered = str(name).lower()
        if not isinstance(value, str) or not value.strip():
            continue
        if lowered == "cookie":
            cookies |= {item.strip() for item in value.split(";") if item.strip()}
            continue
        if lowered not in CREDENTIAL_HEADERS:
            continue
        text = value.strip()
        tokens.add(text)
        # "Bearer abc" and a bare "abc" under a different header name are one
        # secret presented two ways.
        if " " in text:
            tokens.add(text.split(" ", 1)[1].strip())
    return tokens, cookies


def _claims(headers: dict) -> dict | None:
    """The payload of a JWT carried anywhere in these headers, if there is one."""
    token = jwtlab.bearer_token(headers)
    decoded = jwtlab.decode(token) if token else None
    return decoded["payload"] if decoded else None


def subject(headers: dict) -> str | None:
    """The principal these headers name, when the credential is a readable JWT."""
    claims = _claims(headers) or {}
    for claim in ("sub", *CLIENT_CLAIMS):
        if claims.get(claim):
            return str(claims[claim])
    return None


def same_principal(sent: dict, other: dict) -> str | None:
    """Why ``other`` is the same caller as ``sent``, or None when it is not.

    Only positive evidence counts. Absence of evidence returns None and the
    probe goes ahead, because the header list above is a guess: a credential
    under a name this tool does not know would otherwise read as "no
    credential at all", and suppressing a real authorization finding is a far
    worse outcome than spending one request to check.

    One case stays open by that rule: a second identity that reuses the first
    one's session cookie and adds an unrelated cookie of its own is not
    recognised, because telling a session cookie from a preference cookie by
    its name is guesswork. The probe runs, and two opaque cookie jars that
    differ are taken at face value.
    """
    if not sent or not other:
        return None
    held_tokens, held_cookies = _credentials(sent)
    offered_tokens, offered_cookies = _credentials(other)
    if offered_tokens & held_tokens:
        return "both identities send the same credential"
    # Nothing of its own: whatever this request is, it is not a second account
    # asking. A cookie counts only as part of the whole bag here, so two
    # accounts that share a theme cookie and differ in their session cookie
    # still reach the probe.
    offered, held = offered_tokens | offered_cookies, held_tokens | held_cookies
    if offered and offered <= held:
        return "the second identity sends no credential the first one did not"

    first, second = _claims(sent), _claims(other)
    if first is None or second is None:
        # At least one credential is opaque to us. Two opaque strings that
        # differ could be two accounts, or one account issued two tokens;
        # nothing readable here can tell those apart.
        return None
    left, right = str(first.get("sub") or ""), str(second.get("sub") or "")
    if left and right:
        return f"both tokens carry the subject “{left}”" if left == right else None
    if left or right:
        # One token names a subject and the other does not, so the claim that
        # would settle it is missing from one side.
        return None
    for claim in CLIENT_CLAIMS:
        left, right = str(first.get(claim) or ""), str(second.get(claim) or "")
        if left and right and left == right:
            return f"both tokens are issued to the same client “{left}”"
    return None


def _fingerprint(config: dict, connection: Connection | None = None) -> str:
    """A stable key for a configuration, without keeping the secret readable.

    The route is part of the key. The same credentials fetched direct and
    through a proxy produce the same token, but reusing the cached one would
    leave the exchange missing from the proxy history that the operator reads
    as the record of the run.
    """
    material = json.dumps({key: config.get(key) for key in sorted(config)}, sort_keys=True,
                          default=str)
    if connection is not None:
        material += repr(connection)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def clear_cache() -> None:
    _tokens.clear()


def _mint(config: dict, *, verify_tls: bool, timeout: float,
          user_agent: str | None = None, connection: Connection | None = None) -> dict:
    """Obtain a token for an OAuth configuration, honouring the chosen grant."""
    grant = str(config.get("grant") or "client_credentials")
    token_endpoint = str(config.get("token_endpoint") or "").strip()
    if not token_endpoint:
        raise CredentialError("The OAuth identity has no token endpoint.")

    shared = {
        "token_url": token_endpoint,
        "client_id": str(config.get("client_id") or ""),
        "client_secret": str(config.get("client_secret") or ""),
        "auth_style": str(config.get("auth_style") or "post"),
        "verify_tls": verify_tls,
        "timeout": timeout,
        "user_agent": user_agent,
        # The token exchange takes the same route out as the probes, so an
        # operator watching a proxy sees the credential being fetched too.
        "connection": connection,
    }
    scope = str(config.get("scope") or "")
    try:
        if grant == "client_credentials":
            return oauth.client_credentials(scope=scope,
                                            audience=str(config.get("audience") or ""), **shared)
        if grant == "password":
            return oauth.password_grant(username=str(config.get("username") or ""),
                                        password=str(config.get("password") or ""),
                                        scope=scope, **shared)
        if grant in ("refresh_token", "authorization_code"):
            # An authorization code grant cannot be replayed without a browser,
            # but the refresh token it returned can be, which is what keeps a
            # long run authenticated.
            refresh_token = str(config.get("refresh_token") or "")
            if not refresh_token:
                raise CredentialError(
                    "This identity uses the authorization code grant, which needs a browser. "
                    "Supply the refresh token it returned so the audit can renew without one.")
            return oauth.refresh(refresh_token=refresh_token, scope=scope, **shared)
    except ValueError as exc:
        raise CredentialError(str(exc)) from exc
    raise CredentialError(f"Unsupported OAuth grant for an audit identity: {grant}")


def _token_headers(config: dict, *, verify_tls: bool, timeout: float,
                   user_agent: str | None = None,
                   connection: Connection | None = None) -> tuple[dict, dict]:
    """Headers for an OAuth identity, minting or reusing as needed."""
    key = _fingerprint(config, connection)
    cached = _tokens.get(key)
    now = time.time()
    if cached and cached["expires_at"] > now:
        return dict(cached["headers"]), cached["summary"]

    token = _mint(config, verify_tls=verify_tls, timeout=timeout, user_agent=user_agent,
                  connection=connection)
    lifetime = token.get("expires_in")
    try:
        ttl = max(int(lifetime) - REFRESH_MARGIN, 30) if lifetime else DEFAULT_TTL
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL
    headers = {token["header_name"]: token["header_value"]}
    # The access token itself is not kept in the summary that reaches a report.
    summary = {key: value for key, value in token.items()
               if key not in ("access_token", "header_value", "refresh_token")}
    _tokens[key] = {"headers": headers, "summary": summary, "expires_at": now + ttl}
    return dict(headers), summary


def resolve(identities: dict, key: str, *, verify_tls: bool = True,
            timeout: float = 15.0, user_agent: str | None = None,
            connection: Connection | None = None) -> tuple[dict, dict | None, str]:
    """Turn one configured identity into request headers.

    Returns (headers, token summary, note). The note is empty on success and
    explains the failure otherwise, so a run reports a credential problem
    rather than producing a page of 401 findings.
    """
    value = (identities or {}).get(key) or {}
    if not isinstance(value, dict):
        return {}, None, ""

    config = value.get("oauth")
    if isinstance(config, dict) and config:
        base = value.get("headers") if isinstance(value.get("headers"), dict) else {}
        headers = {str(name): str(item) for name, item in base.items()}
        try:
            minted, summary = _token_headers(config, verify_tls=verify_tls, timeout=timeout,
                                             user_agent=user_agent, connection=connection)
        except CredentialError as exc:
            return headers, None, f"The {key} identity could not obtain an OAuth token. {exc}"
        # A minted token replaces any matching header rather than sitting beside it.
        for name in list(headers):
            if name.lower() in (item.lower() for item in minted):
                del headers[name]
        headers.update(minted)
        return headers, summary, ""

    if isinstance(value.get("headers"), dict):
        return {str(n): str(v) for n, v in value["headers"].items()}, None, ""
    # The historical shape: a flat mapping of header names to values.
    return {str(name): str(item) for name, item in value.items()
            if isinstance(item, (str, int, float))}, None, ""
