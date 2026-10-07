"""OAuth 2 client support.

Namazu obtains tokens so the workbench and the audit can reach protected routes,
and so a second identity can be a genuinely different account rather than a
hand-pasted string.

Four grants are supported:

``authorization_code``  with PKCE (RFC 7636). Namazu serves its own redirect URI
                        at ``/oauth/callback``, so the browser round trip ends
                        back in the tool with no copy-paste step.
``client_credentials``  machine-to-machine, no user involved.
``refresh_token``       renew without repeating the browser flow.
``password``            supported because real engagements still meet it; Namazu
                        reports its use as a finding (RFC 9700 §2.4).

Tokens are held in memory only, for as long as it takes the browser to collect
them, and are never written to disk. A pending authorization is identified by an
unguessable session id and is bound to the ``state`` value Namazu issued.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from .audit import jwtlab
from .discovery import check_url, client_headers

SESSION_TTL = 600  # seconds a pending authorization stays collectable
MAX_SESSIONS = 16
WELL_KNOWN = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")

_sessions: dict[str, dict] = {}


# ── PKCE ─────────────────────────────────────────────────────────────────────

def pkce_pair() -> tuple[str, str]:
    """A (verifier, S256 challenge) pair per RFC 7636."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ── discovery ────────────────────────────────────────────────────────────────

def discover(issuer: str, *, verify_tls: bool = True, timeout: float = 15.0,
             client: httpx.Client | None = None, user_agent: str | None = None) -> dict:
    """Fetch an authorization server's metadata document."""
    issuer = check_url(issuer.strip())
    parts = urlsplit(issuer)
    bases = []
    if parts.path and parts.path not in ("/",):
        if parts.path.endswith(("openid-configuration", "oauth-authorization-server")):
            bases.append(issuer)
        else:
            bases += [urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/") + path, "", ""))
                      for path in WELL_KNOWN]
    bases += [urlunsplit((parts.scheme, parts.netloc, path, "", "")) for path in WELL_KNOWN]

    owns = client is None
    http = client or httpx.Client(verify=verify_tls, trust_env=False,
                                  headers=client_headers(user_agent))
    tried: list[dict] = []
    try:
        for url in dict.fromkeys(bases):
            try:
                response = http.get(url, timeout=timeout, follow_redirects=True,
                                    headers={"Accept": "application/json"})
            except httpx.HTTPError as exc:
                tried.append({"url": url, "error": type(exc).__name__})
                continue
            tried.append({"url": url, "status": response.status_code})
            if response.status_code != 200:
                continue
            try:
                document = response.json()
            except ValueError:
                continue
            if not isinstance(document, dict) or not document.get("token_endpoint"):
                continue
            return {
                "issuer": document.get("issuer"),
                "authorization_endpoint": document.get("authorization_endpoint"),
                "token_endpoint": document.get("token_endpoint"),
                "revocation_endpoint": document.get("revocation_endpoint"),
                "introspection_endpoint": document.get("introspection_endpoint"),
                "userinfo_endpoint": document.get("userinfo_endpoint"),
                "jwks_uri": document.get("jwks_uri"),
                "scopes_supported": document.get("scopes_supported") or [],
                "grant_types_supported": document.get("grant_types_supported") or [],
                "response_types_supported": document.get("response_types_supported") or [],
                "code_challenge_methods_supported": document.get("code_challenge_methods_supported") or [],
                "token_endpoint_auth_methods_supported":
                    document.get("token_endpoint_auth_methods_supported") or [],
                "source": url,
                "document": document,
            }
    finally:
        if owns:
            http.close()
    raise ValueError("No OAuth metadata document was found. Tried: "
                     + ", ".join(entry["url"] for entry in tried))


def from_spec(spec: dict) -> list[dict]:
    """OAuth configurations the imported contract already describes."""
    out = []
    for name, scheme in (spec.get("security_schemes") or {}).items():
        if not isinstance(scheme, dict) or str(scheme.get("type", "")).lower() != "oauth2":
            continue
        for flow_name, flow in (scheme.get("flows") or {}).items():
            if not isinstance(flow, dict):
                continue
            out.append({
                "scheme": name,
                "flow": flow_name,
                "grant": {"authorizationCode": "authorization_code", "clientCredentials": "client_credentials",
                          "password": "password", "implicit": "implicit"}.get(flow_name, flow_name),
                "authorization_endpoint": flow.get("authorizationUrl"),
                "token_endpoint": flow.get("tokenUrl"),
                "refresh_endpoint": flow.get("refreshUrl"),
                "scopes": sorted(flow.get("scopes") or {}),
            })
    return out


# ── token requests ───────────────────────────────────────────────────────────

def _auth_headers(client_id: str, client_secret: str, style: str) -> tuple[dict, dict]:
    """Returns (extra headers, extra form fields) for the chosen client auth style."""
    if client_secret and style == "basic":
        raw = f"{client_id}:{client_secret}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}, {}
    fields = {"client_id": client_id} if client_id else {}
    if client_secret:
        fields["client_secret"] = client_secret
    return {}, fields


def request_token(token_url: str, form: dict, *, client_id: str = "", client_secret: str = "",
                  auth_style: str = "post", verify_tls: bool = True, timeout: float = 15.0,
                  client: httpx.Client | None = None, user_agent: str | None = None) -> dict:
    """Post to the token endpoint and normalise the response."""
    token_url = check_url(token_url.strip())
    headers, extra = _auth_headers(client_id, client_secret, auth_style)
    payload = {**form, **extra}
    owns = client is None
    http = client or httpx.Client(verify=verify_tls, trust_env=False,
                                  headers=client_headers(user_agent))
    try:
        response = http.post(
            token_url, data=payload, timeout=timeout, follow_redirects=False,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                     **headers},
        )
    except httpx.HTTPError as exc:
        raise ValueError(f"The token endpoint could not be reached ({type(exc).__name__}).") from exc
    finally:
        if owns:
            http.close()

    try:
        body = response.json()
    except ValueError:
        raise ValueError(
            f"The token endpoint returned a non-JSON response (HTTP {response.status_code})."
        ) from None
    if response.status_code >= 400 or not isinstance(body, dict) or "access_token" not in body:
        detail = ""
        if isinstance(body, dict):
            detail = body.get("error_description") or body.get("error") or ""
        raise ValueError(f"The token request failed (HTTP {response.status_code}){': ' + detail if detail else '.'}")
    return summarize_token(body)


def summarize_token(body: dict) -> dict:
    """Normalise a token response and describe the token without storing it anywhere."""
    access = str(body.get("access_token") or "")
    kind = str(body.get("token_type") or "Bearer").strip() or "Bearer"
    summary = {
        "access_token": access,
        "token_type": kind,
        "header_name": "Authorization",
        "header_value": f"{kind[:1].upper()}{kind[1:]} {access}",
        "expires_in": body.get("expires_in"),
        "scope": body.get("scope"),
        "refresh_token": body.get("refresh_token"),
        "id_token_present": bool(body.get("id_token")),
    }
    report = jwtlab.analyze(access) if jwtlab.decode(access) else None
    if report:
        summary["jwt"] = {
            "algorithm": report.get("algorithm"),
            "subject": report.get("subject"),
            "issuer": report.get("issuer"),
            "audience": report.get("audience"),
            "expires_in_seconds": report.get("expires_in_seconds"),
            "privilege_claims": report.get("privilege_claims"),
            "weaknesses": report.get("weaknesses"),
        }
    return summary


def client_credentials(**kwargs) -> dict:
    scope = kwargs.pop("scope", "")
    audience = kwargs.pop("audience", "")
    form = {"grant_type": "client_credentials"}
    if scope:
        form["scope"] = scope
    if audience:
        form["audience"] = audience
    return request_token(form=form, **kwargs)


def password_grant(*, username: str, password: str, scope: str = "", **kwargs) -> dict:
    form = {"grant_type": "password", "username": username, "password": password}
    if scope:
        form["scope"] = scope
    return request_token(form=form, **kwargs)


def refresh(*, refresh_token: str, scope: str = "", **kwargs) -> dict:
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if scope:
        form["scope"] = scope
    return request_token(form=form, **kwargs)


# ── authorization code with PKCE ─────────────────────────────────────────────

def _prune() -> None:
    now = time.time()
    for key in [key for key, entry in _sessions.items() if now - entry["created"] > SESSION_TTL]:
        _sessions.pop(key, None)
    while len(_sessions) > MAX_SESSIONS:
        oldest = min(_sessions, key=lambda key: _sessions[key]["created"])
        _sessions.pop(oldest, None)


def start_authorization(*, authorization_endpoint: str, token_endpoint: str, client_id: str,
                        redirect_uri: str, client_secret: str = "", scope: str = "",
                        audience: str = "", auth_style: str = "post", use_pkce: bool = True,
                        extra_params: dict | None = None, verify_tls: bool = True,
                        timeout: float = 15.0) -> dict:
    """Build the authorize URL and remember what the callback will need."""
    authorization_endpoint = check_url(authorization_endpoint.strip())
    check_url(token_endpoint.strip())
    if not client_id:
        raise ValueError("Enter the OAuth client id.")
    _prune()

    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(24)
    session = secrets.token_urlsafe(24)

    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    if scope:
        query["scope"] = scope
    if audience:
        query["audience"] = audience
    if use_pkce:
        query["code_challenge"] = challenge
        query["code_challenge_method"] = "S256"
    for key, value in (extra_params or {}).items():
        if isinstance(key, str) and isinstance(value, str) and key not in query:
            query[key] = value

    parts = urlsplit(authorization_endpoint)
    existing = parts.query
    authorize_url = urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        (existing + "&" if existing else "") + urlencode(query), "",
    ))

    _sessions[session] = {
        "created": time.time(), "state": state, "verifier": verifier if use_pkce else "",
        "token_endpoint": token_endpoint, "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect_uri, "auth_style": auth_style, "verify_tls": verify_tls,
        "timeout": timeout, "status": "pending", "token": None, "error": "",
    }
    return {"session": session, "authorize_url": authorize_url, "redirect_uri": redirect_uri,
            "state": state, "pkce": use_pkce}


def complete_authorization(*, state: str, code: str = "", error: str = "",
                           error_description: str = "") -> dict:
    """Redeem the code the authorization server sent back to /oauth/callback."""
    _prune()
    session_id = next((key for key, entry in _sessions.items() if entry["state"] == state), None)
    if session_id is None:
        raise ValueError("This authorization response does not match a pending request. "
                         "Start the flow again from Namazu.")
    entry = _sessions[session_id]
    if error:
        entry["status"] = "error"
        entry["error"] = f"{error}{': ' + error_description if error_description else ''}"
        return {"session": session_id, "status": "error", "error": entry["error"]}
    if not code:
        entry["status"] = "error"
        entry["error"] = "The authorization server returned no code."
        return {"session": session_id, "status": "error", "error": entry["error"]}

    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": entry["redirect_uri"]}
    if entry["verifier"]:
        form["code_verifier"] = entry["verifier"]
    try:
        token = request_token(
            entry["token_endpoint"], form, client_id=entry["client_id"],
            client_secret=entry["client_secret"], auth_style=entry["auth_style"],
            verify_tls=entry["verify_tls"], timeout=entry["timeout"],
        )
    except ValueError as exc:
        entry["status"] = "error"
        entry["error"] = str(exc)
        return {"session": session_id, "status": "error", "error": entry["error"]}
    entry["status"] = "complete"
    entry["token"] = token
    # The verifier has done its job; do not keep it alongside the token.
    entry["verifier"] = ""
    return {"session": session_id, "status": "complete"}


def collect(session: str) -> dict:
    """Hand the token to the browser once, then forget it."""
    _prune()
    entry = _sessions.get(session)
    if entry is None:
        return {"status": "unknown"}
    if entry["status"] == "pending":
        return {"status": "pending"}
    if entry["status"] == "error":
        _sessions.pop(session, None)
        return {"status": "error", "error": entry["error"]}
    token = entry["token"]
    _sessions.pop(session, None)
    return {"status": "complete", "token": token}


# ── authorization server probes ──────────────────────────────────────────────

def probe_authorization_server(*, authorization_endpoint: str, client_id: str, redirect_uri: str,
                              user_agent: str | None = None,
                               metadata: dict | None = None, verify_tls: bool = True,
                               timeout: float = 15.0, client: httpx.Client | None = None) -> list:
    """Read-only checks against the authorize endpoint.

    Each probe is a GET that the authorization server is expected to reject. A
    rejection is the healthy result; being redirected to an attacker-supplied
    destination, or receiving a code without PKCE, is the finding.
    """
    from .audit.model import Exchange, finding

    authorization_endpoint = check_url(authorization_endpoint.strip())
    owns = client is None
    http = client or httpx.Client(verify=verify_tls, trust_env=False,
                                  headers=client_headers(user_agent))
    findings: list = []
    evil = "https://namazu-probe.invalid/callback"

    def send(query: dict, label: str):
        parts = urlsplit(authorization_endpoint)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                          (parts.query + "&" if parts.query else "") + urlencode(query), ""))
        exchange = Exchange(label=label, method="GET", url=url, identity="oauth probe")
        try:
            response = http.get(url, timeout=timeout, follow_redirects=False)
            exchange.status = response.status_code
            exchange.headers = dict(response.headers)
            exchange.body = response.text[:4000]
        except httpx.HTTPError as exc:
            exchange.error = type(exc).__name__
        return exchange

    try:
        # 1. redirect_uri validation
        probe = send({"response_type": "code", "client_id": client_id, "redirect_uri": evil,
                      "state": secrets.token_urlsafe(8), "scope": "openid"},
                     "authorize with an unregistered redirect_uri")
        location = probe.header("location")
        if probe.status in (301, 302, 303, 307, 308) and "namazu-probe.invalid" in location:
            findings.append(finding(
                "oauth.redirect-not-validated", "Authorization server redirects to an unregistered URI",
                "critical", "confirmed", owasp="API2:2023 Broken Authentication",
                endpoint=f"GET {authorization_endpoint}", parameter="redirect_uri",
                method=("Sent one authorization request with redirect_uri set to a host that cannot be "
                        "registered, and read the Location header without following it."),
                detail=(f"The authorization endpoint answered HTTP {probe.status} with Location: {location}. "
                        "It accepted a redirect_uri that is not registered for this client."),
                impact=("An attacker sends a victim an authorization link pointing at their own host. The "
                        "authorization server issues the code or token to that host, and the attacker "
                        "redeems it. The result is a complete account takeover with no credential theft."),
                remediation=("Compare redirect_uri against the registered values by exact string match. "
                             "No wildcards, no prefix or suffix matching, no subdomain rules. Reject the "
                             "request with an error page rather than redirecting when it does not match."),
                evidence={"sent_redirect_uri": evil, "status": probe.status, "location": location,
                          "client_id": client_id},
                exchanges=[probe],
            ))

        # 2. implicit grant still enabled
        probe = send({"response_type": "token", "client_id": client_id, "redirect_uri": redirect_uri,
                      "state": secrets.token_urlsafe(8), "scope": "openid"},
                     "authorize with response_type=token")
        location = probe.header("location")
        unsupported = "unsupported_response_type" in (location + probe.body).lower()
        if probe.status in (301, 302, 303, 307, 308) and redirect_uri.split("://", 1)[-1] in location \
                and not unsupported:
            findings.append(finding(
                "oauth.implicit-enabled", "Authorization server still accepts the implicit grant",
                "medium", "probable", owasp="API2:2023 Broken Authentication",
                endpoint=f"GET {authorization_endpoint}", parameter="response_type",
                method=("Sent one authorization request with response_type=token and checked whether the "
                        "server rejected it with unsupported_response_type."),
                detail=(f"response_type=token produced HTTP {probe.status} towards the registered redirect "
                        "URI rather than an unsupported_response_type error, so the implicit grant appears "
                        "to still be enabled for this client."),
                impact=("Access tokens can be obtained in a URL fragment, where they reach browser history, "
                        "Referer headers and logs. Removing implicit from the contract does not disable it "
                        "at the server."),
                remediation=("Restrict this client's allowed response types to `code` in the authorization "
                             "server configuration, and disable the implicit grant tenant-wide once all "
                             "clients have migrated to authorization code + PKCE."),
                evidence={"response_type": "token", "status": probe.status, "location": location},
                exchanges=[probe],
            ))

        # 3. PKCE enforcement
        supported = (metadata or {}).get("code_challenge_methods_supported") or []
        probe = send({"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
                      "state": secrets.token_urlsafe(8), "scope": "openid"},
                     "authorize without a code_challenge")
        location = probe.header("location")
        rejected = "invalid_request" in (location + probe.body).lower() or "pkce" in (location + probe.body).lower()
        if probe.status in (301, 302, 303, 307, 308) and not rejected and supported:
            findings.append(finding(
                "oauth.pkce-not-enforced", "PKCE is supported but not required",
                "medium", "probable", owasp="API2:2023 Broken Authentication",
                endpoint=f"GET {authorization_endpoint}", parameter="code_challenge",
                method=("Sent one authorization request with no code_challenge parameter and checked "
                        "whether the server rejected it. The server's own metadata advertises "
                        f"code_challenge_methods_supported = {supported}."),
                detail=(f"The server advertises PKCE support ({', '.join(supported)}) but accepted an "
                        f"authorization request without a code_challenge (HTTP {probe.status}). PKCE is "
                        "therefore optional, which means an attacker can simply omit it."),
                impact=("Without a required code verifier, an intercepted authorization code can be "
                        "redeemed by anyone who obtains it, which is the attack PKCE exists to stop."),
                remediation=("Configure the authorization server to require PKCE with S256 for this client "
                             "and reject any authorization request lacking code_challenge. RFC 9700 §2.1.1 "
                             "requires PKCE for all clients, confidential ones included."),
                evidence={"code_challenge_methods_supported": supported, "status": probe.status,
                          "location": location},
                exchanges=[probe],
            ))
    finally:
        if owns:
            http.close()
    return findings
