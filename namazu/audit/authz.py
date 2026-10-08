"""Authorization probes. Every request here uses a read-only method.

The strongest evidence comes from replaying one identity's request as another
identity. If user B receives the same object body that user A received, the
server is not checking ownership. That is a confirmed BOLA, proved without
changing a single byte of server state.

Weaker signals (id swapping under one identity, anonymous replay) are reported
as probable or possible, because a public route and a broken one can look the
same from outside.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import jwtlab
from .identity import same_principal, strip_credentials, subject
from .model import Exchange, body_signature, finding, mark, similarity
from .transport import BudgetExhausted, Executor

ADMIN_PATH = re.compile(r"(?i)/(admin|administrator|manage|management|internal|private|sudo|root|"
                        r"superuser|console|backoffice|ops|system|config|settings/all)(/|$)")
ID_PARAM = re.compile(r"(?i)^(id|.*_id|.*Id|uid|uuid|guid|key|ref|no|num|number|code|slug|account|user|customer|order|invoice|document|file)$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


# RFC 8414: where an authorization server publishes what it signs with.
METADATA_PATH = "/.well-known/openid-configuration"
# Each PEM encoding is a different HMAC secret, so each is a separate request.
# Four is enough for the forms in use without turning one probe into a sweep.
MAX_CONFUSION_PROBES = 4


def _swap_path_segment(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    segments = parts.path.split("/")
    segments[index] = value
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))


def _swap_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(name, value if name == key else existing)
             for name, existing in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _mutate_identifier(value: str) -> str | None:
    """A neighbouring identifier of the same shape, or None when we cannot form one."""
    if value.isdigit():
        number = int(value)
        return str(number + 1) if number < 10 ** 15 else str(max(1, number - 1))
    if UUID.match(value):
        head, tail = value[:-1], value[-1]
        replacement = "0" if tail.lower() != "0" else "1"
        return head + replacement
    if re.fullmatch(r"[A-Za-z]+[-_]?\d+", value):
        digits = re.search(r"\d+$", value)
        return value[:digits.start()] + str(int(digits.group()) + 1)
    return None


def object_references(url: str) -> list[dict]:
    """Identifier-looking positions in a URL that can be swapped."""
    refs: list[dict] = []
    parts = urlsplit(url)
    segments = parts.path.split("/")
    for index, segment in enumerate(segments):
        if not segment or index == 0:
            continue
        swapped = _mutate_identifier(segment)
        if swapped:
            refs.append({"kind": "path", "label": f"path segment {index}", "original": segment,
                         "swapped": swapped, "url": _swap_path_segment(url, index, swapped)})
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if not ID_PARAM.match(key):
            continue
        swapped = _mutate_identifier(value)
        if swapped:
            refs.append({"kind": "query", "label": f"query “{key}”", "original": value,
                         "swapped": swapped, "url": _swap_query(url, key, swapped)})
    return refs[:3]


def _looks_like_data(exchange: Exchange) -> bool:
    return exchange.ok and 200 <= exchange.status < 300 and len(exchange.body.strip()) > 2


def probe(executor: Executor, *, baseline: Exchange, endpoint: str, operation: dict,
          identity_a: dict, identity_b: dict | None, base_headers: dict,
          notes: list | None = None) -> list:
    """Run the authorization battery around an already-captured baseline."""
    findings: list = []
    method = baseline.method
    if method not in ("GET", "HEAD"):
        return findings
    declared_auth = any(isinstance(entry, dict) and entry for entry in (operation.get("security") or []))
    authed = bool(identity_a)

    try:
        anonymous_findings, anonymous = _anonymous_replay(
            executor, baseline, endpoint, declared_auth, authed, base_headers)
        findings += anonymous_findings
        if identity_b:
            findings += _cross_identity(executor, baseline, endpoint, identity_b, base_headers,
                                        declared_auth, anonymous, notes)
        findings += _identifier_swap(executor, baseline, endpoint, base_headers, authed)
        findings += _cors_reflection(executor, baseline, endpoint, base_headers)
        findings += _method_tampering(executor, baseline, endpoint, base_headers)
        if authed:
            findings += _jwt_replay(executor, baseline, endpoint, identity_a, base_headers,
                                    anonymous)
    except BudgetExhausted:
        pass
    return findings


def _anonymous_replay(executor, baseline, endpoint, declared_auth, authed, base_headers):
    """Does the route answer with no credentials at all? Returns (findings, exchange)."""
    stripped = strip_credentials(base_headers)
    if authed and stripped == base_headers:
        return [], None
    if not authed and not declared_auth:
        return [], None
    anonymous = executor.send(baseline.method, baseline.url, label="replay without credentials",
                              headers=stripped, identity="anonymous")
    if not _looks_like_data(anonymous):
        return [], anonymous
    match = similarity(baseline.body, anonymous.body)
    if authed and match >= 0.95:
        return [finding(
            "authz.missing-authentication", "Protected data returned without any credentials",
            "critical" if declared_auth else "high", "confirmed",
            owasp="API2:2023 Broken Authentication", endpoint=endpoint,
            method=("Replayed the baseline request with every credential header removed and compared the "
                    "two response bodies after normalising volatile values such as timestamps and ids."),
            highlights=[mark("performs no authentication", "weak",
                             "Removing every credential changed nothing about the response.")],
            detail=(f"Removing every credential header still returned HTTP {anonymous.status}, and the body "
                    f"matches the authenticated response ({int(match * 100)}% similar). The route performs "
                    "no authentication."),
            impact="Anyone on the network can read this data without an account.",
            remediation="Require and verify authentication before the handler runs.",
            evidence={"authenticated_status": baseline.status, "anonymous_status": anonymous.status,
                      "body_similarity": match, "declared_auth": declared_auth},
            exchanges=[baseline, anonymous],
        )], anonymous
    if declared_auth:
        return [finding(
            "authz.documented-auth-not-enforced", "Documented authentication is not enforced",
            "high", "probable" if authed else "possible",
            owasp="API5:2023 Broken Function Level Authorization", endpoint=endpoint,
            method=("Replayed the baseline request with every credential header removed, then checked the "
                    "status and body length against what the contract says this route requires."),
            detail=(f"The contract marks {endpoint} as requiring authentication, but an unauthenticated "
                    f"request returned HTTP {anonymous.status} with a {len(anonymous.body)}-byte body. "
                    "Confirm whether the returned data is meant to be public."),
            impact="If this data is protected elsewhere, it is reachable here without credentials.",
            remediation="Enforce the documented security scheme on this route, or correct the contract.",
            evidence={"anonymous_status": anonymous.status, "body_similarity": match,
                      "anonymous_length": len(anonymous.body)},
            exchanges=[baseline, anonymous],
        )], anonymous
    return [], anonymous


def _cross_identity(executor, baseline, endpoint, identity_b, base_headers, declared_auth,
                    anonymous=None, notes=None) -> list:
    """The decisive test: does user B get user A's object back?

    Three gates keep shared data out of this. The second identity has to be
    a different caller, because one account presented twice would match for
    the most ordinary reason there is. The request has to address a
    specific object (an identifier in the path or query), because two users seeing the
    same search results is normal. And the data must not already be readable
    anonymously, because then the problem is missing authentication, which is
    reported on its own, not a broken boundary between two users.

    Every gate says in the run notes why it stopped the probe.
    """
    def skipped(reason: str) -> list:
        """Record why the probe did not run. Silence here reads as a clean result.

        A reader who supplied two accounts and sees no cross-identity finding
        has no way to tell a passing boundary from a probe that never ran, and
        the first thing they suspect is that their credentials did not arrive.
        """
        if notes is not None:
            notes.append(f"The cross-identity read did not run: {reason}.")
        return []

    addresses_object = bool(object_references(baseline.url))
    admin_route_early = bool(ADMIN_PATH.search(urlsplit(baseline.url).path))
    if not addresses_object and not admin_route_early:
        return skipped(
            "this request addresses no specific object, so there is no per-object boundary to "
            "test. Two accounts seeing the same collection or search result is normal")
    if (anonymous is not None and _looks_like_data(anonymous)
            and similarity(baseline.body, anonymous.body) >= 0.95):
        return skipped(
            "the same data came back with no credentials at all, so the finding here is missing "
            "authentication, reported on its own, rather than a broken boundary between two accounts")
    reason = same_principal(base_headers, identity_b)
    if reason:
        return skipped(f"{reason}. A boundary between two accounts can only be tested with two "
                       "different accounts")

    headers = {**strip_credentials(base_headers), **identity_b}
    # Named in the evidence when the credentials are readable, so a reader can
    # check for themselves that two different callers were compared.
    principals = {key: value for key, value in
                  (("identity_a_subject", subject(base_headers)),
                   ("identity_b_subject", subject(headers))) if value}
    other = executor.send(baseline.method, baseline.url,
                          label="same object requested as the second identity",
                          headers=headers, identity="identity B")
    if not other.ok:
        return []
    if other.status in (401, 403):
        return []
    if not _looks_like_data(other):
        return []
    match = similarity(baseline.body, other.body)
    same = body_signature(baseline.body) == body_signature(other.body)
    admin_route = bool(ADMIN_PATH.search(urlsplit(baseline.url).path))

    if same or match >= 0.95:
        return [finding(
            "authz.bola-confirmed", "Another user's credentials return the same object",
            "critical", "confirmed", owasp="API1:2023 Broken Object Level Authorization",
            endpoint=endpoint,
            method=("Sent the first identity's exact request a second time, changing only the credentials "
                    "to the second identity's, and compared the two bodies by normalised signature. "
                    "Nothing was written."),
            highlights=[mark("never checks that the object belongs to them", "weak",
                     "Authentication happened; authorization did not."),
             mark("the same body as the first identity", "proof",
                     "Two different accounts received identical data for the same object id.")],
            detail=(f"The identical request authenticated as the second identity returned HTTP "
                    f"{other.status} with the same body as the first identity "
                    f"({'byte-identical after normalisation' if same else f'{int(match * 100)}% similar'}). "
                    "The server authenticates the caller but never checks that the object belongs to them."),
            impact="Any authenticated user can read any other user's object by its identifier.",
            remediation="Check object ownership on every read, not just authentication. Scope queries to "
                        "the caller's subject rather than filtering after the fetch.",
            evidence={"identity_a_status": baseline.status, "identity_b_status": other.status,
                      "body_similarity": match, "identical": same,
                      "signature_a": body_signature(baseline.body),
                      "signature_b": body_signature(other.body), **principals},
            exchanges=[baseline, other],
        )]
    if admin_route:
        return [finding(
            "authz.bfla", "Second identity reached a privileged route",
            "high", "probable", owasp="API5:2023 Broken Function Level Authorization",
            endpoint=endpoint,
            method=("Replayed the request as the second identity against a route whose path marks it "
                    "administrative, and checked for a 401 or 403 rather than data."),
            detail=(f"{endpoint} sits under an administrative path, yet the second identity received HTTP "
                    f"{other.status} with a {len(other.body)}-byte body rather than 401 or 403."),
            impact="A lower-privileged account can reach administrative functionality.",
            remediation="Enforce role checks on privileged routes server-side.",
            evidence={"identity_b_status": other.status, "body_similarity": match,
                      **principals},
            exchanges=[baseline, other],
        )]
    return []


def _identifier_swap(executor, baseline, endpoint, base_headers, authed) -> list:
    """Change the object id and see whether a different object comes back."""
    out = []
    references = object_references(baseline.url)
    if not references or not _looks_like_data(baseline):
        return out
    for reference in references:
        if not executor.affordable(2):
            break
        swapped = executor.send(baseline.method, reference["url"],
                                label=f"{reference['label']} changed to {reference['swapped']}",
                                headers=base_headers, identity="identity A")
        if not _looks_like_data(swapped):
            continue
        match = similarity(baseline.body, swapped.body)
        if match >= 0.98:
            # Same body for a different id usually means the id is ignored, not an IDOR.
            continue
        if not re.search(re.escape(reference["swapped"]), swapped.body[:4000]):
            # Without the requested id echoed back we cannot say we reached that object.
            continue
        out.append(finding(
            "authz.idor", "Changing the object identifier returned a different object",
            "high", "probable" if authed else "possible",
            owasp="API1:2023 Broken Object Level Authorization", endpoint=endpoint,
            parameter=reference["label"],
            method=("Changed one identifier in the URL, left everything else untouched, and required the "
                    "response to differ from the baseline and to echo the identifier that was asked for."),
            detail=(f"Replacing {reference['label']} ({reference['original']} → {reference['swapped']}) "
                    f"returned HTTP {swapped.status} with a different body that echoes the requested "
                    f"identifier. The object was reachable by guessing its id"
                    + (" while authenticated as a single user." if authed else " with no credentials.")
                    + " Confirm the second object belongs to someone else before treating it as a breach."),
            impact="Sequential or guessable identifiers let a caller walk the whole collection.",
            remediation="Enforce per-object ownership checks and prefer unguessable identifiers.",
            evidence={"reference": reference["label"], "original": reference["original"],
                      "swapped": reference["swapped"], "status": swapped.status,
                      "body_similarity": match, "authenticated": authed},
            exchanges=[baseline, swapped],
        ))
        break
    return out


def _cors_reflection(executor, baseline, endpoint, base_headers) -> list:
    """Does the server echo whatever Origin it is handed?"""
    if not executor.affordable(1):
        return []
    probe_origin = executor.signature.origin
    probe_exchange = executor.send(
        baseline.method, baseline.url, label=f"Origin: {probe_origin}",
        headers={**base_headers, "Origin": probe_origin}, identity="identity A",
    )
    if not probe_exchange.ok:
        return []
    allowed = probe_exchange.header("access-control-allow-origin")
    credentials = probe_exchange.header("access-control-allow-credentials").lower() == "true"
    if allowed == probe_origin:
        return [finding(
            "cors.origin-reflected", "CORS reflects any Origin it is sent",
            "high" if credentials else "medium", "confirmed",
            owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            method=("Repeated the baseline request with an Origin header for a host that cannot be "
                    "registered, then read Access-Control-Allow-Origin and "
                    "Access-Control-Allow-Credentials from the response."),
            detail=(f"Sending Origin: {probe_origin} came back as Access-Control-Allow-Origin: "
                    f"{allowed}"
                    + (" together with Access-Control-Allow-Credentials: true." if credentials
                       else ", so the allow-list is not actually checked.")),
            impact=("Any website a victim visits can read this API's authenticated responses."
                    if credentials else "Any website can read this response cross-origin."),
            remediation="Compare the Origin against a fixed allow-list and echo it only on a match.",
            evidence={"sent_origin": probe_origin, "allow_origin": allowed,
                      "allow_credentials": credentials},
            scope="host", exchanges=[probe_exchange],
        )]
    if allowed == "null":
        return [finding(
            "cors.null-origin", "CORS allows the null origin",
            "medium", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            method=("Repeated the baseline request with a probe Origin header and read the "
                    "Access-Control-Allow-Origin value that came back."),
            detail="The server answered with Access-Control-Allow-Origin: null, which sandboxed iframes "
                   "and some redirects can present.",
            impact="An attacker-controlled sandboxed document can read this response.",
            remediation="Never allow the literal null origin.",
            evidence={"allow_origin": allowed}, scope="host", exchanges=[probe_exchange],
        )]
    return []


def _method_tampering(executor, baseline, endpoint, base_headers) -> list:
    """Is a denied route reachable with a different verb, or an override header?"""
    out = []
    if baseline.status not in (401, 403):
        return out
    if executor.affordable(1):
        head = executor.send("HEAD", baseline.url, label="HEAD against a denied route",
                             headers=base_headers, identity="identity A")
        if head.ok and 200 <= head.status < 300:
            out.append(finding(
                "authz.method-bypass", "A denied route answers a different method",
                "high", "confirmed", owasp="API5:2023 Broken Function Level Authorization",
                endpoint=endpoint,
                method=("Sent HEAD to the same URL that refused the original method, and compared the two "
                        "statuses."),
                detail=(f"{baseline.method} returned HTTP {baseline.status}, but HEAD on the same URL "
                        f"returned HTTP {head.status}. The authorization rule is bound to the verb rather "
                        "than the resource."),
                impact="An attacker switches verbs to skip the check; response headers alone often leak "
                       "existence, size and metadata.",
                remediation="Apply authorization to the route, not to individual methods.",
                evidence={"denied_method": baseline.method, "denied_status": baseline.status,
                          "allowed_method": "HEAD", "allowed_status": head.status},
                exchanges=[baseline, head],
            ))
    if executor.affordable(1):
        override = executor.send(
            baseline.method, baseline.url, label="X-HTTP-Method-Override: HEAD",
            headers={**base_headers, "X-HTTP-Method-Override": "HEAD"}, identity="identity A",
        )
        if override.ok and override.status != baseline.status and 200 <= override.status < 400:
            out.append(finding(
                "authz.method-override-honoured", "Server honours X-HTTP-Method-Override",
                "medium", "probable", owasp="API5:2023 Broken Function Level Authorization",
                endpoint=endpoint,
                method=("Repeated the request with an X-HTTP-Method-Override header and compared the status "
                        "with the unmodified request."),
                detail=(f"Adding X-HTTP-Method-Override: HEAD changed the response from HTTP "
                        f"{baseline.status} to HTTP {override.status}. A gateway or framework in front of "
                        "the handler is rewriting the method from a client-supplied header."),
                impact="Method-based rules at a proxy or WAF can be bypassed, including for write verbs.",
                remediation="Ignore method-override headers, or strip them at the edge before routing.",
                evidence={"baseline_status": baseline.status, "override_status": override.status},
                exchanges=[baseline, override],
            ))
    return out


def _jwt_replay(executor, baseline, endpoint, identity_a, base_headers,
                anonymous=None) -> list:
    """Forge a token offline, then replay it on a read-only route."""
    token = jwtlab.bearer_token(identity_a)
    if not token:
        return []
    report = jwtlab.analyze(token)
    if not report.get("valid"):
        return []
    out: list = []
    header_name = next((name for name in identity_a if name.lower() == "authorization"), None)

    offline = [w for w in report["weaknesses"] if w["id"] in ("weak-secret", "remote-key-url", "kid-injectable",
                                                              "no-expiry", "sensitive-claim", "long-lifetime")]
    for weakness in offline:
        severity = weakness["severity"]
        out.append(finding(
            f"jwt.{weakness['id']}", f"Supplied JWT weakness: {weakness['id'].replace('-', ' ')}",
            severity, "confirmed", owasp="API2:2023 Broken Authentication", endpoint=endpoint,
            detail=weakness["detail"] + " This was determined offline; no request was sent for it.",
            impact=("The signing key is recoverable, so tokens can be minted for any user."
                    if weakness["id"] == "weak-secret" else
                    "Weakens the guarantees the token is supposed to provide."),
            remediation=("Rotate to a high-entropy secret of at least 256 bits, or move to asymmetric signing."
                         if weakness["id"] == "weak-secret" else
                         "Set a short exp, pin the key source, and keep sensitive data out of the payload."),
            evidence={"algorithm": report["algorithm"], "key_id": report.get("key_id"),
                      "cracked_secret": report.get("cracked_secret"),
                      "claims": report.get("privilege_claims")},
        ))

    if not header_name or not executor.affordable(2):
        return out

    # A route that answers with no credentials at all proves nothing about
    # signature verification: a forged token is "accepted" because no token
    # was needed. _anonymous_replay reports that, and reporting a signature
    # bypass on top of it would be two findings for one cause, the second
    # wrong. The offline weaknesses above stand either way.
    if _open_route(baseline, anonymous):
        return out

    scheme = identity_a[header_name].split(" ", 1)[0] if " " in identity_a[header_name] else "Bearer"
    unsigned = jwtlab.forge_unsigned(report["claims"])
    none_probe = executor.send(
        baseline.method, baseline.url, label="replay with an alg:none token",
        headers={**base_headers, header_name: f"{scheme} {unsigned}"}, identity="forged",
    )
    if none_probe.ok and 200 <= none_probe.status < 300 and similarity(baseline.body, none_probe.body) >= 0.9:
        out.append(finding(
            "jwt.signature-not-verified", "Server accepts an unsigned JWT",
            "critical", "confirmed", owasp="API2:2023 Broken Authentication", endpoint=endpoint,
            method=("Re-encoded the supplied token's own claims with alg:none and an empty signature, "
                    "replayed the read-only request with it, and compared the body with the genuine "
                    "token’s response."),
            highlights=[mark("alg:none and an empty signature was accepted", "weak",
                     "The server never verified the signature, so any token can be forged.")],
            detail=("A token re-encoded with alg:none and an empty signature was accepted: the route "
                    f"returned HTTP {none_probe.status} with the same data as the real token. The server "
                    "is not verifying the signature."),
            impact="Anyone can mint a token for any user and take over their account.",
            remediation="Pin the accepted algorithm server-side and reject alg:none outright.",
            evidence={"forged_algorithm": "none", "status": none_probe.status,
                      "body_similarity": similarity(baseline.body, none_probe.body)},
            exchanges=[baseline, none_probe],
        ))
        return out

    secret = report.get("cracked_secret")
    if secret is not None and executor.affordable(1):
        escalated = jwtlab.escalated_claims(report["claims"])
        forged = jwtlab.forge_hmac(escalated, secret, alg=report["algorithm"] if report["algorithm"].startswith("HS") else "HS256")
        probe_exchange = executor.send(
            baseline.method, baseline.url, label="replay with a re-signed, privilege-escalated token",
            headers={**base_headers, header_name: f"{scheme} {forged}"}, identity="forged",
        )
        if probe_exchange.ok and 200 <= probe_exchange.status < 300:
            out.append(finding(
                "jwt.forged-token-accepted", "A token signed with the recovered secret was accepted",
                "critical", "confirmed", owasp="API2:2023 Broken Authentication", endpoint=endpoint,
                method=("Recovered the signing secret offline from a wordlist, re-signed the claims with "
                        "raised privilege values, and replayed the read-only request with the forged token."),
                detail=(f"The signing secret “{secret or '(empty)'}” was recovered offline, used to sign a "
                        f"token with raised privilege claims, and the server returned HTTP "
                        f"{probe_exchange.status}. This is a full authentication bypass."),
                impact="Any identity and any role can be claimed by forging a token offline.",
                remediation="Rotate the signing key to a high-entropy value immediately and invalidate "
                            "existing tokens.",
                evidence={"secret": secret, "escalated_claims": escalated, "status": probe_exchange.status},
                exchanges=[baseline, probe_exchange],
            ))
            return out

    out += _jwt_alg_confusion(executor, baseline, endpoint, report, header_name, scheme,
                              base_headers)
    return out


def _open_route(baseline, anonymous) -> bool:
    """Does this route return the same data with no credentials at all?"""
    return (anonymous is not None and _looks_like_data(anonymous)
            and similarity(baseline.body, anonymous.body) >= 0.95)


def _accepted(baseline, probe) -> bool:
    """Did a forged token get the genuine response back?"""
    return (probe.ok and 200 <= probe.status < 300
            and similarity(baseline.body, probe.body) >= 0.9)


def _json_document(exchange):
    if not exchange.ok or not 200 <= exchange.status < 300:
        return None
    try:
        value = json.loads(exchange.body)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _issuer_keys(executor, issuer: str):
    """The issuer's own signing keys, via its metadata document.

    Two GETs of documents that are public by design. The issuer is the one the
    operator's own token names, so it is part of the system under test rather
    than a host Namazu went looking for, and no credential or operator header
    crosses to it.

    A jku or x5u header is deliberately not followed. Those are attacker-
    controllable by definition, which is why their presence is already a
    finding of its own; fetching key material from one would measure nothing
    about the server.
    """
    try:
        metadata = executor.send(
            "GET", issuer.rstrip("/") + METADATA_PATH,
            label="fetch the token issuer's metadata", headers={}, identity="anonymous")
    except ValueError:
        return [], ""
    document = _json_document(metadata)
    jwks_uri = (document or {}).get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        return [], ""
    try:
        response = executor.send("GET", jwks_uri.strip(),
                                 label="fetch the token issuer's signing keys",
                                 headers={}, identity="anonymous")
    except ValueError:
        return [], ""
    return jwtlab.jwks_signing_keys(_json_document(response) or {}), jwks_uri.strip()


def _jwt_alg_confusion(executor, baseline, endpoint, report, header_name, scheme,
                       base_headers) -> list:
    """Re-sign an RSA-signed token as HS256 with the public key as the secret.

    The bug is one line: the verifier is handed the token's own declared
    algorithm instead of the one the route expects. The key material it then
    HMACs against is the RSA public key, which anyone can fetch.
    """
    if not report["algorithm"].startswith(("RS", "PS")):
        return []
    issuer = report.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip():
        return []
    # Metadata, key set, the control, and at least one forged token.
    if not executor.affordable(4):
        return []

    keys, jwks_uri = _issuer_keys(executor, issuer.strip())
    if not keys or not executor.affordable(2):
        return []

    # The control, and the reason this can be reported as confirmed. A token
    # signed with a secret nobody could know must be refused. If it is
    # accepted, the server is not verifying HMAC signatures at all, which is a
    # different finding and one the alg:none probe above already covers.
    decoy = jwtlab.forge_hmac(report["claims"], secrets.token_bytes(32), alg="HS256",
                              header_extra={"kid": report["key_id"]} if report.get("key_id") else None)
    control = executor.send(
        baseline.method, baseline.url,
        label="control: replay with an HS256 token signed by a secret nobody holds",
        headers={**base_headers, header_name: f"{scheme} {decoy}"}, identity="forged")
    if not control.ok or _accepted(baseline, control):
        return []

    sent = 0
    for key in keys:
        for label, material in jwtlab.confusion_keys(key):
            if sent >= MAX_CONFUSION_PROBES or not executor.affordable(1):
                return []
            sent += 1
            key_id = key.get("kid") or report.get("key_id")
            forged = jwtlab.forge_hmac(
                report["claims"], material, alg="HS256",
                header_extra={"kid": key_id} if key_id else None)
            probe_exchange = executor.send(
                baseline.method, baseline.url,
                label=f"replay as HS256 signed with the {label} of the issuer's public key",
                headers={**base_headers, header_name: f"{scheme} {forged}"}, identity="forged")
            if not _accepted(baseline, probe_exchange):
                continue
            return [finding(
                "jwt.alg-confusion", "An RSA-signed token is accepted when re-signed as HS256",
                "critical", "confirmed", owasp="API2:2023 Broken Authentication",
                endpoint=endpoint,
                method=(f"Fetched the issuer's public signing key from {jwks_uri}, re-encoded the "
                        f"supplied token's own claims with alg:HS256, signed them with that public "
                        f"key's {label} as the HMAC secret, and replayed the read-only request. A "
                        "control token signed with an unrelated 32-byte secret was sent first and "
                        "was refused, so the server does verify HMAC signatures. Nothing was "
                        "written."),
                highlights=[
                    mark("re-signed as HS256", "weak",
                         "The verifier trusted the algorithm named in the token instead of the one "
                         "this route expects."),
                    mark("signed with that public key", "proof",
                         "The signing key is the public key, so anyone who can read the key set "
                         "can mint a token for any user."),
                ],
                detail=(f"The token presented to this route is signed with {report['algorithm']}. "
                        f"Re-encoding its claims as HS256 and signing them with the issuer's public "
                        f"key, in its {label} form, as the HMAC secret returned HTTP "
                        f"{probe_exchange.status} with the same data as the genuine token. The "
                        "server is verifying against the algorithm the token declares rather than "
                        "the one it requires, so the public key is being used as a shared secret."),
                impact=("The verification key is published, so anyone can forge a token for any "
                        "user or role. This is a full authentication bypass."),
                remediation=("Pin the accepted algorithm where the token is verified rather than "
                             "reading it from the token header: pass the expected algorithm "
                             "explicitly, for example algorithms=['RS256'], and reject any token "
                             "whose alg is not in that list."),
                evidence={"token_algorithm": report["algorithm"], "forged_algorithm": "HS256",
                          "key_encoding": label, "key_id": key_id, "jwks_uri": jwks_uri,
                          "control_status": control.status, "status": probe_exchange.status,
                          "body_similarity": similarity(baseline.body, probe_exchange.body)},
                exchanges=[baseline, control, probe_exchange],
            )]
    return []
