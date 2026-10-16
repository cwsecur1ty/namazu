"""Analysis of one captured response. Sends no additional requests.

Covers contextual transport/browser headers, cookie flags, secrets in the
body, and data the response returns that its contract never documented.
Implementation disclosure is aggregated across exchanges by disclosure.py.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import jwtlab
from .identity import CREDENTIAL_HEADERS
from .model import Exchange, finding, json_body, walk_json
from .response_compare import edge_block_markers
from .specscan import _resolve, _writable_properties

SECRET_FIELDS = re.compile(
    r"(?i)^(password|passwd|pwd|pass|password_?hash|hash|salt|secret|client_?secret|"
    r"private_?key|privatekey|api_?key|apikey|access_?token|refresh_?token|session_?key|"
    r"ssn|social_?security|card_?number|cardnumber|cvv|cvc|pin|security_?answer|"
    r"mother_?maiden|date_?of_?birth|dob|tax_?id|passport|license_?number)$"
)
SECRET_VALUES = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "provider secret key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s\"'<>]*:[^\s\"'<>@]+@"), "connection string with credentials"),
)
SECURITY_HEADERS = (
    "strict-transport-security", "x-content-type-options", "content-security-policy",
    "content-security-policy-report-only", "x-frame-options", "referrer-policy",
    "permissions-policy", "cache-control", "vary", "access-control-allow-origin",
    "access-control-allow-credentials", "access-control-allow-private-network",
)
RENDERABLE_TYPES = {"text/html", "application/xhtml+xml"}
BROWSER_RESOURCE_TYPES = RENDERABLE_TYPES | {
    "text/javascript", "application/javascript", "text/css",
}


def _header(exchange: Exchange, name: str) -> str:
    return exchange.header(name)


def _set_cookies(exchange: Exchange) -> list[str]:
    raw = exchange.header("set-cookie")
    if not raw:
        return []
    # httpx collapses repeated headers with ", ", so split on the cookie boundary only.
    return [part.strip() for part in re.split(r",(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", raw) if part.strip()]


def review(exchange: Exchange, *, endpoint: str, operation: dict | None = None,
           document: dict | None = None) -> list:
    """Everything one response can tell us on its own."""
    findings: list = []
    if not exchange.ok:
        return findings
    is_https = urlsplit(exchange.url).scheme == "https"
    findings += review_headers(exchange, endpoint=endpoint)
    findings += _cookies(exchange, endpoint, is_https)
    findings += _body_secrets(exchange, endpoint)
    findings += _tokens(exchange, endpoint)
    if operation is not None:
        findings += _undocumented_fields(exchange, endpoint, operation, document or {})
    return findings


def header_context(exchange: Exchange, *, browser_use: bool | None = None) -> dict:
    """Describe observed context without assuming every API has a browser client."""
    content_type = exchange.header("content-type").split(";", 1)[0].strip().lower()
    request_headers = {name.lower(): value for name, value in exchange.request_headers.items()}
    attachment = exchange.header("content-disposition").lower().startswith("attachment")
    edge = bool(edge_block_markers(exchange))
    renderable = content_type in RENDERABLE_TYPES and not attachment
    browser_evidence = browser_use is True or bool(
        request_headers.get("origin") or request_headers.get("sec-fetch-mode") or renderable)
    if browser_use is False:
        browser_evidence = False
    return {
        "content_type": content_type or "unknown",
        "response_source": "recognised-edge-block" if edge else "application-or-unattributed",
        "browser_use": "declared" if browser_use is True else "not-declared" if browser_use is False
        else "indicated-by-exchange" if browser_evidence else "unknown",
        "browser_relevant": browser_evidence,
        "renderable_document": renderable,
        "attachment": attachment,
        "credentials_sent": any(name in CREDENTIAL_HEADERS
                                or name in {key.lower() for key in exchange.redacted_names}
                                for name in request_headers),
        "successful_response": 200 <= exchange.status < 300,
    }


def review_headers(exchange: Exchange, *, endpoint: str,
                   browser_use: bool | None = None) -> list:
    """Offline contextual assessment; presence never establishes effective protection."""
    if not exchange.ok or not exchange.status:
        return []
    context = header_context(exchange, browser_use=browser_use)
    host = urlsplit(exchange.url).hostname or ""
    local = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
    observed = {name: exchange.safe_text(exchange.header(name), redact_properties=False)
                for name in SECURITY_HEADERS if exchange.header(name)}
    out = []
    if observed:
        out.append(finding(
            "transport.header-observation", "Response control headers observed",
            "info", "confirmed", category="informational", endpoint=endpoint,
            confirmed_claim="The listed header values were present on this response.",
            method="Read the captured response headers and response/request context without sending a request.",
            detail="The captured response includes " + ", ".join(observed) + ". Presence does not establish "
                   "that the configuration is valid, enforced, or appropriate for its consumers.",
            impact="No security consequence was demonstrated by these header values.",
            limitations="Browser enforcement, cache isolation, permitted origins and header configuration "
                        "correctness were not established by this observation.",
            remediation="Review these values against the intended browser clients, authentication and cache policy.",
            evidence={"headers": observed, "context": context}, exchanges=[exchange],
        ))
    # An explicit edge page describes the intermediary response, not application controls.
    if context["response_source"] == "recognised-edge-block":
        return out
    out += _transport(exchange, endpoint, urlsplit(exchange.url).scheme == "https", local, context)
    out += _cors(exchange, endpoint)
    return out


def _transport(exchange: Exchange, endpoint: str, is_https: bool, local: bool, context: dict) -> list:
    out = []
    if not is_https and not local:
        out.append(finding(
            "transport.cleartext", "API answered over plain HTTP",
            "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail=f"{exchange.method} {exchange.url} completed over http://. Any credential sent to this "
                   "origin travels in clear text.",
            impact="Tokens and response data can be read or modified by anyone on the network path.",
            remediation="Serve the API over TLS only and redirect or reject plaintext requests.",
            evidence={"url": exchange.url, "status": exchange.status}, scope="host", exchanges=[exchange],
        ))
    if is_https and not local and context["browser_relevant"] and not exchange.header("strict-transport-security"):
        out.append(finding(
            "transport.no-hsts", "No Strict-Transport-Security header",
            "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="This browser-relevant HTTPS response does not include Strict-Transport-Security.",
            impact="An HSTS policy may reduce HTTP downgrade exposure for browser clients.",
            limitations="The browser's stored HSTS policy, preload status, parent-domain policy and any "
                        "actual downgrade were not checked. This response alone does not show exposure.",
            remediation="Send Strict-Transport-Security with a max-age of at least 31536000.",
            evidence={"context": context}, exchanges=[exchange],
        ))
    if (context["browser_relevant"] and context["content_type"] in BROWSER_RESOURCE_TYPES
            and not context["attachment"] and not exchange.header("x-content-type-options")):
        out.append(finding(
            "transport.no-nosniff", "No X-Content-Type-Options header",
            "info", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="This browser resource does not set X-Content-Type-Options: nosniff.",
            impact="The header can constrain MIME interpretation in applicable browser fetch contexts.",
            limitations="No MIME confusion, active content execution or browser exploit was demonstrated.",
            remediation="Use an accurate Content-Type and consider nosniff for browser resources.",
            evidence={"context": context}, exchanges=[exchange],
        ))
    cache = exchange.header("cache-control")
    safe_cache = exchange.safe_text(cache, redact_properties=False)
    directives = {part.strip().split("=", 1)[0].lower() for part in cache.split(",")}
    if (context["credentials_sent"] and context["successful_response"] and exchange.body
            and directives & {"public", "s-maxage"} and not directives & {"private", "no-store"}):
        out.append(finding(
            "transport.cacheable-private", "Credentialed response advertises shared caching",
            "info", "confirmed", category="hardening", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail=f"The request carried credentials and the response returned Cache-Control: "
                   f"{safe_cache}. This explicitly permits shared-cache handling and warrants policy review.",
            impact="No cross-identity cache access or sensitive content disclosure was demonstrated.",
            limitations="Credential use does not make every response private. Cache storage, cache keys, "
                        "content sensitivity and cross-identity access remain untested.",
            remediation="Confirm that shared caching is intended; use private or no-store for private data.",
            evidence={"cache_control": safe_cache, "context": context}, exchanges=[exchange],
        ))
    return out


def _cors(exchange: Exchange, endpoint: str) -> list:
    origin = exchange.header("access-control-allow-origin")
    credentials = exchange.header("access-control-allow-credentials").lower() == "true"
    out = []
    if origin == "*" and credentials:
        out.append(finding(
            "cors.wildcard-with-credentials", "CORS wildcard and credential headers coexist",
            "info", "confirmed", category="hardening", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="The response sets Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: "
                   "true. Browsers do not permit credentialed reads using this wildcard origin value.",
            impact="This combination may prevent an intended browser integration from reading the response.",
            limitations="Header presence alone does not establish cross-origin access, credential delivery, "
                        "sensitive response content or exploitation.",
            remediation="Echo a single allow-listed origin, and send credentials only to that origin.",
            evidence={"allow_origin": origin, "allow_credentials": True}, exchanges=[exchange],
        ))
    elif origin == "*":
        out.append(finding(
            "cors.wildcard", "CORS allows any origin",
            "info", "confirmed", category="informational", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="Access-Control-Allow-Origin: * advertises uncredentialed cross-origin reads.",
            impact="This can be intentional for public data; no unauthorized read was demonstrated.",
            limitations="Browser access and the intended confidentiality of this response were not tested.",
            remediation="Restrict the allowed origins if this data is not public.",
            evidence={"allow_origin": origin}, exchanges=[exchange],
        ))
    if exchange.header("access-control-allow-private-network").lower() == "true":
        out.append(finding(
            "cors.private-network", "Private-network CORS header observed",
            "info", "confirmed", category="informational", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="This response includes Access-Control-Allow-Private-Network: true.",
            impact="No browser access to a private-network resource was demonstrated.",
            limitations="The header does not establish network location, browser support, permission, "
                        "successful preflight, credential delivery or response readability.",
            remediation="Review whether this header is needed by the supported browser clients.",
            evidence={"allow_private_network": True}, exchanges=[exchange],
        ))
    return out


def _cookies(exchange: Exchange, endpoint: str, is_https: bool) -> list:
    out = []
    for cookie in _set_cookies(exchange):
        name = cookie.split("=", 1)[0].strip()
        attributes = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
        missing = []
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if is_https and "secure" not in attributes:
            missing.append("Secure")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            session_like = re.search(r"(?i)(session|sid|auth|token|jwt|login|remember)", name) is not None
            out.append(finding(
                "cookie.weak-flags", f"Cookie “{name}” is set without {', '.join(missing)}",
                "medium" if session_like and "HttpOnly" in missing else "low", "confirmed", category="hardening",
                owasp="API8:2023 Security Misconfiguration", endpoint=endpoint, parameter=name,
                detail=f"Set-Cookie for “{name}” omits {', '.join(missing)}.",
                impact="Missing cookie attributes may weaken an application cookie's intended isolation.",
                limitations="A cookie name does not prove its authentication role. Script access, cross-site "
                            "delivery, browser SameSite defaults and an attack consequence were not tested.",
                remediation="Set cookie attributes according to its use; authentication cookies normally need "
                            "Secure and HttpOnly plus an explicit suitable SameSite policy.",
                evidence={"cookie": name, "missing": missing, "session_like_name": session_like,
                          "attributes": exchange.safe_text(name + "=<credential>" + (
                              ";" + cookie.split(";", 1)[1] if ";" in cookie else ""))},
                exchanges=[exchange],
            ))
    return out


def _body_secrets(exchange: Exchange, endpoint: str) -> list:
    out, body = [], exchange.body or ""
    for pattern, label in SECRET_VALUES:
        match = pattern.search(body)
        if match:
            out.append(finding(
                "exposure.secret-value", f"Response body contains a {label}",
                "critical" if "private key" in label or "connection string" in label else "high",
                "confirmed", owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=endpoint,
                detail=f"The response returned what matches a {label}.",
                impact="A live credential in a response reaches every client, log and cache that sees it.",
                remediation="Remove the value from the response and rotate the credential.",
                evidence={"kind": label, "match_prefix": match.group(0)[:12] + "…"},
                exchanges=[exchange],
            ))
    parsed = json_body(exchange)
    if parsed is not None:
        hits = []
        for path, key, value in walk_json(parsed):
            if key and SECRET_FIELDS.match(key) and value not in (None, "", [], {}):
                hits.append(path)
        if hits:
            out.append(finding(
                "exposure.sensitive-field", "Response returns secret-bearing fields",
                "high", "confirmed", owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=endpoint, parameter=hits[0],
                detail=f"The JSON response includes {', '.join(sorted(set(hits))[:8])} with a non-empty value.",
                impact="Clients receive data they do not need, and it persists in logs and caches.",
                remediation="Filter the response model to the fields the consumer actually requires.",
                evidence={"fields": sorted(set(hits))[:16]}, exchanges=[exchange],
            ))
    return out


def _tokens(exchange: Exchange, endpoint: str) -> list:
    out = []
    if re.search(r"(?i)[?&](?:access_token|token|jwt|api_?key|key|auth)=", exchange.url):
        out.append(finding(
            "exposure.credential-in-url", "Credential is carried in the query string",
            "medium", "confirmed", owasp="API2:2023 Broken Authentication", endpoint=endpoint,
            detail="The request URL carries what looks like a credential as a query parameter.",
            impact="Query strings persist in access logs, proxies, browser history and Referer headers.",
            remediation="Move credentials into a request header.",
            evidence={"url": exchange.url}, exchanges=[exchange],
        ))
    for token in jwtlab.find_tokens(exchange.body or "", limit=3):
        report = jwtlab.analyze(token)
        if not report.get("valid"):
            continue
        serious = [w for w in report["weaknesses"] if w["severity"] in ("critical", "high")]
        if serious:
            out.append(finding(
                "jwt.forgeable-in-response", "Response body returns a forgeable JWT",
                "critical", "confirmed", verification="observed",
            confirmed_claim=(
                "A token in the response body was decoded and shown to be forgeable offline. No forged token "
                "was sent, so this does not establish that the server would accept one."),
            owasp="API2:2023 Broken Authentication", endpoint=endpoint,
                detail="A JWT returned in the response body can be forged offline: "
                       + "; ".join(w["detail"] for w in serious),
                impact="Anyone who can read this response can mint tokens for any user.",
                remediation="Sign tokens with a strong secret or an asymmetric key, and reject alg:none.",
                evidence={"algorithm": report["algorithm"], "subject": report.get("subject"),
                          "weaknesses": report["weaknesses"],
                          "cracked_secret": report.get("cracked_secret")},
                exchanges=[exchange],
            ))
    return out


def _undocumented_fields(exchange: Exchange, endpoint: str, operation: dict, document: dict) -> list:
    """Fields returned that the operation's own 2xx schema never declares."""
    if exchange.status >= 400:
        return []
    parsed = json_body(exchange)
    if not isinstance(parsed, (dict, list)):
        return []
    declared: set[str] = set()
    found_schema = False
    for status, contract in (operation.get("responses") or {}).items():
        if not str(status).startswith("2") or not isinstance(contract, dict):
            continue
        schemas = [entry.get("schema") for entry in (contract.get("content") or {}).values()
                   if isinstance(entry, dict) and entry.get("schema")]
        if contract.get("schema"):
            schemas.append(contract["schema"])
        for schema in schemas:
            resolved = _resolve(schema, document)
            if isinstance(resolved, dict) and (resolved.get("properties") or resolved.get("items")):
                found_schema = True
            for _path, name, _sub in _writable_properties(schema, document):
                declared.add(name)
    if not found_schema or not declared:
        return []
    returned = {key for _path, key, _value in walk_json(parsed) if key}
    extra = sorted(returned - declared)[:20]
    if not extra:
        return []
    interesting = [name for name in extra if SECRET_FIELDS.match(name)]
    return [finding(
        "exposure.undocumented-field", "Response returns fields the contract does not document",
        "high" if interesting else "low", "confirmed",
        owasp="API3:2023 Broken Object Property Level Authorization", endpoint=endpoint,
        parameter=(interesting or extra)[0],
        detail=(f"The response includes {', '.join(extra[:10])}, none of which appear in the documented "
                "2xx schema. Undocumented fields are returned by the implementation but never reviewed "
                "against the contract."),
        impact=("Clients receive more object properties than the API promises"
                + (", including secret-bearing fields." if interesting else ".")),
        remediation="Serialise responses from an explicit field list that matches the published schema.",
        evidence={"undocumented": extra, "secret_bearing": interesting}, exchanges=[exchange],
    )]
