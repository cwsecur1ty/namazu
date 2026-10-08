"""Analysis of one captured response. Sends no additional requests.

Covers transport and browser-facing headers, cookie flags, technology
disclosure, verbose errors, secrets in the body, and data the response returns
that its own contract never documented.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import jwtlab
from .model import Exchange, finding, json_body, walk_json
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
ERROR_SIGNATURES = (
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"(?i)\b(?:SQLSTATE|ORA-\d{5}|SQLiteException|PG::\w+Error|MySqlException|"
                r"You have an error in your SQL syntax|Unclosed quotation mark)"), "database error"),
    (re.compile(r"(?i)<b>(?:Warning|Fatal error|Notice)</b>:\s"), "PHP error output"),
    (re.compile(r"(?i)\b(?:Microsoft \.NET Framework|System\.(?:Web|Data|NullReference)\w*Exception)"), ".NET exception"),
    (re.compile(r"(?i)(?:^|[\s\"'])(?:/(?:home|var|usr|opt|srv)/[\w./-]{6,}|[A-Z]:\\\\(?:Users|inetpub|wwwroot)\\\\[\w\\\\.-]{4,})"), "server file path"),
    (re.compile(r"(?i)\bWerkzeug\b.{0,40}\bDebugger\b|\bconsole\.py\b"), "interactive debugger"),
)
TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-drupal-cache", "x-runtime", "x-version", "x-backend-server")
CACHE_SAFE = re.compile(r"(?i)\b(no-store|private)\b")


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
    host = urlsplit(exchange.url).hostname or ""
    local = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")

    findings += _transport(exchange, endpoint, is_https, local)
    findings += _cors(exchange, endpoint)
    findings += _cookies(exchange, endpoint, is_https)
    findings += _disclosure(exchange, endpoint)
    findings += _body_secrets(exchange, endpoint)
    findings += _tokens(exchange, endpoint)
    if operation is not None:
        findings += _undocumented_fields(exchange, endpoint, operation, document or {})
    return findings


def _transport(exchange: Exchange, endpoint: str, is_https: bool, local: bool) -> list:
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
    if is_https and not exchange.header("strict-transport-security"):
        out.append(finding(
            "transport.no-hsts", "No Strict-Transport-Security header",
            "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="The HTTPS response does not set Strict-Transport-Security, so a browser client will "
                   "still try the first request over HTTP.",
            impact="Leaves a window for a downgrade on the initial connection.",
            remediation="Send Strict-Transport-Security with a max-age of at least 31536000.",
            evidence={}, scope="host", exchanges=[exchange],
        ))
    if not exchange.header("x-content-type-options"):
        out.append(finding(
            "transport.no-nosniff", "No X-Content-Type-Options header",
            "info", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="Responses do not set X-Content-Type-Options: nosniff.",
            impact="A browser may re-interpret an API response as HTML or script.",
            remediation="Send X-Content-Type-Options: nosniff on every response.",
            evidence={}, scope="host", exchanges=[exchange],
        ))
    cache = exchange.header("cache-control")
    auth_sent = any(name.lower() in ("authorization", "cookie") for name in exchange.request_headers)
    if auth_sent and exchange.status < 400 and exchange.body and not CACHE_SAFE.search(cache or ""):
        out.append(finding(
            "transport.cacheable-private", "Authenticated response is not marked private",
            "low", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail=f"The request carried credentials and the response returned Cache-Control: "
                   f"{cache or '(absent)'}. Shared caches may store and re-serve this body.",
            impact="A proxy or CDN can serve one user's data to another.",
            remediation="Send Cache-Control: no-store (or private) on authenticated responses.",
            evidence={"cache_control": cache or None}, scope="host", exchanges=[exchange],
        ))
    return out


def _cors(exchange: Exchange, endpoint: str) -> list:
    origin = exchange.header("access-control-allow-origin")
    credentials = exchange.header("access-control-allow-credentials").lower() == "true"
    out = []
    if origin == "*" and credentials:
        out.append(finding(
            "cors.wildcard-with-credentials", "CORS allows any origin together with credentials",
            "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="The response sets Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: "
                   "true. Browsers reject that pair, but any gateway or client that honours it would let "
                   "any site read authenticated responses.",
            impact="Indicates the origin policy is not actually restricting anything.",
            remediation="Echo a single allow-listed origin, and send credentials only to that origin.",
            evidence={"allow_origin": origin, "allow_credentials": True}, scope="host", exchanges=[exchange],
        ))
    elif origin == "*":
        out.append(finding(
            "cors.wildcard", "CORS allows any origin",
            "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="Access-Control-Allow-Origin: * lets any website read this response without credentials.",
            impact="Acceptable for public data; a problem if the route is meant to be restricted.",
            remediation="Restrict the allowed origins if this data is not public.",
            evidence={"allow_origin": origin}, scope="host", exchanges=[exchange],
        ))
    if exchange.header("access-control-allow-private-network").lower() == "true":
        out.append(finding(
            "cors.private-network", "CORS grants private-network access",
            "medium", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="Access-Control-Allow-Private-Network: true lets a public website reach this host "
                   "inside the user's network.",
            impact="A visited page can pivot into an internal service through the browser.",
            remediation="Remove the header unless an internal tool genuinely needs it.",
            evidence={}, scope="host", exchanges=[exchange],
        ))
    return out


def _cookies(exchange: Exchange, endpoint: str, is_https: bool) -> list:
    out = []
    for cookie in _set_cookies(exchange):
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        missing = []
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if is_https and "secure" not in lowered:
            missing.append("Secure")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            session_like = re.search(r"(?i)(session|sid|auth|token|jwt|login|remember)", name) is not None
            out.append(finding(
                "cookie.weak-flags", f"Cookie “{name}” is set without {', '.join(missing)}",
                "medium" if session_like and "HttpOnly" in missing else "low", "confirmed",
                owasp="API8:2023 Security Misconfiguration", endpoint=endpoint, parameter=name,
                detail=f"Set-Cookie for “{name}” omits {', '.join(missing)}.",
                impact=("Script on the page can read a session cookie without HttpOnly, and a missing "
                        "SameSite allows cross-site submission."),
                remediation="Set HttpOnly, Secure and SameSite=Lax or Strict on session cookies.",
                evidence={"cookie": name, "missing": missing, "attributes": cookie[:200]},
                scope="host", exchanges=[exchange],
            ))
    return out


def _disclosure(exchange: Exchange, endpoint: str) -> list:
    out = []
    banners = {name: exchange.header(name) for name in TECH_HEADERS if exchange.header(name)}
    detailed = {name: value for name, value in banners.items() if re.search(r"\d+\.\d+", value)}
    if detailed:
        out.append(finding(
            "disclosure.version-banner", "Response headers disclose software versions",
            "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            detail="The response advertises " + ", ".join(f"{k}: {v}" for k, v in detailed.items()) + ".",
            impact="Version strings let an attacker map the host straight to published vulnerabilities.",
            remediation="Suppress or genericise server and framework banners.",
            evidence={"headers": detailed}, scope="host", exchanges=[exchange],
        ))
    for pattern, label in ERROR_SIGNATURES:
        if pattern.search(exchange.body or ""):
            match = pattern.search(exchange.body)
            out.append(finding(
                "disclosure.verbose-error", f"Response body contains a {label}",
                "medium", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
                detail=f"The HTTP {exchange.status} response exposes a {label} rather than a handled error.",
                impact="Internal paths, queries and library versions guide a targeted attack.",
                remediation="Return a generic error body and log the detail server-side; disable debug mode.",
                evidence={"signature": label, "excerpt": (exchange.body[max(0, match.start() - 60):match.end() + 140])},
                exchanges=[exchange],
            ))
            break
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
