"""Contract analysis. Reads the imported document and sends no requests.

These checks describe attack surface the specification itself declares:
privileged properties a client may write, fields that take a URL the server
will fetch, collection limits with no ceiling, and operations that change
state without declaring authentication.
"""
from __future__ import annotations

import re

from .model import finding, mark

# Property names that normally only a server or an administrator should set.
PRIVILEGED_PROPERTIES = re.compile(
    r"(?i)^(is_?admin|admin|is_?staff|is_?superuser|superuser|role|roles|group|groups|"
    r"permission|permissions|scope|scopes|privilege|privileges|acl|"
    r"is_?verified|verified|email_?verified|is_?active|active|enabled|disabled|"
    r"owner|owner_?id|user_?id|account_?id|tenant_?id|organization_?id|org_?id|"
    r"balance|credit|credits|amount|price|total|discount|"
    r"status|state|approved|confirmed|plan|tier|subscription|quota|limit_?override|"
    r"created_?at|updated_?at|id)$"
)
# Field names whose value the server is likely to dereference.
FETCHING_PROPERTIES = re.compile(
    r"(?i)^(url|uri|href|link|callback|callback_?url|webhook|webhook_?url|redirect|"
    r"redirect_?uri|redirect_?url|return_?url|next|target|dest|destination|"
    r"endpoint|host|proxy|source|src|image_?url|avatar_?url|document_?url|feed|fetch)$"
)
PAGINATION_PROPERTIES = re.compile(r"(?i)^(limit|per_?page|page_?size|size|count|max_?results|top|rows)$")
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _resolve(schema, document, depth: int = 0):
    """Follow local $ref chains far enough to inspect properties."""
    if not isinstance(schema, dict) or depth > 8:
        return schema if isinstance(schema, dict) else {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        current = document
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            current = current.get(part) if isinstance(current, dict) else None
            if current is None:
                return {}
        merged = {**current, **{k: v for k, v in schema.items() if k != "$ref"}}
        return _resolve(merged, document, depth + 1)
    return schema


def _writable_properties(schema, document, depth: int = 0, prefix: str = ""):
    """Yield (path, name, subschema) for every property a client can send."""
    schema = _resolve(schema, document, depth)
    if not isinstance(schema, dict) or depth > 6:
        return
    for composite in ("allOf", "oneOf", "anyOf"):
        for part in schema.get(composite, []) or []:
            yield from _writable_properties(part, document, depth + 1, prefix)
    items = schema.get("items")
    if items:
        yield from _writable_properties(items, document, depth + 1, f"{prefix}[]")
    for name, subschema in (schema.get("properties") or {}).items():
        resolved = _resolve(subschema, document, depth)
        if isinstance(resolved, dict) and resolved.get("readOnly"):
            continue
        path = f"{prefix}.{name}" if prefix else name
        yield path, name, resolved if isinstance(resolved, dict) else {}
        if isinstance(resolved, dict):
            yield from _writable_properties(resolved, document, depth + 1, path)


def _request_schemas(operation: dict, document: dict):
    content = (operation.get("request_body") or {}).get("content") or {}
    for media, entry in content.items():
        if isinstance(entry, dict) and entry.get("schema"):
            yield media, entry["schema"]
    # Swagger 2 keeps the body in a parameter.
    for parameter in operation.get("parameters") or []:
        if parameter.get("in") == "body" and parameter.get("schema"):
            yield "application/json", parameter["schema"]


def _response_schemas(operation: dict):
    for status, contract in (operation.get("responses") or {}).items():
        if not isinstance(contract, dict):
            continue
        for entry in (contract.get("content") or {}).values():
            if isinstance(entry, dict) and entry.get("schema"):
                yield status, entry["schema"]
        if contract.get("schema"):
            yield status, contract["schema"]


def _pointer(operation: dict, *parts: str) -> str:
    """JSON pointer to a place inside this operation, with / and ~ escaped."""
    path = str(operation["path"]).replace("~", "~0").replace("/", "~1")
    tail = "".join("/" + part for part in parts)
    return f"#/paths/{path}/{operation['method'].lower()}{tail}"


def review_operation(spec: dict, operation: dict) -> list:
    """Surface findings that follow from the contract alone."""
    document = spec.get("document") or {}
    endpoint = f"{operation['method']} {operation['path']}"
    method = operation["method"]
    security = operation.get("security") or []
    declared_auth = any(isinstance(entry, dict) and entry for entry in security)
    findings = []

    if method in STATE_CHANGING and not declared_auth:
        findings.append(finding(
            "spec.unauthenticated-write", "State-changing operation declares no authentication",
            "medium", "confirmed", owasp="API5:2023 Broken Function Level Authorization",
            endpoint=endpoint,
            detail=(f"The contract defines {endpoint} with no security requirement, so any caller "
                    "may invoke it. Confirm whether this route is genuinely public."),
            impact="An unauthenticated caller can change server state through this route.",
            remediation="Declare and enforce a security scheme on every state-changing operation.",
            evidence={"method": method, "declared_security": security,
                      "json_pointer": _pointer(operation, "security")},
        ))

    if operation.get("deprecated"):
        findings.append(finding(
            "spec.deprecated-operation", "Deprecated operation is still documented",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management",
            endpoint=endpoint,
            detail="The contract marks this operation deprecated. Deprecated routes often keep "
                   "running with older authorization and validation rules.",
            impact="Retired routes commonly outlive the controls applied to their replacements.",
            remediation="Retire the route, or document the removal date and keep its controls current.",
            evidence={"deprecated": True, "json_pointer": _pointer(operation, "deprecated")},
        ))

    privileged: list[dict] = []
    fetching: list[dict] = []
    for media, schema in _request_schemas(operation, document):
        for path, name, subschema in _writable_properties(schema, document):
            entry = {"property": path, "media_type": media, "type": subschema.get("type"),
                     "format": subschema.get("format")}
            if PRIVILEGED_PROPERTIES.match(name):
                privileged.append(entry)
            if FETCHING_PROPERTIES.match(name) or subschema.get("format") in ("uri", "url", "uri-reference"):
                fetching.append(entry)

    if privileged and method in STATE_CHANGING:
        names = sorted({entry["property"] for entry in privileged})[:12]
        findings.append(finding(
            "spec.mass-assignment-surface", "Request schema accepts privileged properties",
            "medium", "possible", owasp="API3:2023 Broken Object Property Level Authorization",
            endpoint=endpoint, parameter=", ".join(names[:4]),
            detail=(f"The request body schema for {endpoint} lets a client send "
                    f"{', '.join(names)}. If the handler binds the body straight onto its model, "
                    "a caller can set fields the server should own."),
            impact="A caller may escalate privileges or overwrite server-controlled fields.",
            remediation="Bind an explicit allow-list of client-writable fields; mark the rest readOnly "
                        "and reject unknown properties.",
            evidence={"properties": names, "checked": "schema only; run the write probes to confirm",
                      "json_pointer": _pointer(operation, "requestBody")},
        ))

    if fetching:
        names = sorted({entry["property"] for entry in fetching})[:12]
        findings.append(finding(
            "spec.ssrf-surface", "Request schema accepts a server-dereferenced URL",
            "medium", "possible", owasp="API7:2023 Server Side Request Forgery",
            endpoint=endpoint, parameter=", ".join(names[:4]),
            detail=(f"{endpoint} accepts {', '.join(names)}. If the server fetches that value, a "
                    "caller can direct requests at internal hosts or cloud metadata endpoints."),
            impact="Requests may be redirected to internal services that trust the API's network position.",
            remediation="Resolve and allow-list destination hosts, reject private and link-local ranges, "
                        "and do not follow redirects when fetching user-supplied URLs.",
            evidence={"properties": names, "json_pointer": _pointer(operation, "requestBody")},
        ))

    for parameter in operation.get("parameters") or []:
        name = parameter.get("name") or ""
        if parameter.get("in") not in ("query", "path"):
            continue
        schema = _resolve(parameter.get("schema") or {}, document)
        if PAGINATION_PROPERTIES.match(name) and schema.get("type") in ("integer", "number"):
            if schema.get("maximum") is None and schema.get("exclusiveMaximum") is None:
                findings.append(finding(
                    "spec.unbounded-pagination", "Collection size parameter has no maximum",
                    "low", "confirmed", owasp="API4:2023 Unrestricted Resource Consumption",
                    endpoint=endpoint, parameter=name,
                    detail=(f"“{name}” is an unbounded {schema.get('type')}. A caller can request an "
                            "arbitrarily large page and force the server to assemble it."),
                    impact="A single request can exhaust memory, database time or egress bandwidth.",
                    remediation=f"Give “{name}” a documented and server-enforced maximum.",
                    evidence={"parameter": name, "schema": {k: v for k, v in schema.items() if k != "$ref"},
                              "json_pointer": _pointer(operation, "parameters")},
                ))
        if FETCHING_PROPERTIES.match(name):
            findings.append(finding(
                "spec.ssrf-surface", "Operation accepts a URL parameter",
                "low", "possible", owasp="API7:2023 Server Side Request Forgery",
                endpoint=endpoint, parameter=name,
                detail=f"The “{name}” {parameter.get('in')} parameter commonly carries a URL the server fetches "
                       "or redirects to.",
                impact="May allow server-side request forgery or an open redirect.",
                remediation="Allow-list destinations and reject absolute URLs that leave your origin.",
                evidence={"parameter": name, "in": parameter.get("in"),
                          "json_pointer": _pointer(operation, "parameters")},
            ))

    sensitive_in_response = []
    for status, schema in _response_schemas(operation):
        if not str(status).startswith("2"):
            continue
        for path, name, _sub in _writable_properties(schema, document):
            if re.match(r"(?i)^(password|passwd|pwd|password_?hash|hash|salt|secret|"
                        r"private_?key|api_?key|token|access_?token|refresh_?token|ssn|"
                        r"social_?security|card_?number|cvv|pin|security_?answer)$", name):
                sensitive_in_response.append(f"{status}:{path}")
    if sensitive_in_response:
        findings.append(finding(
            "spec.sensitive-response-field", "Response schema documents a secret-bearing field",
            "high", "confirmed", owasp="API3:2023 Broken Object Property Level Authorization",
            endpoint=endpoint, parameter=sensitive_in_response[0].split(":", 1)[1],
            detail=("The documented success response includes "
                    f"{', '.join(sorted(set(sensitive_in_response))[:8])}. The contract itself says this "
                    "operation returns credential material."),
            impact="Secrets reach every client that can call the operation, and every log and cache in between.",
            remediation="Remove the field from the response model, or replace it with a non-reversible reference.",
            evidence={"fields": sorted(set(sensitive_in_response))[:12],
                      "json_pointer": _pointer(operation, "responses")},
        ))

    return findings


def review_document(spec: dict) -> list:
    """Whole-contract findings that need no traffic."""
    document = spec.get("document") or {}
    schemes = spec.get("security_schemes") or {}
    operations = spec.get("operations") or []
    findings = []

    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        kind = str(scheme.get("type", "")).lower()
        where = str(scheme.get("in", "")).lower()
        if kind == "apikey" and where == "query":
            findings.append(finding(
                "spec.apikey-in-query", "API key is carried in the query string",
                "medium", "confirmed", owasp="API2:2023 Broken Authentication",
                parameter=scheme.get("name"),
                detail=(f"Security scheme “{name}” places the key in the query string. Query strings are "
                        "written to access logs, proxy logs, browser history and Referer headers."),
                impact="Credentials leak into logs and third-party referrers, outliving the session.",
                remediation="Move the key to an Authorization header or a dedicated header.",
                evidence={"scheme": name, "in": where, "parameter": scheme.get("name")},
            ))
        if kind == "http" and str(scheme.get("scheme", "")).lower() == "basic":
            findings.append(finding(
                "spec.basic-auth", "Contract documents HTTP Basic authentication",
                "low", "confirmed", owasp="API2:2023 Broken Authentication",
                detail=(f"Security scheme “{name}” uses HTTP Basic, which replays a reusable password on "
                        "every request."),
                impact="A single intercepted request exposes a long-lived password.",
                remediation="Prefer short-lived bearer tokens; require TLS and rotate credentials.",
                evidence={"scheme": name},
            ))
        if kind == "oauth2":
            findings.extend(_oauth_scheme(name, scheme))

    if operations and not schemes and not (document.get("security") or []):
        findings.append(finding(
            "spec.no-auth-defined", "Contract defines no security scheme",
            "medium", "confirmed", owasp="API2:2023 Broken Authentication",
            detail=f"None of the {len(operations)} documented operations reference a security scheme, and the "
                   "document declares none.",
            impact="Clients and gateways cannot tell which routes need credentials; reviewers cannot audit them.",
            remediation="Declare securitySchemes and apply them per operation, or document the API as public.",
            evidence={"operations": len(operations)},
        ))

    for server in spec.get("servers") or []:
        if str(server).lower().startswith("http://") and "localhost" not in str(server) and "127.0.0.1" not in str(server):
            findings.append(finding(
                "spec.cleartext-server", "Contract advertises a cleartext server",
                "high", "confirmed", owasp="API8:2023 Security Misconfiguration",
                detail=f"The document lists {server} over plain HTTP.",
                impact="Credentials and responses travel unencrypted and can be read or altered in transit.",
                remediation="Serve the API over HTTPS only and remove the http:// server entry.",
                evidence={"server": server},
            ))

    return findings


def _scope_names(flow: dict) -> list[str]:
    scopes = flow.get("scopes")
    return sorted(scopes) if isinstance(scopes, dict) else []


def _oauth_scheme(name: str, scheme: dict) -> list:
    """Review one OAuth2 security scheme, flow by flow.

    The grant a contract offers is a design decision with a documented security
    outcome, so each flow gets its own finding rather than one generic note.
    """
    out = []
    flows = scheme.get("flows")
    if not isinstance(flows, dict):
        flows = {}
    pointer = f"#/components/securitySchemes/{name}/flows"

    implicit = flows.get("implicit")
    if isinstance(implicit, dict):
        authorize = implicit.get("authorizationUrl") or "(no authorizationUrl declared)"
        scopes = _scope_names(implicit)
        out.append(finding(
            "spec.oauth-implicit-flow", "OAuth2 implicit flow is advertised in the specification",
            "medium", "confirmed", owasp="API2:2023 Broken Authentication", parameter=name,
            # A hardening concern, not a weakness: the deprecated grant is
            # advertised, and nothing here establishes that the authorization
            # server offers it. The severity rules lower this to low on the
            # static origin, which is the honest ceiling for a declaration.
            category="hardening", origin="static-declaration", verification="unverified",
            confirmed_claim=(
                f"What is confirmed is the declaration: {pointer}/implicit exists in the imported "
                "document. Not confirmed, and not tested: that the authorization server offers the "
                "implicit grant, that it would issue a token through it, or that any client uses it."),
            mapping_basis=(
                "API2:2023 names the area of concern, which is the choice of authentication flow. It "
                "is not a claim that authentication was bypassed. No CWE is attached: the mechanism "
                "depends on whether a token would come back in the URL fragment or the query string, "
                "and a static read cannot tell which."),
            method=(f"Read {pointer}/implicit in the imported document. The presence of the implicit "
                    "object is the finding; no request was sent to the authorization server."),
            detail=(
                f"The specification declares an implicit flow for security scheme “{name}”, with "
                f"authorizationUrl {authorize}"
                + (f" and {len(scopes)} scope(s): {', '.join(scopes[:8])}." if scopes else ".")
                + " This is what the document advertises. Namazu read it statically and did not contact "
                  "the authorization server, so this finding describes the specification rather than "
                  "observed behaviour."),
            impact=(
                "If an access token issued through this flow is disclosed, whoever holds it can act as "
                "that user or client for the token's scopes and remaining lifetime. A bearer token "
                "needs no further secret.\n\n"
                "A token delivered in the URL fragment is reachable by anything with access to the "
                "browser context: script running on the redirect page, including third-party script; "
                "the browser's history; and extensions able to read the page or the address bar. Weak "
                "redirect_uri validation at the authorization server turns that into a remote attack, "
                "because the token is delivered wherever the redirect points.\n\n"
                "A URL fragment is not sent to the server, so it does not by itself appear in the "
                "Referer header, in proxy logs or in server access logs. Those routes apply only if "
                "this implementation returns the token in the query string instead, which Namazu has not "
                "determined."),
            limitations=(
                "Identified statically from the OpenAPI document. This does not establish that the "
                "implicit grant is enabled at the authorization server, that it issues usable tokens, "
                "or that it is exploitable. The declaration may be stale and describe a flow the "
                "server no longer supports.\n\n"
                "Namazu has also not determined where a token would actually be returned, fragment or "
                "query string, and that is what decides whether the Referer and log exposure routes "
                "apply.\n\n"
                "Use Test authorization server in the Auth tab to check the running server with "
                "response_type=token."),
            remediation=(
                "Move this client to the authorization code grant with PKCE:\n"
                "1. In the contract, replace the `implicit` flow object with `authorizationCode`, "
                "keeping the same scopes and adding the `tokenUrl`.\n"
                "2. In the client, generate a 43-128 character random `code_verifier` per "
                "authorization request, send `code_challenge=BASE64URL(SHA256(verifier))` with "
                "`code_challenge_method=S256`, and send the verifier when redeeming the code.\n"
                "3. Configure the authorization server to reject `response_type=token` for this "
                "client.\n"
                "4. Register exact redirect URIs: full string match, no wildcards or path prefixes.\n"
                "5. Keep tokens out of the browser URL: hold them in memory, or use a "
                "backend-for-frontend that keeps them server-side.\n\n"
                "If the implicit flow is not actually supported, remove it from the specification so "
                "the document stops advertising it.\n\n"
                "Namazu's Auth tab can run authorization code + PKCE against this scheme, so the "
                "replacement can be confirmed working before the old grant is withdrawn."),
            highlights=[
                mark("implicit", "weak",
                     "The grant itself is the finding. RFC 9700 says it SHOULD NOT be used and "
                     "OAuth 2.1 removes it."),
                mark("ACCESS TOKEN", "weak",
                     "Under implicit this is what the browser receives, and it is immediately usable."),
                mark("useless without the verifier", "proof",
                     "What PKCE adds: an intercepted code on its own is not enough."),
                mark("is not sent to the server", "proof",
                     "Why the Referer and server-log routes do not automatically apply to a fragment."),
                mark(authorize, "attacker",
                     "The authorization endpoint a crafted link would point a victim at."),
            ],
            evidence={
                "scheme": name,
                "flow": "implicit",
                "json_pointer": f"{pointer}/implicit",
                "authorization_url": implicit.get("authorizationUrl"),
                "refresh_url": implicit.get("refreshUrl"),
                "scopes": scopes,
                "flow_object": implicit,
                "source": "OpenAPI document, read statically",
                "authorization_server_tested": False,
                "token_delivery_location": "not determined; fragment and query are both possible",
                "removed_in": "OAuth 2.1 (draft-ietf-oauth-v2-1); discouraged by RFC 9700 2.1.2",
            },
        ))

    password = flows.get("password")
    if isinstance(password, dict):
        scopes = _scope_names(password)
        out.append(finding(
            "spec.oauth-password-flow", "OAuth2 resource owner password grant is offered",
            "medium", "confirmed", owasp="API2:2023 Broken Authentication", parameter=name,
            method=(f"Read {pointer}/password in the imported document. No credentials were submitted "
                    "and no request was sent to the authorization server."),
            detail=(
                f"Security scheme “{name}” offers the resource owner password credentials grant with "
                f"tokenUrl {password.get('tokenUrl') or '(none declared)'}"
                + (f" and scopes {', '.join(scopes[:8])}." if scopes else ".")
                + " In this grant the client collects the user's actual username and password and "
                  "posts them to the token endpoint. RFC 9700 §2.4 states the grant MUST NOT be used, "
                  "and OAuth 2.1 removes it."),
            impact=(
                "Every client that uses this grant handles raw user passwords, so the credential's "
                "exposure surface becomes the union of all those clients rather than just the "
                "authorization server. It is incompatible with multi-factor authentication, with "
                "federated or social login, and with step-up authentication, because there is no "
                "interactive step where the authorization server can challenge the user. It also "
                "trains users to type their password into non-authorization-server UI, which is the "
                "behaviour phishing depends on."),
            remediation=(
                "Replace it with a grant that fits the client:\n"
                "• User-facing apps (web, mobile, desktop, SPA): authorization code + PKCE.\n"
                "• Machine-to-machine with no user: client credentials.\n"
                "• Input-constrained devices (TV, CLI): device authorization grant (RFC 8628).\n"
                "Then disable the password grant at the authorization server for every client, not "
                "just in the contract. Removing it from the document does not stop the endpoint "
                "accepting it."),
            highlights=[
                mark("resource owner password credentials", "weak",
                     "RFC 9700 §2.4 states this grant MUST NOT be used."),
                mark("the client collects the user's actual username and password", "weak",
                     "The password leaves the authorization server and enters every client."),
                mark("incompatible with multi-factor authentication", "weak",
                     "There is no interactive step where the server can challenge the user."),
            ],
            evidence={
                "scheme": name,
                "flow": "password",
                "json_pointer": f"{pointer}/password",
                "token_url": password.get("tokenUrl"),
                "scopes": scopes,
                "flow_object": password,
                "forbidden_by": "RFC 9700 §2.4 (MUST NOT); removed in OAuth 2.1",
            },
        ))

    code_flow = flows.get("authorizationCode")
    if isinstance(code_flow, dict):
        scopes = _scope_names(code_flow)
        if scopes and any(name_ in ("*", "all", "full", "admin", "write:all", "read:all") for name_ in scopes):
            out.append(finding(
                "spec.oauth-broad-scope", "OAuth2 scheme declares a catch-all scope",
                "low", "confirmed", owasp="API5:2023 Broken Function Level Authorization", parameter=name,
                method=f"Read the scope names declared at {pointer}/authorizationCode/scopes.",
                detail=(f"Security scheme “{name}” declares the scope(s) "
                        f"{', '.join(s for s in scopes if s in ('*', 'all', 'full', 'admin', 'write:all', 'read:all'))}, "
                        "which grant everything the API can do in a single consent."),
                impact=("A token issued for a narrow purpose carries authority over every operation, so a "
                        "leaked token loses any blast-radius limit the scope model was supposed to give."),
                remediation=("Define scopes per resource and action (for example `orders:read`, "
                             "`orders:write`) and have each operation require only the scopes it needs. "
                             "Retire the catch-all scope once clients have migrated."),
                evidence={"scheme": name, "scopes": scopes, "json_pointer": f"{pointer}/authorizationCode/scopes"},
            ))

    if not flows and scheme.get("type", "").lower() == "oauth2":
        out.append(finding(
            "spec.oauth-no-pkce", "OAuth2 scheme declares no flows",
            "low", "confirmed", owasp="API2:2023 Broken Authentication", parameter=name,
            method=f"Read {pointer} in the imported document.",
            detail=(f"Security scheme “{name}” is typed oauth2 but declares no flows object, so the "
                    "contract does not say which grant, authorization URL or scopes a client should use."),
            impact=("Clients and reviewers cannot tell which grant is in use, so neither the correct "
                    "integration nor the correct security review can be derived from the contract."),
            remediation=("Declare the flow explicitly, normally `authorizationCode` with `authorizationUrl`, "
                         "`tokenUrl` and the scope list."),
            evidence={"scheme": name, "json_pointer": pointer, "scheme_object": scheme},
        ))
    return out
