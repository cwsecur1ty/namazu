"""Per-check reference data: CWE, reading, and how the check is performed.

Keeping this out of the probe code means a finding's classification can be
reviewed and corrected in one place, and every probe gets a default "how this
was found" sentence. A probe that can say something more specific, such as which
payload fired, which two responses were compared, passes ``method=`` at the
call site and overrides the default.
"""
from __future__ import annotations

OWASP_API = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"


def _ref(title: str, url: str) -> dict:
    return {"title": title, "url": url}


CWE_NAMES = {
    16: "Configuration",
    79: "Cross-site Scripting",
    89: "SQL Injection",
    90: "LDAP Injection",
    93: "CRLF Injection",
    94: "Code Injection",
    113: "HTTP Response Splitting",
    200: "Exposure of Sensitive Information",
    209: "Generation of Error Message Containing Sensitive Information",
    235: "Improper Handling of Extra Parameters",
    284: "Improper Access Control",
    285: "Improper Authorization",
    287: "Improper Authentication",
    295: "Improper Certificate Validation",
    306: "Missing Authentication for Critical Function",
    319: "Cleartext Transmission of Sensitive Information",
    322: "Key Exchange without Entity Authentication",
    345: "Insufficient Verification of Data Authenticity",
    347: "Improper Verification of Cryptographic Signature",
    352: "Cross-Site Request Forgery",
    384: "Session Fixation",
    400: "Uncontrolled Resource Consumption",
    425: "Direct Request (Forced Browsing)",
    434: "Unrestricted Upload",
    441: "Unintended Proxy or Intermediary",
    444: "HTTP Request Smuggling",
    522: "Insufficiently Protected Credentials",
    523: "Unprotected Transport of Credentials",
    524: "Use of Cache Containing Sensitive Information",
    525: "Use of Web Browser Cache Containing Sensitive Information",
    538: "Insertion of Sensitive Information into Externally-Accessible File",
    540: "Inclusion of Sensitive Information in Source Code",
    548: "Exposure of Information Through Directory Listing",
    565: "Reliance on Cookies without Validation",
    598: "Use of GET Request Method With Sensitive Query Strings",
    601: "URL Redirection to Untrusted Site",
    613: "Insufficient Session Expiration",
    614: "Sensitive Cookie Without Secure Attribute",
    639: "Authorization Bypass Through User-Controlled Key",
    644: "Improper Neutralization of HTTP Headers",
    651: "Exposure of WSDL File",
    693: "Protection Mechanism Failure",
    770: "Allocation of Resources Without Limits",
    778: "Insufficient Logging",
    798: "Use of Hard-coded Credentials",
    829: "Inclusion of Functionality from Untrusted Control Sphere",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    918: "Server-Side Request Forgery",
    942: "Permissive Cross-domain Policy",
    1004: "Sensitive Cookie Without HttpOnly",
    1021: "Improper Restriction of Rendered UI Layers",
    1275: "Sensitive Cookie with Improper SameSite Attribute",
}

RFC = {
    "oauth-bcp": _ref("RFC 9700: OAuth 2.0 Security Best Current Practice",
                      "https://www.rfc-editor.org/rfc/rfc9700.html"),
    "oauth21": _ref("OAuth 2.1 draft", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1"),
    "pkce": _ref("RFC 7636: Proof Key for Code Exchange",
                 "https://www.rfc-editor.org/rfc/rfc7636.html"),
    "jwt-bcp": _ref("RFC 8725: JSON Web Token Best Current Practices",
                    "https://www.rfc-editor.org/rfc/rfc8725.html"),
    "cors": _ref("MDN: Cross-Origin Resource Sharing",
                 "https://developer.mozilla.org/docs/Web/HTTP/CORS"),
    "cookies": _ref("RFC 6265bis: Cookies: HTTP State Management",
                    "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis"),
    "hsts": _ref("RFC 6797: HTTP Strict Transport Security",
                 "https://www.rfc-editor.org/rfc/rfc6797.html"),
    "cache": _ref("RFC 9111: HTTP Caching", "https://www.rfc-editor.org/rfc/rfc9111.html"),
    "oas": _ref("OpenAPI 3.1 Specification", "https://spec.openapis.org/oas/v3.1.0.html"),
}
CHEAT = {
    "authz": _ref("OWASP Authorization Cheat Sheet",
                  "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"),
    "massassign": _ref("OWASP Mass Assignment Cheat Sheet",
                       "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"),
    "sqli": _ref("OWASP SQL Injection Prevention Cheat Sheet",
                 "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    "nosql": _ref("OWASP Testing for NoSQL Injection",
                  "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"),
    "ssti": _ref("OWASP Testing for Server-Side Template Injection",
                 "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"),
    "ssrf": _ref("OWASP SSRF Prevention Cheat Sheet",
                 "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
    "redirect": _ref("OWASP Unvalidated Redirects and Forwards Cheat Sheet",
                     "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    "traversal": _ref("OWASP Testing for Path Traversal",
                      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"),
    "xss": _ref("OWASP Cross Site Scripting Prevention Cheat Sheet",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    "headers": _ref("OWASP HTTP Security Response Headers Cheat Sheet",
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"),
    "rest": _ref("OWASP REST Security Cheat Sheet",
                 "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"),
    "graphql": _ref("OWASP GraphQL Cheat Sheet",
                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"),
    "crlf": _ref("OWASP Testing for HTTP Splitting and Smuggling",
                 "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling"),
    "hostheader": _ref("OWASP Testing for Host Header Injection",
                       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"),
    "clickjack": _ref("OWASP Clickjacking Defense Cheat Sheet",
                      "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
    "tls": _ref("OWASP Transport Layer Security Cheat Sheet",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"),
    "errors": _ref("OWASP Error Handling Cheat Sheet",
                   "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"),
    "secrets": _ref("OWASP Secrets Management Cheat Sheet",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
    "ratelimit": _ref("OWASP Denial of Service Cheat Sheet",
                      "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"),
    "hpp": _ref("OWASP Testing for HTTP Parameter Pollution",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"),
}

STATIC = "Read from the imported contract. No request was sent for this finding."
BASELINE = "Observed in the operation's baseline response. No extra request was sent."

# id -> cwe, references, default method sentence.
CATALOGUE: dict[str, dict] = {
    # ── contract analysis ────────────────────────────────────────────────
    "spec.unauthenticated-write": {"cwe": 306, "refs": [CHEAT["authz"], RFC["oas"]], "method": STATIC},
    "spec.deprecated-operation": {"cwe": 1059, "refs": [RFC["oas"]], "method": STATIC},
    "spec.mass-assignment-surface": {"cwe": 915, "refs": [CHEAT["massassign"]], "method": STATIC},
    "spec.ssrf-surface": {"cwe": 918, "refs": [CHEAT["ssrf"]], "method": STATIC},
    "spec.unbounded-pagination": {"cwe": 770, "refs": [CHEAT["ratelimit"]], "method": STATIC},
    "spec.sensitive-response-field": {"cwe": 200, "refs": [CHEAT["rest"]], "method": STATIC},
    "spec.apikey-in-query": {"cwe": 598, "refs": [CHEAT["rest"]], "method": STATIC},
    "spec.basic-auth": {"cwe": 522, "refs": [CHEAT["rest"]], "method": STATIC},
    "spec.oauth-implicit-flow": {"cwe": 598, "refs": [RFC["oauth-bcp"], RFC["oauth21"], RFC["pkce"]],
                                 "method": STATIC},
    "spec.oauth-password-flow": {"cwe": 522, "refs": [RFC["oauth-bcp"], RFC["oauth21"]], "method": STATIC},
    "spec.oauth-no-pkce": {"cwe": 287, "refs": [RFC["pkce"], RFC["oauth-bcp"]], "method": STATIC},
    "spec.oauth-broad-scope": {"cwe": 285, "refs": [RFC["oauth-bcp"]], "method": STATIC},
    "spec.no-auth-defined": {"cwe": 306, "refs": [RFC["oas"], CHEAT["rest"]], "method": STATIC},
    "spec.cleartext-server": {"cwe": 319, "refs": [CHEAT["tls"]], "method": STATIC},

    # ── transport and headers ────────────────────────────────────────────
    "transport.cleartext": {"cwe": 319, "refs": [CHEAT["tls"]], "method": BASELINE},
    "transport.no-hsts": {"cwe": 319, "refs": [RFC["hsts"], CHEAT["headers"]], "method": BASELINE},
    "transport.no-nosniff": {"cwe": 16, "refs": [CHEAT["headers"]], "method": BASELINE},
    "transport.cacheable-private": {"cwe": 525, "refs": [RFC["cache"], CHEAT["headers"]], "method": BASELINE},
    "transport.downgrade-redirect": {"cwe": 319, "refs": [CHEAT["tls"]],
                                     "method": "Read the Location header of the baseline response."},
    "tls.certificate": {"cwe": 295, "refs": [CHEAT["tls"]],
                        "method": "Inspected the X.509 certificate presented during the TLS handshake. "
                                  "No application request was needed."},
    "http.trace-enabled": {"cwe": 16, "refs": [CHEAT["headers"]],
                           "method": "Sent a TRACE request and checked whether the server echoed it back."},
    "clickjacking.missing-frame-controls": {"cwe": 1021, "refs": [CHEAT["clickjack"], CHEAT["headers"]],
                                            "method": BASELINE},

    # ── CORS and cookies ─────────────────────────────────────────────────
    "cors.wildcard-with-credentials": {"cwe": 942, "refs": [RFC["cors"], CHEAT["rest"]], "method": BASELINE},
    "cors.wildcard": {"cwe": 942, "refs": [RFC["cors"]], "method": BASELINE},
    "cors.private-network": {"cwe": 942, "refs": [RFC["cors"]], "method": BASELINE},
    "cors.origin-reflected": {"cwe": 942, "refs": [RFC["cors"], CHEAT["rest"]], "method": None},
    "cors.null-origin": {"cwe": 942, "refs": [RFC["cors"]], "method": None},
    "cookie.weak-flags": {"cwe": 1004, "refs": [RFC["cookies"], CHEAT["headers"]], "method": BASELINE},

    # ── information disclosure ───────────────────────────────────────────
    "disclosure.version-banner": {"cwe": 200, "refs": [CHEAT["headers"]], "method": BASELINE},
    "disclosure.verbose-error": {"cwe": 209, "refs": [CHEAT["errors"]], "method": BASELINE},
    "exposure.secret-value": {"cwe": 798, "refs": [CHEAT["secrets"]], "method": BASELINE},
    "exposure.sensitive-field": {"cwe": 200, "refs": [CHEAT["rest"]], "method": BASELINE},
    "exposure.undocumented-field": {"cwe": 200, "refs": [CHEAT["rest"], RFC["oas"]],
                                    "method": "Compared the field names in the response body against the "
                                              "properties declared in the operation's own 2xx schema."},
    "exposure.credential-in-url": {"cwe": 598, "refs": [CHEAT["rest"]], "method": BASELINE},

    # ── authentication ───────────────────────────────────────────────────
    "authz.missing-authentication": {"cwe": 306, "refs": [CHEAT["authz"]], "method": None},
    "authz.documented-auth-not-enforced": {"cwe": 285, "refs": [CHEAT["authz"], RFC["oas"]], "method": None},
    "authz.bola-confirmed": {"cwe": 639, "refs": [CHEAT["authz"]], "method": None},
    "authz.idor": {"cwe": 639, "refs": [CHEAT["authz"]], "method": None},
    "authz.bfla": {"cwe": 285, "refs": [CHEAT["authz"]], "method": None},
    "authz.write-bfla": {"cwe": 285, "refs": [CHEAT["authz"]], "method": None},
    "authz.method-bypass": {"cwe": 285, "refs": [CHEAT["authz"]], "method": None},
    "authz.invalid-credentials-accepted": {"cwe": 287, "refs": [CHEAT["authz"], RFC["jwt-bcp"]], "method": None},
    "contract.server-error": {"cwe": 248, "refs": [CHEAT["errors"], RFC["oas"]], "method": None},
    "contract.undocumented-status": {"cwe": 1059, "refs": [RFC["oas"]], "method": None},
    "contract.content-type-mismatch": {"cwe": 1059, "refs": [RFC["oas"]], "method": None},
    "contract.response-schema-violation": {"cwe": 1059, "refs": [RFC["oas"], CHEAT["rest"]], "method": None},
    "authz.path-bypass": {"cwe": 284, "refs": [CHEAT["authz"], CHEAT["rest"]], "method": None},
    "authz.header-bypass": {"cwe": 290, "refs": [CHEAT["authz"], CHEAT["hostheader"]], "method": None},
    "cache.deception": {"cwe": 524, "refs": [RFC["cache"], CHEAT["headers"]], "method": None},
    "inventory.source-exposed": {"cwe": 540, "refs": [CHEAT["rest"]], "method": None},
    "authz.method-override-honoured": {"cwe": 285, "refs": [CHEAT["authz"]], "method": None},

    # ── JWT ──────────────────────────────────────────────────────────────
    "jwt.forgeable-in-response": {"cwe": 347, "refs": [RFC["jwt-bcp"]], "method": BASELINE},
    "jwt.signature-not-verified": {"cwe": 347, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.forged-token-accepted": {"cwe": 347, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.alg-none": {"cwe": 347, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.expired": {"cwe": 613, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.weak-secret": {"cwe": 798, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.no-expiry": {"cwe": 613, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.long-lifetime": {"cwe": 613, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.kid-injectable": {"cwe": 94, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.remote-key-url": {"cwe": 345, "refs": [RFC["jwt-bcp"]], "method": None},
    "jwt.sensitive-claim": {"cwe": 200, "refs": [RFC["jwt-bcp"]], "method": None},

    # ── OAuth authorization server ───────────────────────────────────────
    "oauth.redirect-not-validated": {"cwe": 601, "refs": [RFC["oauth-bcp"], CHEAT["redirect"]], "method": None},
    "oauth.pkce-not-enforced": {"cwe": 287, "refs": [RFC["pkce"], RFC["oauth-bcp"]], "method": None},
    "oauth.implicit-enabled": {"cwe": 598, "refs": [RFC["oauth-bcp"], RFC["oauth21"]], "method": None},

    # ── input handling ───────────────────────────────────────────────────
    "input.sql-error": {"cwe": 89, "refs": [CHEAT["sqli"]], "method": None},
    "input.sql-boolean": {"cwe": 89, "refs": [CHEAT["sqli"]], "method": None},
    "input.nosql-operator": {"cwe": 943, "refs": [CHEAT["nosql"]], "method": None},
    "input.ldap-error": {"cwe": 90, "refs": [CHEAT["sqli"]], "method": None},
    "input.template-injection": {"cwe": 94, "refs": [CHEAT["ssti"]], "method": None},
    "input.html-reflection": {"cwe": 79, "refs": [CHEAT["xss"]], "method": None},
    "input.open-redirect": {"cwe": 601, "refs": [CHEAT["redirect"]], "method": None},
    "input.path-traversal": {"cwe": 22, "refs": [CHEAT["traversal"]], "method": None},
    "input.ssrf-confirmed": {"cwe": 918, "refs": [CHEAT["ssrf"]], "method": None},
    "input.crlf-injection": {"cwe": 113, "refs": [CHEAT["crlf"]], "method": None},
    "input.header-reflection": {"cwe": 644, "refs": [CHEAT["hostheader"]], "method": None},
    "input.parameter-pollution": {"cwe": 235, "refs": [CHEAT["hpp"]], "method": None},
    "input.mass-assignment-confirmed": {"cwe": 915, "refs": [CHEAT["massassign"]], "method": None},
    "input.mass-assignment-echoed": {"cwe": 915, "refs": [CHEAT["massassign"]], "method": None},
    "input.unknown-property-accepted": {"cwe": 235, "refs": [CHEAT["massassign"], RFC["oas"]], "method": None},

    # ── resource consumption ─────────────────────────────────────────────
    "limits.pagination-not-enforced": {"cwe": 770, "refs": [CHEAT["ratelimit"]], "method": None},
    "limits.no-rate-limit": {"cwe": 770, "refs": [CHEAT["ratelimit"]], "method": None},

    # ── inventory ────────────────────────────────────────────────────────
    "inventory.docs-exposed": {"cwe": 200, "refs": [CHEAT["rest"]], "method": None},
    "inventory.undocumented-endpoint": {"cwe": 425, "refs": [CHEAT["rest"]], "method": None},
    "inventory.graphql-introspection": {"cwe": 200, "refs": [CHEAT["graphql"]], "method": None},
    "inventory.graphql-suggestions": {"cwe": 200, "refs": [CHEAT["graphql"]], "method": None},
    "inventory.version-sibling": {"cwe": 1059, "refs": [CHEAT["rest"]], "method": None},
    "inventory.zombie-operation": {"cwe": 1059, "refs": [RFC["oas"]], "method": BASELINE},
    "inventory.undocumented-methods": {"cwe": 749, "refs": [CHEAT["rest"]], "method": None},
}

# CWE ids used above that are not in the short name table.
CWE_NAMES.setdefault(22, "Path Traversal")
CWE_NAMES.setdefault(248, "Uncaught Exception")
CWE_NAMES.setdefault(290, "Authentication Bypass by Spoofing")
CWE_NAMES.setdefault(749, "Exposed Dangerous Method or Function")
CWE_NAMES.setdefault(943, "Improper Neutralization in Data Query Logic")
CWE_NAMES.setdefault(1059, "Insufficient Technical Documentation")


def decorate(finding_id: str) -> dict:
    """Catalogue entry for a check: cwe label, references and default method."""
    entry = CATALOGUE.get(finding_id)
    extra = BACKGROUND.get(finding_id, {})
    if not entry:
        return {"cwe": None, "references": [], "method": "", **extra}
    cwe = entry.get("cwe")
    return {
        "cwe": f"CWE-{cwe}: {CWE_NAMES.get(cwe, '')}".rstrip(": ") if cwe else None,
        "references": list(entry.get("refs") or []),
        "method": entry.get("method") or "",
        **extra,
    }


# What a finding of each kind does not establish. A probe with something more
# specific to say passes limitations= and keeps it.
STATIC_LIMITATION = (
    "Identified from the imported document. Namazu sent no request for this finding, so it does not "
    "establish that the running implementation behaves the way the document describes. The "
    "declaration may be stale, or the feature may be disabled at the server."
)
BASELINE_LIMITATION = (
    "Observed in a single response. A route that behaves differently under other inputs, other "
    "credentials or other conditions would not be reflected here."
)
CONFIDENCE_LIMITATION = {
    "probable": "The evidence is consistent with this weakness but was not proved outright. "
                "Confirm it by hand before reporting it as exploitable.",
    "possible": "This is attack surface rather than a demonstrated weakness. It describes something "
                "worth testing, not something Namazu established.",
}


def default_limitation(finding_id: str, method: str, confidence: str) -> str:
    """The honest caveat for a finding, from how it was reached."""
    parts = []
    if method == STATIC:
        parts.append(STATIC_LIMITATION)
    elif method == BASELINE:
        parts.append(BASELINE_LIMITATION)
    caveat = CONFIDENCE_LIMITATION.get(confidence)
    if caveat:
        parts.append(caveat)
    return "\n\n".join(parts)


def coverage() -> dict:
    """Every check the engine can emit, for the UI's coverage view."""
    return {finding_id: decorate(finding_id) for finding_id in sorted(CATALOGUE)}


# ── highlight rules ──────────────────────────────────────────────────────────
# Evidence keys whose value is the thing a reader should look at first, with the
# reason shown on hover. "kind" drives the colour: weak and leak are red,
# attacker is amber (a value Namazu supplied), proof is the accent colour.
EVIDENCE_HIGHLIGHTS = {
    # the dangerous value itself
    "cracked_secret": ("weak", "The signing secret, recovered offline. Anyone holding it can mint a valid token."),
    "secret": ("weak", "The signing secret, recovered offline."),
    "flow": ("weak", "The grant type that carries the weakness."),
    "allow_origin": ("weak", "The origin the server told the browser to trust."),
    "forged_algorithm": ("weak", "The algorithm Namazu substituted; the server accepted it."),
    "algorithm": ("weak", "The token's signing algorithm."),
    "missing": ("weak", "The cookie attributes that are absent."),
    "removed_in": ("weak", "The specification that withdrew this grant."),
    "forbidden_by": ("weak", "The requirement this contradicts."),
    "declared_security": ("weak", "The security requirement the contract declares. Empty means none."),
    "protocol": ("weak", "The TLS version negotiated."),
    "verification_error": ("weak", "Why the certificate failed verification."),

    # data that should not have been returned
    "match_prefix": ("leak", "The start of the credential pattern matched in the response body."),
    "fields": ("leak", "Response fields carrying values that should not leave the server."),
    "undocumented": ("leak", "Fields returned that the operation's own schema never declares."),
    "secret_bearing": ("leak", "Undocumented fields that also look like secrets."),
    "properties": ("leak", "Privileged properties a client is able to set."),
    "excerpt": ("leak", "The disclosed content, as returned."),
    "error_excerpt": ("leak", "The server's own error text, returned to the caller."),
    "headers": ("leak", "Response headers that disclose software versions."),
    "privilege_claims": ("leak", "Privilege claims carried inside the token."),
    "escalated_claims": ("attacker", "The claims Namazu raised before re-signing the token."),

    # values Namazu supplied
    "payload": ("attacker", "The value Namazu sent into this parameter."),
    "true_payload": ("attacker", "The predicate that should match, if the input reaches a query."),
    "false_payload": ("attacker", "The predicate that should not match."),
    "confirm_payload": ("attacker", "A second true predicate, used to rule out coincidence."),
    "sent_redirect_uri": ("attacker", "The redirect target Namazu supplied. The server should have rejected it."),
    "sent_origin": ("attacker", "The Origin header Namazu supplied."),
    "sent": ("attacker", "The value Namazu supplied."),
    "unresolvable_payload": ("attacker", "A host that cannot resolve. Only a server-side fetch produces an error for it."),
    "loopback_payload": ("attacker", "A closed port on the server's own loopback interface."),
    "canary": ("attacker", "The random marker Namazu sent, so reflection cannot be mistaken for existing content."),
    "swapped": ("attacker", "The identifier Namazu substituted."),
    "second_value": ("attacker", "The duplicate value Namazu appended."),
    "value": ("attacker", "The header value Namazu supplied."),
    "response_type": ("attacker", "The response type Namazu requested."),

    # what proves it
    "location": ("proof", "The Location header the server returned, read without following it."),
    "error_signature": ("proof", "The network error pattern that proves the server attempted the fetch."),
    "injected_header": ("proof", "A header present only because the payload contained a line break."),
    "probe_header_value": ("proof", "The value that arrived in the injected header."),
    "echoed_header": ("proof", "The header the server echoed back."),
    "signature_a": ("proof", "Normalised fingerprint of the first identity's response body."),
    "signature_b": ("proof", "Normalised fingerprint of the second identity's response body. Identical means no ownership check."),
    "json_pointer": ("proof", "Where this sits in the imported document."),
    "allow": ("proof", "The methods the server advertises for this path."),
    "code_challenge_methods_supported": ("proof", "PKCE methods the server advertises but does not require."),
}
# Keys whose value is a number or flag worth marking only when it is damning.
CONDITIONAL_HIGHLIGHTS = {
    "body_similarity": lambda v: isinstance(v, (int, float)) and v >= 0.95,
    "identical": lambda v: v is True,
    "reached_loopback": lambda v: v is True,
    "allow_credentials": lambda v: v is True,
    "verified_by_read_back": lambda v: v is True,
}
_CONDITIONAL_NOTES = {
    "body_similarity": ("proof", "How closely the two bodies match after normalising volatile values."),
    "identical": ("proof", "The two responses are the same object."),
    "reached_loopback": ("proof", "The fetch reached the server's own loopback interface."),
    "allow_credentials": ("weak", "Credentials are allowed alongside the reflected origin."),
    "verified_by_read_back": ("proof", "The value was still there when the object was read back."),
}


def derive_highlights(evidence: dict) -> list:
    """Mark the evidence values that carry the meaning of a finding."""
    out: list = []
    for key, value in (evidence or {}).items():
        rule = EVIDENCE_HIGHLIGHTS.get(key)
        if rule:
            kind, note = rule
            for item in (value if isinstance(value, list) else [value]):
                if isinstance(item, (dict, list)) or item in (None, "", True, False):
                    continue
                text = str(item)
                if 3 <= len(text) <= 240:
                    out.append({"text": text, "kind": kind, "note": note})
            continue
        test = CONDITIONAL_HIGHLIGHTS.get(key)
        if test and test(value):
            kind, note = _CONDITIONAL_NOTES[key]
            out.append({"text": str(value), "kind": kind, "note": note})
    return out[:24]


def pointer_commands(source_url: str, pointer: str) -> dict | None:
    """Shell commands that print the exact part of the contract a finding came from.

    A contract finding has no request behind it, so there is nothing to replay.
    What a reader can still do is pull the document and look at the same place,
    which is what these commands do.
    """
    if not source_url or not pointer or not pointer.startswith("#/"):
        return None
    segments = [part.replace("~1", "/").replace("~0", "~") for part in pointer[2:].split("/") if part]
    if not segments:
        return None
    jq_path = "".join(
        f".{part}" if part.replace("_", "").replace("-", "").isalnum() and not part[0].isdigit()
        else f'["{part}"]'
        for part in segments
    )
    ps_path = "".join(f".'{part}'" for part in segments)
    return {
        "bash": f"curl -s {source_url} | jq '{jq_path}'",
        "powershell": f"(Invoke-RestMethod '{source_url}'){ps_path} | ConvertTo-Json -Depth 6",
        "cmd": f'curl.exe -s "{source_url}" | jq "{jq_path}"',
    }


# ── issue background ─────────────────────────────────────────────────────────
# How a class of weakness works, independent of this target. Kept apart from a
# finding's own observation so a reader can tell "what is true here" from "what
# is true about this kind of bug". This is the split Burp Suite uses between Issue
# detail and Issue background.
BACKGROUND: dict[str, dict] = {
    "spec.oauth-implicit-flow": {
        "background": (
            "OAuth 2.0's implicit grant returns the access token to the browser through the front "
            "channel. The authorization server redirects the user back to the client with the token in "
            "the URL fragment:\n\n"
            "    https://app.example.com/callback#access_token=eyJhbGciOi…\n\n"
            "The authorization code grant returns a short-lived, single-use code instead, which the "
            "client exchanges for a token over a back channel. PKCE (RFC 7636) binds that exchange: the "
            "client sends SHA-256 of a random verifier on the authorization request, and the verifier "
            "itself when redeeming the code.\n\n"
            "    implicit        browser receives:  ACCESS TOKEN     (usable immediately)\n"
            "    code + PKCE     browser receives:  CODE             (useless without the verifier)\n\n"
            "The practical difference is what an attacker gains by intercepting the front-channel "
            "response. Under implicit it carries a working bearer token. Under authorization code with "
            "PKCE it carries a code that cannot be redeemed without the matching verifier, which never "
            "leaves the client.\n\n"
            "RFC 9700 (OAuth 2.0 Security Best Current Practice, January 2025) states the implicit grant "
            "SHOULD NOT be used. OAuth 2.1 removes it from the specification."
        ),
        "remediation_background": (
            "Authorization code with PKCE is the flow RFC 9700 recommends for every client type, public "
            "and confidential alike. PKCE is no longer only for mobile and single-page applications. A "
            "public client (browser or native app) uses it without a client secret; a confidential "
            "client uses it in addition to client authentication.\n\n"
            "Exact-match redirect URI registration matters as much as the grant choice. Prefix and "
            "wildcard matching have repeatedly been the step that turns a front-channel weakness into "
            "account takeover."
        ),
    },
    "spec.oauth-password-flow": {
        "background": (
            "The resource owner password credentials grant has the client collect the user's real "
            "username and password and post them to the token endpoint. It exists in OAuth 2.0 as a "
            "migration path for legacy applications that already handled passwords directly.\n\n"
            "RFC 9700 §2.4 states the grant MUST NOT be used. OAuth 2.1 removes it. The objection is "
            "structural rather than cryptographic: the grant requires the password to pass through the "
            "client, which is the thing OAuth was designed to avoid."
        ),
        "remediation_background": (
            "Which grant replaces it depends on the client, not on the API:\n"
            "  • browser, mobile, desktop or SPA  →  authorization code + PKCE\n"
            "  • service with no user present     →  client credentials\n"
            "  • TV, CLI or other constrained input → device authorization grant (RFC 8628)\n\n"
            "Disabling the grant at the authorization server is the change that takes effect. Removing "
            "it from the API document only stops it being advertised."
        ),
    },
    "authz.bola-confirmed": {
        "background": (
            "Broken Object Level Authorization is the most common API weakness and the hardest to catch "
            "in review, because the code usually looks correct: the request is authenticated, the handler "
            "runs, and an object is returned. What is missing is the check that the object belongs to the "
            "caller.\n\n"
            "    GET /orders/1   as alice   →  200  {\"id\":1,\"owner\":\"alice\"}\n"
            "    GET /orders/1   as bob     →  200  {\"id\":1,\"owner\":\"alice\"}   ← no ownership check\n\n"
            "Authentication answers \"who is calling\". Authorization answers \"may this caller have this "
            "object\". A route can do the first perfectly and omit the second entirely."
        ),
        "remediation_background": (
            "The durable fix is to scope the query by the authenticated subject rather than fetch first "
            "and filter afterwards: `WHERE id = ? AND owner_id = ?` rather than `WHERE id = ?` followed "
            "by a comparison that a later refactor can drop.\n\n"
            "Unguessable identifiers raise the cost of enumeration but are not an access control. Treat "
            "them as defence in depth, never as the check itself."
        ),
    },
    "authz.idor": {
        "background": (
            "An object reference that a client can change, such as a sequential id in a path or a query "
            "parameter, lets a caller address objects that were never offered to them. Where the server "
            "does not verify ownership, walking the identifier space enumerates the collection."
        ),
    },
    "authz.missing-authentication": {
        "background": (
            "A route that returns the same data with and without credentials is performing no "
            "authentication at all. This is distinct from a broken authorization check: there is no "
            "identity involved, so every caller is equivalent."
        ),
    },
    "jwt.signature-not-verified": {
        "background": (
            "A JWT's integrity rests entirely on its signature. A server that decodes the payload without "
            "verifying the signature accepts whatever the client asserts.\n\n"
            "The `alg` header is attacker-supplied, which is why RFC 8725 tells implementations to pin "
            "the expected algorithm rather than read it from the token. `alg:none` was standardised for "
            "tokens whose integrity is guaranteed by another layer; accepted on a bearer token it is a "
            "complete authentication bypass."
        ),
        "remediation_background": (
            "Verify with an explicitly configured algorithm and key. Reject `none`, reject an `alg` that "
            "does not match what you configured, and do not let the token select between symmetric and "
            "asymmetric verification, because that choice is the algorithm-confusion attack."
        ),
    },
    "jwt.weak-secret": {
        "background": (
            "HMAC-signed tokens are only as strong as the shared secret. A secret from a tutorial, a "
            "framework default, or a short word is recoverable offline from a single captured token, at "
            "no cost to the attacker and with nothing visible to the server."
        ),
    },
    "input.sql-boolean": {
        "background": (
            "Boolean-based blind SQL injection works where the application does not return database "
            "errors but does behave differently depending on whether an injected condition is true.\n\n"
            "    ?id=5 AND 1=1   →  the normal record\n"
            "    ?id=5 AND 1=2   →  a different response\n\n"
            "Each request answers one yes/no question about the database, which is enough to read data a "
            "character at a time. No error message is required."
        ),
        "remediation_background": (
            "Parameterised queries remove the weakness by construction: the value never becomes part of "
            "the statement. Escaping and allow-lists are weaker because they depend on the escaping "
            "matching every context the value can reach."
        ),
    },
    "input.sql-error": {
        "background": (
            "A database error produced by an unbalanced quote shows the input is being concatenated into "
            "a statement rather than passed as a parameter. The error itself is a side effect; the "
            "concatenation is the weakness."
        ),
    },
    "input.ssrf-confirmed": {
        "background": (
            "Server-Side Request Forgery turns the API into a proxy. The server's network position is "
            "usually far more privileged than the caller's: cloud instance metadata, internal admin "
            "interfaces, databases and service meshes commonly trust anything originating inside the "
            "network.\n\n"
            "Detection does not require reaching any of those. A network error that only the server could "
            "have produced, such as a name that does not resolve or a port that refuses the connection, "
            "establishes that the parameter controls a server-side fetch."
        ),
        "remediation_background": (
            "Allow-listing destinations is the only robust control. Blocklists of private ranges are "
            "bypassed by DNS rebinding, redirects, IPv6-mapped addresses and alternative encodings, so "
            "resolve the hostname, check the resolved address, and connect to that address rather than "
            "re-resolving."
        ),
    },
    "cors.origin-reflected": {
        "background": (
            "The same-origin policy stops one site reading another's authenticated responses. CORS is how "
            "a server opts out for specific origins. A server that echoes whatever Origin it receives has "
            "opted out for all of them.\n\n"
            "With `Access-Control-Allow-Credentials: true`, any site a victim visits can make credentialed "
            "requests to this API and read the replies."
        ),
    },
    "input.mass-assignment-confirmed": {
        "background": (
            "Mass assignment occurs where a framework binds a request body onto a model automatically. "
            "The convenience is that new fields need no plumbing; the cost is that fields the server "
            "should own, such as role, balance or verification state, are writable by whoever sends the body."
        ),
        "remediation_background": (
            "Bind an explicit allow-list per endpoint. A deny-list of sensitive fields fails the first "
            "time someone adds a sensitive field without updating it."
        ),
    },
    "input.open-redirect": {
        "background": (
            "A redirect whose destination comes from a request parameter lends the origin's reputation to "
            "an attacker's link. Where the parameter feeds an OAuth or SSO redirect, the consequence is "
            "not phishing but delivery of codes or tokens to the attacker's host."
        ),
    },
    "input.path-traversal": {
        "background": (
            "Where a path segment reaches the filesystem without being confined to a base directory, "
            "relative traversal reads files outside it. Configuration, credentials and keys are the usual "
            "targets."
        ),
    },
    "input.crlf-injection": {
        "background": (
            "A carriage return and line feed terminate a header in the HTTP message. Input that reaches "
            "the response head without those characters being removed lets a caller append headers, and "
            "in some stacks terminate the head and supply a body of their own."
        ),
    },
    "input.header-reflection": {
        "background": (
            "`X-Forwarded-Host` is set by proxies to preserve the original host. An application that "
            "trusts it when building absolute URLs will build them from whatever a client sends, because "
            "the header carries no authentication."
        ),
    },
    "limits.no-rate-limit": {
        "background": (
            "Rate limiting bounds what a single caller can consume and how fast an attack can iterate. "
            "Its absence is what makes credential stuffing, enumeration and brute force practical at "
            "scale rather than merely possible."
        ),
    },
    "limits.pagination-not-enforced": {
        "background": (
            "A page size the caller controls without a server-side ceiling converts one request into "
            "unbounded work: the database reads it, the application serialises it, and the network "
            "carries it."
        ),
    },
    "inventory.undocumented-endpoint": {
        "background": (
            "Shadow endpoints are routes that exist but appear in no specification. They receive none of "
            "the review, testing or gateway policy that documented routes get, which is why operational "
            "and debug paths are so often the weakest surface on a host."
        ),
    },
    "inventory.version-sibling": {
        "background": (
            "Superseded API versions commonly keep running after clients migrate. They retain the "
            "authorization and validation rules they shipped with, so a fix applied to the current "
            "version does not reach them."
        ),
    },
    "exposure.undocumented-field": {
        "background": (
            "Where a response is serialised from a model rather than an explicit field list, adding a "
            "column to that model adds it to the API. The contract stops describing what is actually "
            "returned, and review based on the contract stops being complete."
        ),
    },
    "transport.cleartext": {
        "background": (
            "Without TLS, credentials and responses are readable and modifiable by anything on the "
            "network path. For an API this includes the bearer token on every request."
        ),
    },
}
