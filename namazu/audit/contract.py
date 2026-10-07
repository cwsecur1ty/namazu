"""Contract conformance as audit findings.

The workbench already validates a response against its declared contract, and
the result is shown per request. This turns the same comparison into findings,
so a run across the whole API reports where the implementation and its own
published schema disagree.

That class of defect is what property-based tools like schemathesis exist to
find. Having it natively means the gap is reported whether or not the optional
tooling is installed, and it costs no extra request: everything here is derived
from the baseline response the audit already captured.
"""
from __future__ import annotations

import re

from ..runner import review_response
from .model import Exchange, finding, mark, similarity
from .transport import BudgetExhausted, Executor

# Tokens that make a bearer credential structurally wrong rather than merely
# unknown, so a server that parses before it verifies will reject them.
INVALID_TOKEN = "namazu.invalid.credential"
SERVER_ERROR = range(500, 600)


def review(spec: dict, operation: dict, baseline: Exchange, endpoint: str) -> list:
    """Compare the baseline response with the operation's own contract."""
    if not baseline.ok or not (operation.get("responses") or {}):
        return []
    report = review_response(spec, operation, baseline.status, baseline.headers,
                             baseline.body, baseline.truncated)
    findings: list = []
    checks = {entry.get("name"): entry.get("valid") for entry in (report.get("checks") or [])
              if isinstance(entry, dict)}
    documented = sorted(str(code) for code in (operation.get("responses") or {}))

    if baseline.status in SERVER_ERROR:
        findings.append(finding(
            "contract.server-error", "Operation returned a server error to its own example request",
            "medium", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            method=("Sent the request the contract describes, built from the documented parameter "
                    "examples and schema, and read the status."),
            detail=(f"The baseline request returned HTTP {baseline.status}. The inputs came from the "
                    "operation's own documented examples and schema, so this is not a malformed "
                    "request being rejected."),
            impact=("An unhandled path exists behind an input the contract presents as valid. Error "
                    "handlers are also where stack traces and internal detail tend to escape."),
            remediation=("Handle the input and return a documented status, or correct the schema if the "
                         "request Namazu generated is not actually valid for this operation."),
            highlights=[mark(str(baseline.status), "weak",
                             "The status returned to a request the contract says is valid.")],
            evidence={"status": baseline.status, "documented_statuses": documented,
                      "body_excerpt": baseline.excerpt(300)},
            exchanges=[baseline],
        ))
    elif checks.get("Documented HTTP status") is False:
        findings.append(finding(
            "contract.undocumented-status", "Response status is not documented for this operation",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management", endpoint=endpoint,
            method=("Compared the baseline response status against the status codes the operation "
                    "declares, including range keys such as 4XX and the default entry."),
            detail=(f"The operation returned HTTP {baseline.status}, which does not appear in its "
                    f"documented responses ({', '.join(documented) or 'none declared'})."),
            impact=("A client written from this contract has no branch for this status, so it will "
                    "treat the response as something it is not."),
            remediation=(f"Document HTTP {baseline.status} for this operation, or return one of the "
                         "statuses the contract already declares."),
            highlights=[mark(str(baseline.status), "weak", "The status the contract does not mention.")],
            evidence={"status": baseline.status, "documented_statuses": documented},
            exchanges=[baseline],
        ))

    if checks.get("Documented Content-Type") is False:
        actual = baseline.content_type or "(none)"
        findings.append(finding(
            "contract.content-type-mismatch", "Response media type is not documented",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management", endpoint=endpoint,
            method=("Compared the response Content-Type against the media types the matched response "
                    "object declares."),
            detail=(f"The response arrived as {actual}, which the operation does not document for "
                    f"HTTP {baseline.status}."),
            impact="A client negotiating on the documented media type will fail to parse this response.",
            remediation="Return a documented media type, or add this one to the response content map.",
            highlights=[mark(actual, "weak", "The media type that is not in the contract.")],
            evidence={"content_type": actual, "status": baseline.status},
            exchanges=[baseline],
        ))

    if checks.get("Response schema") is False or checks.get("Valid JSON") is False:
        problems = [entry if isinstance(entry, str) else
                    f"{entry.get('path', '')}: {entry.get('message', '')}".strip(": ")
                    for entry in (report.get("errors") or [])][:8]
        findings.append(finding(
            "contract.response-schema-violation", "Response body does not match its declared schema",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management", endpoint=endpoint,
            method=("Validated the response body against the JSON Schema the operation declares for "
                    "this status and media type."),
            detail=("The response body violates the schema the operation publishes for it: "
                    + "; ".join(problems) if problems else
                    "The response body violates the schema the operation publishes for it."),
            background=(
                "A schema that does not describe the real response is worse than no schema. Clients "
                "generate models from it, test suites assert against it, and gateways sometimes "
                "enforce it. When it drifts, every one of those is wrong in the same direction and "
                "nothing reports it."),
            impact=("Generated clients will mis-parse this response, and any review that reads the "
                    "contract rather than the traffic is reasoning about something that is not there."),
            remediation=("Correct the schema to describe what the operation returns, or change the "
                         "handler to match the published shape."),
            highlights=[mark(problems[0], "proof", "The first mismatch found.")] if problems else [],
            evidence={"status": baseline.status, "violations": problems,
                      "body_excerpt": baseline.excerpt(300)},
            exchanges=[baseline],
        ))
    return findings


def invalid_credentials(executor: Executor, *, baseline: Exchange, endpoint: str,
                        operation: dict, identity: dict, headers: dict) -> list:
    """Does a structurally invalid credential still get in?

    This is a different question from the anonymous replay. Many servers reject
    a missing Authorization header at the framework level and then never verify
    the token they were given, so a deliberate nonsense value is the probe that
    separates "authentication is enforced" from "a header is required".
    """
    if baseline.method not in ("GET", "HEAD") or not identity:
        return []
    declared = any(isinstance(entry, dict) and entry for entry in (operation.get("security") or []))
    if not declared or not executor.affordable(1):
        return []
    if not (baseline.ok and 200 <= baseline.status < 300 and len(baseline.body.strip()) > 2):
        return []

    corrupted = {}
    for name, value in headers.items():
        if name.lower() == "authorization":
            scheme = value.split(" ", 1)[0] if " " in value else "Bearer"
            corrupted[name] = f"{scheme} {INVALID_TOKEN}"
        elif name.lower() in ("x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token"):
            corrupted[name] = INVALID_TOKEN
        else:
            corrupted[name] = value
    if corrupted == headers:
        return []

    probe = executor.send(baseline.method, baseline.url,
                          label="replay with a deliberately invalid credential",
                          headers=corrupted, identity="invalid credential")
    if not probe.ok or not (200 <= probe.status < 300) or len(probe.body.strip()) <= 2:
        return []
    match = similarity(baseline.body, probe.body)
    if match < 0.9:
        return []
    return [finding(
        "authz.invalid-credentials-accepted", "A deliberately invalid credential was accepted",
        "critical", "confirmed", owasp="API2:2023 Broken Authentication", endpoint=endpoint,
        method=("Replaced the credential value with a string that cannot be a valid token, kept every "
                "other header identical, and compared the two response bodies. The header was present "
                "and well-formed, so this is not a missing-credential test."),
        detail=(f"Sending the credential as “{INVALID_TOKEN}” returned HTTP {probe.status} with a "
                f"body {int(match * 100)}% similar to the authenticated response. The server accepts "
                "the request without verifying the credential it was given."),
        background=(
            "A route can require an Authorization header without ever checking it. Framework "
            "middleware often enforces presence, while verification sits in application code that a "
            "refactor can remove or a feature flag can disable. Testing with no header at all does "
            "not catch this, because the presence check still fires. Sending a well-formed header "
            "with a worthless value is what separates the two."),
        impact=("Anyone can call this route by inventing a credential. The route is effectively "
                "public while appearing authenticated in the contract and in logs."),
        remediation=("Verify the credential on every request and reject anything that does not "
                     "validate. Make verification the thing that grants access, rather than the "
                     "presence of a header."),
        highlights=[
            mark(INVALID_TOKEN, "attacker", "The worthless value Namazu sent in place of the token."),
            mark("without verifying the credential", "weak",
                 "Presence of the header was enough; the value was never checked."),
        ],
        evidence={"authenticated_status": baseline.status, "invalid_credential_status": probe.status,
                  "body_similarity": match, "sent_value": INVALID_TOKEN,
                  "declared_security": operation.get("security")},
        exchanges=[baseline, probe],
    )]
