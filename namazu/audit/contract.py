"""Offline contract conformance for every captured operation response.

Related disagreements become one operation observation with occurrence counts
and evidence references. Explicit edge pages and unmatched methods or routes
are separate from application conformance. Reviewing evidence sends no request.
"""
from __future__ import annotations

import copy
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

from ..runner import _matching_media, review_response
from ..spec import _pointer, _replace_pointer
from . import disclosure
from .identity import CREDENTIAL_HEADERS
from .model import Exchange, finding, mark, similarity
from .provenance import attach_snapshot_integrity
from .response_compare import edge_block_markers
from .response_records import captured_records
from .transport import Executor

# A value that makes a bearer credential structurally wrong rather than merely
# unknown, so a server that parses before it verifies will reject it. It names
# the tool, so it comes from the run's signature rather than being a constant.
SERVER_ERROR = range(500, 600)


def snapshot(spec: dict, operation: dict, *, request_url="") -> dict:
    """Portable response-only contract, with reachable local schema references.

    Request examples, credentials, servers and unrelated operation schemas do
    not belong in a response review snapshot. Local references remain local;
    reviewing a snapshot never fetches a URL.
    """
    def clean(value, *, named_map=False):
        if isinstance(value, dict):
            maps = {"properties", "patternProperties", "$defs", "definitions", "content", "headers", "links", "schemas", "responses"}
            return {key: clean(item, named_map=key in maps and not named_map) for key, item in value.items()
                    if named_map or key not in ("example", "examples", "default", "externalDocs")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return copy.deepcopy(value)

    selected = {key: clean(operation[key], named_map=key == "responses") for key in ("id", "method", "path", "responses", "produces")
                if key in operation}
    document = {key: spec.get("document", {}).get(key) for key in ("openapi", "swagger")
                if key in spec.get("document", {})}
    seen, warnings = set(), []

    def refs(value):
        if isinstance(value, dict):
            ref = value.get("$ref")
            if isinstance(ref, str) and ref not in seen:
                seen.add(ref)
                try:
                    if len(seen) > 512 or not ref.startswith("#/"):
                        raise ValueError("Only bounded local references can be preserved for offline review.")
                    target = clean(_pointer(spec.get("document", {}), ref))
                    # _replace_pointer expects parent containers to exist.
                    tokens = unquote(ref[2:]).split("/")
                    parent = document
                    for token in tokens[:-1]:
                        parent = parent.setdefault(token.replace("~1", "/").replace("~0", "~"), {})
                    _replace_pointer(document, ref, target)
                    refs(target)
                except (ValueError, TypeError, KeyError) as exc:
                    warnings.append(str(exc))
            for key, item in value.items():
                if key != "$ref":
                    refs(item)
        elif isinstance(value, list):
            for item in value:
                refs(item)

    refs(selected)
    return attach_snapshot_integrity({"snapshot_version": 1, "version": spec.get("version", "3.0.0"),
            "document": document, "operation": selected,
            "request_path": urlsplit(request_url).path if request_url else "",
            "warnings": list(dict.fromkeys(warnings))})


def _matches_operation(exchange, saved):
    operation = saved.get("operation", {})
    if exchange.method.upper() != str(operation.get("method") or "").upper():
        return False
    template = operation.get("path") or ""
    if not template:
        return True
    template_pattern = re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(template))
    path = urlsplit(exchange.url).path
    baseline_path = saved.get("request_path") or ""
    if baseline_path:
        matched = re.search(template_pattern + r"$", baseline_path)
        if matched:
            prefix = re.escape(baseline_path[:matched.start()])
            return re.fullmatch(prefix + template_pattern, path) is not None
        return path == baseline_path
    return re.search(template_pattern + r"$", path) is not None


def _response_definitions(saved):
    operation = saved["operation"]
    responses = operation.get("responses") or {}
    return {str(key): value for key, value in responses.items() if isinstance(value, dict)}


def _declared_media(saved, response=None):
    if response is None:
        out = {}
        for item in _response_definitions(saved).values():
            out.update(_declared_media(saved, item))
        return out
    if saved.get("version") == "2.0" and "schema" in response:
        return {media: {} for media in saved["operation"].get("produces") or ["*/*"]}
    content = response.get("content")
    return content if isinstance(content, dict) else {}


def _issues(saved, exchange):
    operation = saved["operation"]
    report = review_response(saved, operation, exchange.status,
                             {str(key).lower(): value for key, value in exchange.headers.items()},
                             exchange.body, exchange.truncated)
    checks = {entry.get("name"): entry.get("valid") for entry in report.get("checks", [])}
    issues = []
    media = exchange.header("content-type").split(";", 1)[0].strip().lower()
    if checks.get("Documented HTTP status") is False:
        issues.append({"kind": "undocumented-status", "status": exchange.status,
                       "message": f"HTTP {exchange.status} is not documented for this operation."})
        # No schema can be selected for an undocumented status. It is still
        # possible to state that a media type is absent from every declaration.
        declared = _declared_media(saved)
        if declared and not _matching_media(media, declared):
            issues.append({"kind": "undocumented-media-type", "status": exchange.status, "media_type": media or "(missing)",
                           "message": f"The operation does not document {media or '(missing Content-Type)'} in any response.",
                           "schema_comparison": "unavailable: response status is undocumented"})
    else:
        definitions = _response_definitions(saved)
        response = next((value for key, value in definitions.items() if key == str(exchange.status)), None)
        if response is None:
            response = next((value for key, value in definitions.items() if key.upper() == f"{exchange.status // 100}XX"), None)
        if response is None:
            response = next((value for key, value in definitions.items() if key.lower() == "default"), None)
        declared = _declared_media(saved, response) if response is not None else {}
        mismatch = (bool(declared) and not _matching_media(media, declared)
                    and exchange.method != "HEAD" and exchange.status not in (204, 304))
        if mismatch:
            issues.append({"kind": "undocumented-media-type", "status": exchange.status, "media_type": media or "(missing)",
                           "message": f"The operation does not document {media or '(missing Content-Type)'} for HTTP {exchange.status}.",
                           "syntax_suffix_match": checks.get("Documented Content-Type") is None and "Documented Content-Type" in checks})
    if checks.get("Response schema") is False or checks.get("Valid JSON") is False:
        errors = [exchange.safe_text(str(error.get("path", "")) + ": " + str(error.get("message", "")))
                  if isinstance(error, dict) else exchange.safe_text(str(error)) for error in report.get("errors", [])]
        issues.append({"kind": "response-schema-violation", "status": exchange.status,
                       "message": "The retained response violates its declared schema.", "violations": errors})
    return issues, report


def review_captured(saved, exchanges, endpoint, *, evidence_root="/log"):
    """Review every captured response; return data and Finding objects offline."""
    records = list(captured_records(exchanges, evidence_root))
    available = isinstance(saved, dict) and isinstance(saved.get("operation"), dict) and bool(saved["operation"].get("responses"))
    groups, reviewed, evidence = {}, [], []
    counts = Counter()
    for exchange, reference in records:
        row = {"evidence_ref": reference, "status": exchange.status,
               "method": exchange.method, "label": exchange.safe_text(exchange.label), "issues": []}
        if exchange.error or not exchange.status:
            counts["incomplete_tests"] += 1
            row.update(state="incomplete", reason_code="response-not-received", reason=exchange.safe_text(exchange.error) or "No response status was captured.")
        elif (markers := edge_block_markers(exchange)):
            counts["responses_received"] += 1
            counts["edge_responses"] += 1
            row.update(state="edge-block", reason_code="explicit-edge-block-page", markers=markers,
                       reason="Explicit Incapsula block markers were observed. Application contract review is excluded; downstream handling is unknown.")
        else:
            counts["responses_received"] += 1
            counts["application_responses"] += 1
            if not available:
                row.update(state="not-reviewed", reason_code="response-contract-unavailable",
                           reason="No response contract snapshot is available; contract agreement cannot be established from the export alone.")
            elif not _matches_operation(exchange, saved):
                row.update(state="not-reviewed", reason_code="operation-contract-unmatched",
                           reason="The request method or route differs from this operation's contract; no application contract is assigned by assumption.")
            else:
                issues, report = _issues(saved, exchange)
                reviewed.append(reference)
                row.update(state="mismatch" if issues else "incomplete" if report.get("valid") is None else "reviewed",
                           reason_code="response-contract-disagreement" if issues else "response-contract-incomplete" if report.get("valid") is None else "response-contract-reviewed",
                           issues=issues, warnings=report.get("warnings", []), checks=report.get("checks", []))
                if issues:
                    counts["mismatch_occurrences"] += 1
                for issue in issues:
                    import json
                    key = json.dumps(issue, sort_keys=True)
                    if key not in groups:
                        groups[key] = {**issue, "occurrence_count": 0, "occurrences": [], "exchange": exchange}
                    groups[key]["occurrence_count"] += 1
                    groups[key]["occurrences"].append(reference)
        evidence.append(row)
    findings = []
    if groups:
        mismatches = [{key: value for key, value in group.items() if key != "exchange"} for group in groups.values()]
        representatives = []
        for group in groups.values():
            if not any(group["exchange"] is item for item in representatives):
                representatives.append(group["exchange"])
        findings.append(finding(
            "contract.response-disagreement", "Captured application responses disagree with the operation contract",
            "info", "confirmed", endpoint=endpoint, category="contract", origin="runtime-observation", verification="observed",
            method="Compared the status, media type and available response schema of each captured application response with the saved operation contract; explicit edge block pages were reviewed separately.",
            detail=f"The operation does not document or match {len(groups)} distinct response contract condition(s), across {counts['mismatch_occurrences']} response occurrence(s): "
                   + " ".join(group["message"] for group in groups.values()),
            impact="Contract disagreement can affect client handling. No security mechanism failure or exploitable impact follows from this observation alone.",
            limitations="Only retained responses were reviewed. Undocumented statuses do not have a schema to validate against. Edge pages and unmatched operations are excluded from application attribution. A generated example is not proof of business-valid input.",
            remediation="Reconcile the documented statuses, media types and schemas with the intended responses. Add missing media types to the matching response content map.",
            evidence={"occurrence_count": counts["mismatch_occurrences"], "distinct_mismatches": len(groups),
                      "reviewed_responses": len(reviewed), "documented_statuses": sorted(_response_definitions(saved)),
                      "mismatches": mismatches, "representative_evidence": [group["occurrences"][0] for group in groups.values()]},
            exchanges=representatives[:8],
        ))
    disclosure_report, disclosure_findings = disclosure.review_captured(exchanges, endpoint, evidence_root=evidence_root)
    findings += disclosure_findings
    contract_findings = [item.to_dict() for item in findings if item.id == "contract.response-disagreement"]
    incomplete_review = [row for row in evidence if row["state"] in ("incomplete", "not-reviewed") or row.get("warnings")]
    contract_state = ("unavailable" if not available else "no-matching-application-responses" if not reviewed else
                      "partial" if incomplete_review else "reviewed")
    report = {
        "version": 1, "endpoint": endpoint, "request_attempts": len(records),
        **{key: counts[key] for key in ("responses_received", "application_responses", "edge_responses", "incomplete_tests")},
        "contract": {"state": contract_state, "reviewed_responses": len(reviewed),
                     "incomplete_review_responses": len(incomplete_review),
                     "mismatch_occurrences": counts["mismatch_occurrences"], "distinct_mismatches": len(groups),
                     "findings": contract_findings, "exchanges": evidence,
                     "missing_prerequisites": [] if available else ["A saved response contract for this operation is required for offline contract review."],
                     "limitations": list(saved.get("warnings") or []) if available else []},
        "disclosures": disclosure_report, "findings": [item.to_dict() for item in findings],
    }
    return report, findings


def review_exchanges(saved, exchanges, endpoint, *, evidence_root="/log"):
    """Serializable offline response review; sends no requests."""
    return review_captured(saved, exchanges, endpoint, evidence_root=evidence_root)[0]


def review_saved_audit(payload):
    """Review an imported audit's request log without trusting old conclusions."""
    requests = payload.get("requests", payload.get("log", [])) or []
    snapshots = payload.get("contract_snapshots") or {}
    if isinstance(snapshots, list):
        snapshots = {item.get("endpoint", ""): item.get("contract_snapshot", item.get("snapshot"))
                     for item in snapshots if isinstance(item, dict)}
    if payload.get("contract_snapshot") and payload.get("endpoint"):
        snapshots = {**snapshots, payload["endpoint"]: payload["contract_snapshot"]}
    grouped = {}
    for index, row in enumerate(requests):
        if not isinstance(row, dict):
            continue
        endpoint = row.get("endpoint") or payload.get("endpoint") or "unassigned operation"
        if endpoint == "surface sweep" or row.get("scope") == "inventory":
            continue
        grouped.setdefault(endpoint, []).append({**row, "evidence_ref": {"pointer": f"/requests/{index}", "index": index}})
    for row in (payload.get("coverage") or {}).get("baselines") or []:
        if isinstance(row, dict) and row.get("endpoint"):
            grouped.setdefault(row["endpoint"], [])
    return {"operations": [
        {"endpoint": endpoint, "contract_snapshot": snapshots.get(endpoint),
         "response_review": review_exchanges(snapshots.get(endpoint), rows, endpoint, evidence_root="/requests")}
        for endpoint, rows in grouped.items()
    ], "limitations": ["Inventory traffic is separate from endpoint contract review.",
                       "Original requests and responses are retained. Viewing or importing this assessment sends no target requests."]}


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

    # True, or absent because an earlier step returned first, means nothing to
    # report. None means the response was the declared syntax under a media type
    # the contract does not list, which is a weaker claim than a mismatch.
    media_match = checks.get("Documented Content-Type", True)
    if media_match is None:
        actual = baseline.content_type or "(none)"
        findings.append(finding(
            "contract.content-type-mismatch", "Response media type is not documented",
            "info", "confirmed", owasp="API9:2023 Improper Inventory Management", endpoint=endpoint,
            method=("Compared the response Content-Type against the media types the matched response "
                    "object declares, allowing a structured syntax suffix to match the syntax it "
                    "names."),
            detail=(f"The response arrived as {actual}, which the operation does not document for "
                    f"HTTP {baseline.status}. It carries a structured syntax suffix matching a media "
                    "type the contract does declare, so the body was still validated against that "
                    "schema."),
            impact=("A client that registers a deserializer for the exact documented media type, or "
                    "negotiates strictly on it, will not handle this response. One that reads the "
                    "suffix will."),
            remediation=(f"Add {actual} to the response content map for HTTP {baseline.status}."),
            highlights=[mark(actual, "weak", "The media type that is not in the contract.")],
            evidence={"content_type": actual, "status": baseline.status, "match": "syntax suffix"},
            exchanges=[baseline],
        ))
    elif media_match is False:
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


def _corrupt_cookies(value: str, invalid_token: str) -> str:
    """Every cookie value replaced, every cookie name kept.

    Replacing the whole header would send a cookie with no name, which a
    server discards: that is the anonymous replay again rather than a
    credential that is present and invalid, which is the question here.
    """
    out = []
    for item in (value or "").split(";"):
        name, separator, _ = item.strip().partition("=")
        out.append(f"{name}={invalid_token}" if separator and name else item.strip())
    return "; ".join(part for part in out if part)


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

    invalid_token = executor.signature.invalid_token
    corrupted = {}
    for name, value in headers.items():
        lowered = str(name).lower()
        if lowered == "authorization":
            scheme = value.split(" ", 1)[0] if " " in value else "Bearer"
            corrupted[name] = f"{scheme} {invalid_token}"
        elif lowered == "cookie":
            corrupted[name] = _corrupt_cookies(value, invalid_token)
        elif lowered in CREDENTIAL_HEADERS:
            corrupted[name] = invalid_token
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
        "critical", "confirmed", verification="impact-demonstrated",
            confirmed_claim=(
                "A request carrying a credential value that cannot be valid received the same authenticated "
                "response as the genuine credential."),
            owasp="API2:2023 Broken Authentication", endpoint=endpoint,
        method=("Replaced the credential value with a string that cannot be a valid token, kept every "
                "other header identical, and compared the two response bodies. The header was present "
                "and well-formed, so this is not a missing-credential test."),
        detail=(f"Sending the credential as “{invalid_token}” returned HTTP {probe.status} with a "
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
            mark(invalid_token, "attacker", "The worthless value Namazu sent in place of the token."),
            mark("without verifying the credential", "weak",
                 "Presence of the header was enough; the value was never checked."),
        ],
        evidence={"authenticated_status": baseline.status, "invalid_credential_status": probe.status,
                  "body_similarity": match, "sent_value": invalid_token,
                  "declared_security": operation.get("security")},
        exchanges=[baseline, probe],
    )]
