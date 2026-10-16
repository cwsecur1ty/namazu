"""Restrained implementation detail review of already captured responses.

Signatures describe what is visible, never the privacy of a hostname or the
exploitability of a framework. Ordinary validation details are kept separate.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .model import finding
from .response_compare import edge_block_markers
from .response_records import captured_records

_STACKS = (
    (re.compile(r"Traceback \(most recent call last\):"), "Python traceback"),
    (re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"), "Java stack frame"),
    (re.compile(r"(?m)^\s*at [\w.$]+\([^\n]*\) in [^\n]+:line \d+"), ".NET stack frame"),
    (re.compile(r"(?m)^\s*at (?:[\w.$]+ )?\(?[^\n]*\.(?:js|ts):\d+:\d+\)?\s*$"), "JavaScript stack frame"),
)
_EXCEPTION = re.compile(r"\b(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*(?:Exception|Error)\b")
_PATH = re.compile(
    r"(?<![\w:/])(?:[A-Za-z]:\\(?:[^\s\"<>|]+\\)*[^\s\"<>|,;]+"
    r"|/(?:app|srv|var|home|opt|usr|etc|tmp|www|workspace)/(?:[^\s\"<>|,;])+)")
_HOST_KEYS = {"host", "hostname", "backendhost", "backendhostname", "serverhost", "serverhostname", "machine", "machinename"}
_MESSAGE_KEYS = {"detail", "message", "error", "exception", "stack", "stacktrace", "traceback", "instance"}
_IGNORED_KEYS = {"type", "documentation", "documentationurl", "docs", "help", "helpurl", "traceid", "correlationid", "requestid", "timestamp"}
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def _strings(body):
    try:
        value = json.loads(body)
    except (TypeError, ValueError):
        return [("body", body)]
    result = []

    def visit(item, path="", parent=""):
        if isinstance(item, dict):
            for name, child in item.items():
                key = str(name).lower().replace("_", "").replace("-", "")
                if key not in _IGNORED_KEYS:
                    visit(child, f"{path}/{name}", key)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{path}/{index}", parent)
        elif isinstance(item, str):
            result.append((parent if parent in _HOST_KEYS | _MESSAGE_KEYS else path, item))

    visit(value)
    return result


def ordinary_validation(exchange):
    """Structured field errors are observed behaviour, not a leak by themselves."""
    if exchange.status not in (400, 422):
        return False
    try:
        body = json.loads(exchange.body)
    except (TypeError, ValueError):
        return False
    return isinstance(body, dict) and isinstance(body.get("errors"), dict) and bool(body["errors"])


def _hostname(value):
    value = value.strip().strip("'\".,;()[]")
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]*", value):
        return value.lower()
    return ""


def _details(exchange):
    # Match the original response, then redact evidence. Redaction must not
    # alter booleans or schema metadata while preparing an observation.
    strings = _strings(exchange.body)
    host = urlsplit(exchange.url).hostname
    hits = []
    for location, value in strings:
        for pattern, label in _STACKS:
            for match in pattern.finditer(value):
                hits.append(("potentially-sensitive", "stack-trace", label, match.group(), value, match.start()))
        for match in _PATH.finditer(value):
            hits.append(("potentially-sensitive", "filesystem-path", "Filesystem path", match.group(), value, match.start()))
        for match in _EXCEPTION.finditer(value):
            hits.append(("limited-implementation-detail", "framework-type", "Framework exception type", match.group(), value, match.start()))
        candidates = []
        if location in _HOST_KEYS:
            candidates += [(value, value, 0)]
        if location in _MESSAGE_KEYS or location == "body":
            for match in re.finditer(r"\bhttps?://([^/\s\"<>]+)[^\s\"<>]*", value, re.I):
                # A general link in an error is often documentation. Require
                # an instance URL or an explicit connection/host context.
                context = value[max(0, match.start() - 70):match.start()]
                if location != "instance" and not re.search(r"(?i)\b(?:backend|upstream|host|connect(?:ion|ing)?|server)\b", context):
                    continue
                try:
                    name = urlsplit(match.group()).hostname or ""
                except ValueError:
                    continue
                # Public documentation links are not implementation evidence.
                if location != "instance" and re.search(r"(?i)(?:docs?|documentation|rfc|ietf|w3\.org|openapis)", match.group()):
                    continue
                candidates.append((name, value, match.start()))
            for match in re.finditer(r"(?i)\b(?:backend|upstream|server|host)(?:\s+(?:host|hostname|name))?\s*[:=]\s*['\"]?([A-Za-z0-9.-]+)", value):
                candidates.append((match[1], value, match.start(1)))
        for name, original, offset in candidates:
            hostname = _hostname(name)
            if hostname and hostname != host:
                hits.append(("limited-implementation-detail", "hostname", "Response hostname", hostname, original, offset))
    for name in _TECH_HEADERS:
        value = exchange.header(name)
        if value and re.search(r"\d+\.\d+", value):
            hits.append(("limited-implementation-detail", "software-banner", "Software version banner", f"{name}: {value}", f"{name}: {value}", 0))
    return hits


def review_captured(exchanges, endpoint, *, evidence_root="/log"):
    """Return a serializable review and informational Finding objects."""
    groups = {}
    validation_refs, edge_refs, incomplete_refs = [], [], []
    for exchange, reference in captured_records(exchanges, evidence_root):
        if exchange.error or not exchange.status:
            incomplete_refs.append(reference)
            continue
        if edge_block_markers(exchange):
            edge_refs.append(reference)
            continue
        if ordinary_validation(exchange):
            validation_refs.append(reference)
        for level, kind, label, value, context, offset in _details(exchange):
            redacted = exchange.safe_text(value)
            key = level, kind, redacted
            if key not in groups:
                excerpt = exchange.safe_text(context[max(0, offset - 80):offset + len(value) + 180])
                groups[key] = {"level": level, "kind": kind, "label": label, "value": redacted,
                               "excerpt": excerpt, "occurrences": [], "exchange": exchange}
            occurrences = groups[key]["occurrences"]
            if not any(item["evidence_ref"] == reference for item in occurrences):
                occurrences.append({"status": exchange.status, "evidence_ref": reference})
    findings = []
    for group in groups.values():
        limited = group["level"] == "limited-implementation-detail"
        count = len(group["occurrences"])
        item = finding(
            "disclosure.implementation-detail" if limited else "disclosure.potentially-sensitive",
            f"{group['label']} appears in captured responses", "info", "confirmed",
            endpoint=endpoint, parameter=f"{group['kind']}:{group['value']}", category="informational",
            origin="runtime-observation", verification="observed",
            method="Read explicit implementation details in captured application responses; no additional request was sent.",
            detail=f"{group['label']}: {group['value']}. Observed in {count} captured response(s).",
            impact=("Limited implementation detail is visible; no exploitable security consequence was demonstrated." if limited else
                    "The response contains diagnostic detail that may be sensitive. Access to files, execution, credential exposure and other security consequences have not been demonstrated."),
            limitations=("A hostname's network location, ownership and reachability are unknown. A framework name or version does not establish a vulnerable deployment. "
                         "The response does not establish which component processed the mutated value or whether the detail is intended for this caller."),
            remediation="Confirm which diagnostics this caller is intended to receive; keep unnecessary implementation details in server-side logs.",
            evidence={"disclosure_level": group["level"], "kind": group["kind"], "signature": group["label"],
                      "value": group["value"], "excerpt": group["excerpt"], "occurrence_count": count,
                      "occurrences": group["occurrences"], "representative_evidence": group["occurrences"][0]["evidence_ref"]},
            exchanges=[group["exchange"]],
        )
        findings.append(item)
    return {
        "observations": [item.to_dict() for item in findings],
        "distinct_observations": len(findings),
        "occurrences": sum(len(item["occurrences"]) for item in groups.values()),
        "ordinary_validation_responses": len(validation_refs), "validation_evidence": validation_refs,
        "edge_responses_excluded": len(edge_refs), "incomplete_tests": len(incomplete_refs),
        "limitations": "Pattern-based review of retained evidence only. Absence of a match does not establish absence of disclosure; truncated bodies are incomplete.",
    }, findings


def review_exchanges(exchanges, endpoint, *, evidence_root="/log"):
    return review_captured(exchanges, endpoint, evidence_root=evidence_root)[0]
