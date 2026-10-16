"""Evidence-backed assessment of a saved audit. This module performs no network IO."""
from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from . import contract, passive, readiness
from .model import Exchange
from .provenance import contract_manifest, saved_run_provenance
from .response_compare import (
    compare_responses,
    edge_block_markers,
    field_validation_observed,
    normalize_policy,
)


def exchange_from_record(record: dict) -> Exchange:
    response = record.get("response") or {}
    request = record.get("request") or {}
    body = record.get("response_body", response.get("body", record.get("body_excerpt", "")))
    request_body = record.get("request_body", request.get("body"))
    if request_body is not None and not isinstance(request_body, str):
        request_body = json.dumps(request_body)
    return Exchange(
        label=record.get("label", "captured response"), method=record.get("method", request.get("method", "")),
        url=record.get("url", request.get("url", "")),
        request_headers=record.get("request_headers", request.get("headers", {})),
        request_body=request_body,
        status=record.get("status", response.get("status", 0)) or 0,
        headers=record.get("response_headers", response.get("headers", {})),
        identity=record.get("identity", "unknown"),
        body=body if isinstance(body, str) else json.dumps(body),
        error=record.get("error", response.get("error", "")) or "",
        truncated=bool(record.get("truncated", response.get("truncated")))
        or not ("response_body" in record or "body" in response),
    )


def _demonstrated(item):
    axes = item.get("assessment") or {}
    return (axes.get("category") == "security" and axes.get("origin") == "runtime-observation"
            and axes.get("verification") == "impact-demonstrated")


def _inventory(record):
    return (str(record.get("endpoint", "")).lower() == "surface sweep"
            or str(record.get("label", "")).lower().startswith(("inventory ", "404 calibration")))


def _record_key(record):
    return json.dumps([record.get(name) for name in ("method", "url", "request_body", "status", "response_body",
                      "request_headers", "response_headers", "identity", "label", "error")], sort_keys=True)


def _explicit_validation(exchange):
    try:
        body = json.loads(exchange.body)
    except (ValueError, TypeError):
        return False
    if not isinstance(body, dict):
        return False
    fields = list(body.get("errors", {})) if isinstance(body.get("errors"), dict) else []
    fields += [body.get("field", body.get("parameter", body.get("input", "")))]
    return any(field_validation_observed(exchange, str(name)) for name in fields if name)


_APPLICABILITY_REASONS = {"GET method", "read-only-method", "URL-like input", "query parameter",
                          "pagination input", "object identifier", "numeric seed value", "JWT credential",
                          "URL input; raw newlines in headers or cookies are not permitted"}


def _coverage_prerequisites(payload):
    """Separate receipt-level applicability from actionable setup, without rewriting receipts."""
    coverage = payload.get("coverage") or {}
    missing, excluded, uncertain = set(), [], []
    applicable_reasons, inapplicable_reasons = {}, {}

    def reasons(row):
        return [str(value.get("code") or value.get("detail") or "unspecified prerequisite")
                if isinstance(value, dict) else str(value) for value in row.get("missing_prerequisites") or []]

    def methods(operation):
        match = re.match(r"^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE)\s", str(operation or ""), re.I)
        if match:
            return {match[1].upper()}
        found = set()
        for baseline in coverage.get("baselines") or []:
            if operation and operation not in {baseline.get("endpoint"), baseline.get("operation_id")}:
                continue
            value = baseline.get("exchange") or {}
            method = value.get("method", (value.get("request") or {}).get("method"))
            if method:
                found.add(str(method).upper())
        return found

    def method_excluded(reason, operation):
        actual = methods(operation)
        allowed = {"GET"} if reason == "GET method" else {"GET", "HEAD"}
        return reason in {"GET method", "read-only-method"} and actual and not actual.intersection(allowed)

    def item(row, values, ref, detail):
        return {"operation": row.get("operation", row.get("endpoint")), "family": row.get("family", row.get("check")),
                "check": row.get("check"), "field_pointer": row.get("field_pointer", ""),
                "recorded_prerequisites": values, "recorded_status": row.get("status", row.get("state")),
                "evidence_ref": ref, "detail": detail}

    for index, probe in enumerate(coverage.get("probes") or []):
        values = reasons(probe)
        family = probe.get("family", probe.get("check"))
        not_applicable = probe.get("status") == "not-applicable"
        method_mismatch = any(method_excluded(reason, probe.get("operation")) for reason in values)
        if not_applicable or method_mismatch:
            inapplicable_reasons.setdefault(family, set()).update(values)
            excluded.append(item(probe, values, f"#/coverage/probes/{index}",
                "This probe does not apply to the recorded operation or input. Its recorded prerequisites are retained as evidence, not setup instructions."
                + (" Changing credentials does not make a GET/read-only probe applicable to this method." if method_mismatch else " Different test inputs may change applicability.")))
        else:
            applicable_reasons.setdefault(family, set()).update(values)
            missing.update(values)

    for index, check in enumerate(coverage.get("checks") or []):
        family = check.get("check")
        for reason in reasons(check):
            if reason in applicable_reasons.get(family, set()):
                missing.add(reason)
            elif reason in inapplicable_reasons.get(family, set()):
                continue
            else:
                operations = check.get("blocked_on", check.get("blockedOn")) or [check.get("operation", check.get("endpoint"))]
                states = check.get("states") or {check.get("state"): 1}
                only_inapplicable = bool(states.get("not-applicable")) and not any(value for key, value in states.items() if key != "not-applicable")
                method_mismatch = all(method_excluded(reason, operation) for operation in operations)
                if only_inapplicable or method_mismatch:
                    excluded.append(item(check, [reason], f"#/coverage/checks/{index}",
                        "This recorded requirement concerns probe applicability, not missing identity setup. The original family ledger is unchanged."))
                elif reason in _APPLICABILITY_REASONS:
                    uncertain.append(item(check, [reason], f"#/coverage/checks/{index}",
                        "This older family summary does not identify an applicable probe that needs this input or credential. Inspect its receipt before treating it as missing setup."))
                else:
                    missing.add(reason)
    return missing, excluded, uncertain


def assess_saved_audit(payload: dict) -> dict:
    """Re-derive conclusions from retained evidence, without trusting saved totals."""
    policy = normalize_policy(payload.get("response_comparison"))
    records = payload.get("requests") or []
    baselines = payload.get("coverage", {}).get("baselines") or []
    baseline_map = {row.get("endpoint"): exchange_from_record(row.get("exchange") or {}) for row in baselines}
    counters = {name: Counter() for name in ("total", "endpoint", "inventory")}
    protected = {}
    recorded_differences = set()
    for probe in payload.get("coverage", {}).get("probes", []):
        pointer = probe.get("field_pointer") or ""
        keys = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/") if part]
        for record in ([probe["exchange"]] if probe.get("exchange") else probe.get("exchanges", [])):
            protected.setdefault(_record_key(record), set()).update(keys)
            previous = probe.get("comparison") or {}
            if (probe.get("reason_code") in {"response-difference", "field-specific-response", "field-response-difference-lead"}
                    or probe.get("status") in {"field-response-observed", "field-specific-response-observed"}
                    or (isinstance(previous, dict) and (previous.get("meaningful_header_differences") or previous.get("equivalent") is False))):
                recorded_differences.add(_record_key(record))
    response_cases = []
    header_groups = {}
    for index, record in enumerate(records):
        exchange = exchange_from_record(record)
        baseline = baseline_map.get(record.get("endpoint"))
        kind = "inventory" if _inventory(record) else "endpoint"
        result = "uncompared-response"
        if not exchange.ok or not exchange.status:
            result = "incomplete-test"
        elif edge_block_markers(exchange):
            result = "edge-block"
        elif exchange.truncated:
            result = "incomplete-capture"
        elif record.get("label") == "baseline":
            result = "baseline"
        elif _explicit_validation(exchange):
            result = "validation-observation"
        elif baseline is not None:
            comparison = compare_responses(exchange, baseline, protected_keys=protected.get(_record_key(record), ()),
                                           policy=policy)
            result = comparison["classification"]
            hidden_response = re.search(r"<credential>|<redacted>|\[redacted\]", json.dumps([
                exchange.headers, exchange.body, baseline.headers, baseline.body]), re.I)
            if result in {"same-denial", "same-response"} and _record_key(record) in recorded_differences and (
                    hidden_response or not comparison["metadata_differences"]):
                result = "comparison-discrepancy"
            imported_comparison = record.get("comparison_before_import_redaction") or {}
            original_header_change = set(imported_comparison.get("meaningful_header_names") or []) - set(policy["metadata_headers"])
            original_meaningful_change = imported_comparison.get("body_status_equivalent") is False or original_header_change
            if (result in {"same-denial", "same-response"} and imported_comparison.get("equivalent") is False
                    and hidden_response and original_meaningful_change):
                result = "comparison-discrepancy"
        for counter in (counters["total"], counters[kind]):
            counter["request_attempts"] += 1
            counter["responses_received"] += int(exchange.ok and bool(exchange.status))
            counter[result] += 1
        response_cases.append({"evidence_ref": f"#/requests/{index}", "operation": record.get("endpoint"),
                               "purpose": kind, "status": exchange.status, "classification": result})
        if kind == "endpoint":
            for finding in passive.review_headers(exchange, endpoint=record.get("endpoint", "")):
                item = finding.to_dict()
                key = json.dumps([item.get("id"), item.get("endpoint"), item.get("evidence")], sort_keys=True)
                if key not in header_groups:
                    header_groups[key] = {**item, "occurrence_count": 0, "evidence_refs": []}
                header_groups[key]["occurrence_count"] += 1
                header_groups[key]["evidence_refs"].append(f"#/requests/{index}")

    reviews = contract.review_saved_audit(payload)
    operation_reviews = reviews.get("operations", [])
    original = payload.get("findings") or []
    vulnerabilities = [item for item in original if _demonstrated(item)]
    # A distinct record is scoped to its operation; repeats remain in the source evidence.
    distinct = {(item.get("id"), item.get("endpoint"), item.get("parameter")) for item in vulnerabilities}
    affected = {item.get("endpoint") for item in vulnerabilities if item.get("endpoint")}
    limitations = []
    prerequisites, not_applicable, applicability_unknown = _coverage_prerequisites(payload)
    positive = [row for row in baselines if row.get("positive_control") is True
                and 200 <= (row.get("status") or 0) < 300]
    prepared = (payload.get("readiness") or {}).get("prepared") or {}
    business_controls = []
    baseline_preparation = []
    for row in baselines:
        captured = row.get("exchange") or {}
        try:
            request = readiness.parse_request(captured)
            draft = readiness.prepare({"request": request, "operation": row.get("endpoint"),
                                       "identity_ref": "primary", "recorded_response": captured})
            baseline_preparation.append({"operation": row.get("endpoint"), "warnings": draft["warnings"],
                                         "missing_prerequisites": draft["missing_prerequisites"],
                                         "owner_request": draft["owner_request"]})
        except (ValueError, TypeError, KeyError):
            baseline_preparation.append({"operation": row.get("endpoint"), "warnings": [],
                                         "missing_prerequisites": [{"code": "saved-request-missing", "detail": "Retain the complete baseline request and response before preparing a positive control."}]})
        try:
            verified = readiness.prepare({**prepared, "recorded_response": row.get("exchange")})
            if verified["positive_control"]:
                business_controls.append(row.get("endpoint"))
        except (ValueError, TypeError, KeyError):
            pass
    if len(positive) != len(baselines) or not baselines:
        prerequisites.add("successful-positive-control")
    if len(business_controls) != len(baselines) or not baselines:
        limitations.append("Successful business behaviour, including summarisation where applicable, has not been established for operations without a successful positive control.")
    if payload.get("scope", {}).get("second_identity") is not True:
        prerequisites.add("distinct-second-identity")
    if len(business_controls) != len(baselines) or not baselines:
        prerequisites.add("resource-and-content-assertions")
    identity_controls = ((payload.get("readiness") or {}).get("configuration") or {}).get("permission_matrix") or []
    second_control = False
    for permission in identity_controls:
        try:
            control = readiness.prepare(permission.get("identity_control") or {})
            second_control |= control["positive_control"] and control["identity_ref"] != prepared.get("identity_ref")
        except (ValueError, TypeError, KeyError):
            pass
    if not second_control:
        prerequisites.add("second-identity-positive-control")
    # A prepared plan is not executed evidence. Never claim a tested boundary from configuration.
    limitations.extend([
        "Report entitlement boundaries and cache isolation have not been established by these audit receipts. They require an explicit permission matrix and controlled cross-identity resource/content assertions.",
        "Uniform denials and recognised edge block pages leave downstream input handling unknown. Validation rejections describe observed behaviour; they do not establish a vulnerability or which server layer processed a value.",
    ])
    if not (payload.get("readiness") or {}).get("configuration", {}).get("permission_matrix"):
        prerequisites.add("explicit-permission-matrix")
    if counters["total"]["incomplete-test"]:
        limitations.append(f"{counters['total']['incomplete-test']} request attempts have no completed response. They remain incomplete tests; replay requires a separately reviewed bounded plan.")
    recorded_total = payload.get("scope", {}).get("requests_sent")
    complete_log = not payload.get("requests_truncated") and (recorded_total is None or recorded_total == len(records))
    if not complete_log:
        limitations.append("The retained request log is incomplete. Response counts cover retained evidence only.")
    blocked = [row for row in payload.get("coverage", {}).get("checks", [])
               if row.get("state") == "blocked" or (row.get("states") or {}).get("blocked", 0)]
    return {
        "version": 1, "source": "retained-evidence-only", "target_requests_sent": 0,
        "provenance": saved_run_provenance(payload),
        "response_comparison": policy, "request_accounting": {key: dict(value) for key, value in counters.items()},
        "recorded_request_attempts": recorded_total, "retained_log_complete": complete_log,
        "security": {"demonstrated_vulnerabilities": len(distinct), "affected_operations": len(affected),
                     "evidence_records": len(vulnerabilities),
                     "finding_refs": [f"#/findings/{i}" for i, item in enumerate(original) if _demonstrated(item)],
                     "interpretation": "No exploitable vulnerability was demonstrated." if not distinct
                     else "Only records with demonstrated security impact are included here."},
        "original_observations": [{"title": item.get("title"), "id": item.get("id"),
                                   "endpoint": item.get("endpoint"), "assessment": item.get("assessment"),
                                   "evidence_ref": f"#/findings/{i}"}
                                  for i, item in enumerate(original) if not _demonstrated(item)],
        "operations": operation_reviews, "response_cases": response_cases,
        "header_observations": list(header_groups.values()),
        "blocked_families": {"count": len(blocked), "checks": [row.get("check") for row in blocked],
                             "basis": "Final coverage ledger; earlier generated notes are historical evidence."},
        "coverage_limitations": limitations, "missing_prerequisites": sorted(prerequisites),
        "not_applicable": not_applicable, "applicability_unknown": applicability_unknown,
        "business_controls_established": business_controls,
        "baseline_preparation": baseline_preparation,
        "next_phase": ["Obtain a known-good request with real test document/persona values and the endpoint role plus report entitlement.",
                       "Record the local identity reference, expected status, and meaningful resource/content assertions.",
                       "Obtain a distinct identity and owner-approved permission matrix, including allowed shared resources and cache/persona/options boundaries.",
                       "Review scope, write permission, rate limit and remaining request budget before executing any follow-up or incomplete-case replay."],
    }


def render_html(assessment: dict) -> str:
    """Portable, escaped report with occurrence evidence preserved in adjacent JSON."""
    def esc(value):
        return html.escape(str(value))
    provenance = assessment.get("provenance") or {}
    source = provenance.get("source_run") or {}
    manifest = provenance.get("contract") or {}
    metadata = [("View", "Offline reassessment"), ("Requests sent by this review", 0),
                ("Source target", source.get("target") or "Not recorded"),
                ("Source environment", source.get("environment") or "Not recorded"),
                ("Source run time", source.get("started_at") or "Not recorded"),
                ("Source tool version", source.get("tool_version") or "Not recorded"),
                ("Source run state", source.get("status") or "Unknown"),
                ("Contract snapshot", manifest.get("availability") or "unavailable"),
                ("Response contract SHA-256", manifest.get("hash") or "Not available")]
    chunks = ['<!doctype html><html lang="en"><meta charset="utf-8"><title>Namazu evidence assessment</title>',
              '<h1>Namazu evidence assessment</h1><p>Offline review of retained evidence. No target requests sent.</p>',
              '<dl>' + ''.join(f'<dt>{esc(name)}</dt><dd>{esc(value)}</dd>' for name, value in metadata) + '</dl>',
              '<p>' + esc(manifest.get("limitation") or "Historical contract information is unavailable.") + '</p>',
              f'<h2>Demonstrated vulnerabilities: {assessment["security"]["demonstrated_vulnerabilities"]}</h2>',
              f'<p>{esc(assessment["security"]["interpretation"])}</p>', '<h2>Requests and responses</h2><table>',
              '<tr><th>Purpose</th><th>Attempts</th><th>Responses received</th><th>Same denial</th><th>Validation</th><th>Edge blocks</th><th>Incomplete</th></tr>']
    for purpose, count in assessment["request_accounting"].items():
        chunks.append('<tr>' + ''.join(f'<td>{esc(value)}</td>' for value in [purpose, count.get("request_attempts", 0),
            count.get("responses_received", 0), count.get("same-denial", 0), count.get("validation-observation", 0),
            count.get("edge-block", 0), count.get("incomplete-test", 0)]) + '</tr>')
    chunks.append('</table>')
    for title, values in (("Coverage limitations", assessment["coverage_limitations"]),
                          ("Missing prerequisites", assessment["missing_prerequisites"]),
                          ("Next test phase", assessment["next_phase"])):
        chunks.append(f'<h2>{title}</h2><ul>' + ''.join(f'<li>{esc(value)}</li>' for value in values) + '</ul>')
    for title, key in (("Does not apply to the recorded operation or input", "not_applicable"),
                       ("Applicability needs evidence review", "applicability_unknown")):
        if assessment.get(key):
            chunks.append(f'<h2>{title}</h2><ul>' + ''.join('<li>' + esc(
                f'{row.get("operation") or "Recorded operation"}: {row.get("check")}: '
                f'{", ".join(row["recorded_prerequisites"])}. {row["detail"]} Evidence: {row["evidence_ref"]}')
                + '</li>' for row in assessment[key]) + '</ul>')
    chunks.append(f'<p>{assessment["blocked_families"]["count"]} blocked families in the final coverage ledger.</p>')
    for preparation in assessment.get("baseline_preparation", []):
        chunks.append('<h2>Prepare a successful baseline</h2>')
        for warning in preparation.get("warnings", []):
            chunks.append(f'<p>{esc(warning["pointer"])}: {esc(warning["detail"])}</p>')
        chunks.append('<h3>Request to the API owner</h3><p>' + esc(preparation.get("owner_request", "Complete baseline evidence is missing.")) + '</p>')
    chunks.append('<h2>Observations and operation review</h2><p>Contract disagreements and limited implementation details do not demonstrate security impact. All retained occurrences and evidence references are listed below.</p>')
    for operation in assessment["operations"]:
        review = operation.get("response_review") or {}
        chunks.append(f'<h3>{esc(operation.get("endpoint", "Operation"))}</h3>')
        chunks.append(f'<p>Contract review: {esc(review.get("contract", {}).get("state", "unavailable"))}. '
                      'Recognised edge pages are excluded from application contract attribution.</p>')
        for item in review.get("findings", []):
            count = item.get("evidence", {}).get("occurrence_count", 0)
            chunks.append(f'<h4>{esc(item.get("title"))} ({count} occurrences)</h4><p>{esc(item.get("detail"))}</p>'
                          + f'<p>{esc(item.get("limitations"))}</p>')
        chunks.append(f'<details><summary>{esc(operation.get("endpoint", "Operation"))}</summary><pre>'
                      + esc(json.dumps(operation, indent=2, ensure_ascii=False)) + '</pre></details>')
    chunks.append('<h2>Original observation records</h2><pre>' + esc(json.dumps(assessment["original_observations"], indent=2)) + '</pre>')
    chunks.append('<h2>Contextual header observations</h2><pre>' + esc(json.dumps(assessment["header_observations"], indent=2)) + '</pre>')
    results = assessment.get("field_results") or {}
    chunks.append('<h2>Per-field coverage</h2><p>Cases and request attempts are different units. Executed cases may contain multiple exchanges; errors remain incomplete tests.</p>')
    for operation in results.get("operations", []):
        chunks.append(f'<h3>{esc(operation.get("operation"))}</h3><table><tr><th>Input field</th><th>Category</th><th>Planned</th><th>Executed</th><th>Skipped</th><th>Same denial</th><th>Validation</th><th>Edge block</th><th>Incomplete</th></tr>')
        for field in operation.get("fields", []):
            counts = field.get("summary") or {}
            chunks.append('<tr>' + ''.join(f'<td>{esc(value)}</td>' for value in [field.get("pointer"), field.get("category"),
                counts.get("plannedCases", 0), counts.get("executedCases", 0), counts.get("skippedCases", 0),
                counts.get("sameDenialCases", 0), counts.get("validationObservationCases", 0),
                counts.get("edgeBlockCases", 0), counts.get("errorCases", 0)]) + '</tr>')
        chunks.append('</table>')
    if not results:
        chunks.append('<p>Per-field derivation unavailable; install Node to use the same model as the UI. No coverage is inferred from request totals.</p>')
    links = ''.join(f'<li><a href="#request-{index}">Request / response {index + 1}</a>: '
                    + esc(row["classification"]) + f' (HTTP {row["status"] or "no response"})</li>'
                    for index, row in enumerate(assessment["response_cases"]))
    chunks.append('<h2>Response accounting evidence</h2><ul>' + links + '</ul></html>')
    if assessment.get("requests"):
        chunks.insert(-1, '<h2>Retained request and response evidence</h2><p>Original comparison values with credentials redacted. Evidence references /requests/N use zero-based indices.</p>')
        for index, record in enumerate(assessment["requests"]):
            chunks.insert(-1, f'<details id="request-{index}"><summary>Request / response {index + 1}: '
                          + f'{esc(record.get("label", ""))}</summary><pre>'
                          + esc(json.dumps(record, indent=2, ensure_ascii=False)) + '</pre></details>')
    return '\n'.join(chunks)


def portable_evidence(assessment, source):
    """Keep source evidence pointers resolvable while masking captured credentials."""
    captures = [exchange_from_record(row) for row in source.get("requests", [])]
    cache = {}

    def safe(value):
        if isinstance(value, dict):
            if "request_headers" in value and "response_body" in value and "url" in value:
                value = {**value, **exchange_from_record(value).to_dict()}
            return {key: safe(item) for key, item in value.items()}
        if isinstance(value, list):
            return [safe(item) for item in value]
        if not isinstance(value, str):
            return value
        if value not in cache:
            text = value
            for exchange in captures:
                text = exchange.safe_text(text, redact_properties=False)
            cache[value] = text
        return cache[value]

    coverage = {key: value for key, value in source.get("coverage", {}).items() if key != "results"}
    if assessment.get("field_results"):
        coverage["results"] = assessment["field_results"]
    result = safe({**assessment, "requests": source.get("requests", []), "findings": source.get("findings", []),
                   "coverage": coverage, "test_plans": source.get("test_plans", []),
                   "contract_snapshots": source.get("contract_snapshots", {}),
                   "api": source.get("api", {}), "started_at": source.get("started_at"),
                   "tool_version": source.get("tool_version"), "run": source.get("run", {})})
    if result.get("provenance"):
        result["provenance"]["contract"] = contract_manifest(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.export.read_text(encoding="utf-8-sig"))
    assessment = assess_saved_audit(source)
    assessment["source_export"] = args.export.name
    node = shutil.which("node")
    if node:
        module = Path(__file__).resolve().parent.parent / "static" / "audit-results.js"
        script = "const model=require(process.argv[1]); const data=JSON.parse(require('fs').readFileSync(0,'utf8')); process.stdout.write(JSON.stringify(model.exportResults(data)));"
        result = subprocess.run([node, "-e", script, str(module)], input=json.dumps(source), text=True,
                                capture_output=True, check=True, timeout=30)
        assessment["field_results"] = json.loads(result.stdout)
    assessment = portable_evidence(assessment, source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix(".json").write_text(json.dumps(assessment, indent=2, ensure_ascii=False), encoding="utf-8")
    args.output.with_suffix(".html").write_text(render_html(assessment), encoding="utf-8")


if __name__ == "__main__":
    main()
