"""Redact a complete saved audit before presenting it. Strictly offline."""
from __future__ import annotations

import copy
import json

from . import readiness
from .provenance import contract_manifest
from .reporting import exchange_from_record
from .response_compare import comparison_facts, normalize_policy


def credential_names(payload):
    """Reuse names explicitly declared by captured OpenAPI or redaction metadata."""
    names = set()

    def visit(value):
        if isinstance(value, dict):
            if value.get("type") == "apiKey" and value.get("in") in {"header", "query", "cookie"} and isinstance(value.get("name"), str):
                names.add(value["name"].lower())
            for field in ("redacted_names", "credential_names"):
                declared = value.get(field)
                if isinstance(declared, (list, tuple, set)):
                    names.update(name.lower() for name in declared if isinstance(name, str))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    return names


def sanitise_saved_audit(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError("Choose a Namazu audit export with a findings array.")
    original = copy.deepcopy(payload)
    policy = normalize_policy(original.get("response_comparison"))
    baselines = {row.get("endpoint"): exchange_from_record(row.get("exchange") or {})
                 for row in (original.get("coverage") or {}).get("baselines", []) if isinstance(row, dict)}
    # Retain only comparison facts, never credential values or a digest of a
    # secret. A difference hidden by masking remains unknown to later viewers.
    markers = {}

    def exchange_key(record):
        exchange = exchange_from_record(record)
        return json.dumps([exchange.method, exchange.url, exchange.request_headers, exchange.request_body,
                           exchange.status, exchange.headers, exchange.body, exchange.error], sort_keys=True)

    protected = {}
    for probe in (original.get("coverage") or {}).get("probes", []):
        if not isinstance(probe, dict):
            continue
        keys = [part.replace("~1", "/").replace("~0", "~") for part in str(probe.get("field_pointer") or "").split("/") if part]
        for entry in ([probe["exchange"]] if probe.get("exchange") else probe.get("exchanges", [])):
            if isinstance(entry, dict):
                protected.setdefault(exchange_key(entry), set()).update(keys)

    for record in original.get("requests") or []:
        if not isinstance(record, dict) or record.get("label") == "baseline":
            continue
        baseline = baselines.get(record.get("endpoint"))
        if baseline is None:
            continue
        comparison = comparison_facts(exchange_from_record(record), baseline, policy=policy,
                                      protected_keys=protected.get(exchange_key(record), ()))
        previous = record.get("comparison_before_import_redaction") or {}
        if previous.get("equivalent") is False and comparison.get("equivalent") is True:
            markers[exchange_key(record)] = previous
            continue
        record["comparison_before_import_redaction"] = comparison
        markers[exchange_key(record)] = record["comparison_before_import_redaction"]

    def attach(value):
        if isinstance(value, dict):
            if value.get("url") and "status" in value and ("response_body" in value or "response" in value):
                key = exchange_key(value)
                if key in markers:
                    value["comparison_before_import_redaction"] = copy.deepcopy(markers[key])
            for key, child in list(value.items()):
                if key != "comparison_before_import_redaction":
                    attach(child)
        elif isinstance(value, list):
            for child in value:
                attach(child)

    attach(original)
    result = readiness._sanitise(original, credential_names=credential_names(original), preserve_metadata=True)
    result["import_review"] = {"requests_sent": 0, "credentials_masked": True,
                               "contract": contract_manifest(result),
                               "note": "Reviewed locally before display. Original checksum records are retained; masking can change their match. Recorded response differences remain distinct from a same-denial conclusion."}
    return result
