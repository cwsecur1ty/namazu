"""Conservative comparison for recorded responses, without changing evidence.

Only explicitly named transport metadata is volatile. Resource identifiers,
hashes, numbers, nested domain timestamps and text remain meaningful. The
results UI applies the same policy to exported exchanges.
"""
from __future__ import annotations

import copy
import json
import re
from urllib.parse import quote, quote_plus

VOLATILE_BODY_KEYS = frozenset({
    "timestamp", "requesttimestamp", "responsetimestamp", "requestid",
    "correlationid", "traceid", "spanid",
})
METADATA_ENVELOPES = frozenset({"meta", "metadata", "context"})
VOLATILE_RESPONSE_HEADERS = frozenset({
    "date", "request-id", "x-request-id", "correlation-id", "x-correlation-id",
    "trace-id", "x-trace-id", "span-id", "x-span-id", "traceparent", "tracestate",
    "x-amzn-trace-id", "x-cloud-trace-context", "cf-ray", "x-b3-traceid", "x-b3-spanid",
    "fm-correlation-id", "x-iinfo",
})
METADATA_HEADER_CATALOG = {
    name: ("transport" if name == "date" else "diagnostic" if name == "x-iinfo" else "correlation")
    for name in sorted(VOLATILE_RESPONSE_HEADERS)
}


def metadata_header_catalog():
    """The exact supported names; security headers cannot be added by pattern."""
    return dict(METADATA_HEADER_CATALOG)


def normalize_policy(policy=None):
    """Resolve a configurable subset of the explicit metadata-header catalog.

    An empty list opts into strict header comparison. Arbitrary names and
    wildcards are rejected, including names with security or validation meaning.
    """
    if policy is None:
        return {"metadata_headers": sorted(VOLATILE_RESPONSE_HEADERS)}
    if not isinstance(policy, dict) or set(policy) - {"metadata_headers"}:
        raise ValueError("Response comparison requires only a metadata_headers list.")
    names = policy.get("metadata_headers", sorted(VOLATILE_RESPONSE_HEADERS))
    if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
        raise ValueError("Response comparison metadata_headers must be a list of exact supported names.")
    normalized = {name.strip().lower() for name in names}
    unsupported = normalized - VOLATILE_RESPONSE_HEADERS
    if unsupported:
        raise ValueError("Unsupported response comparison metadata header: " + ", ".join(sorted(unsupported)))
    return {"metadata_headers": sorted(normalized)}


class _Number(str):
    """Retain a JSON number's exact representation, including large integers."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON properties require raw comparison")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


def _key(name):
    return name.lower().replace("-", "").replace("_", "")


def _canonical(value, path=(), protected_keys=()):
    if isinstance(value, dict):
        metadata = not path or (len(path) == 1 and isinstance(path[0], str) and _key(path[0]) in METADATA_ENVELOPES)
        return ("object", tuple(
            (key, _canonical(item, (*path, key), protected_keys))
            for key, item in sorted(value.items())
            if not (metadata and _key(key) in VOLATILE_BODY_KEYS and _key(key) not in protected_keys
                    and isinstance(item, str))
        ))
    if isinstance(value, list):
        return ("array", tuple(_canonical(item, (*path, index), protected_keys) for index, item in enumerate(value)))
    if isinstance(value, _Number):
        return ("number", str(value))
    if isinstance(value, bool):
        return ("boolean", value)
    if value is None:
        return ("null",)
    return ("string", value)


def canonical_body(body: str, protected_keys=()):
    """Use full JSON structure, or exact text when JSON cannot be interpreted."""
    try:
        parsed = json.loads(body, object_pairs_hook=_object, parse_int=_Number,
                            parse_float=_Number, parse_constant=_invalid_constant)
        return ("json", _canonical(parsed, protected_keys={_key(key) for key in protected_keys}))
    except (TypeError, ValueError, RecursionError):
        return ("text", body)


def stable_headers(headers: dict, body: str = "", policy=None) -> tuple:
    """Exclude only named tracing/timestamp metadata and verified body length.

    Content-Length is derivable only when it matches the complete UTF-8 body;
    otherwise it is kept. Rate-limit, cookie and validation headers are kept.
    """
    metadata = set(normalize_policy(policy)["metadata_headers"])
    stable = []
    for name, value in headers.items():
        key = name.lower()
        text = str(value).strip()
        if key in metadata:
            continue
        if key == "content-length" and text.isascii() and text.isdigit() and int(text) == len(body.encode("utf-8", "replace")):
            continue
        stable.append((key, text))
    return tuple(sorted(stable))


def response_key(exchange, protected_keys=(), policy=None):
    """Return comparable captured evidence, or None when it is incomplete."""
    if exchange.error or not exchange.status or exchange.truncated or not isinstance(exchange.body, str):
        return None
    return exchange.status, canonical_body(exchange.body, protected_keys), stable_headers(exchange.headers, exchange.body, policy)


def equivalent(left, right, protected_keys=(), policy=None) -> bool | None:
    """None means that the captured evidence cannot establish equivalence."""
    a, b = response_key(left, protected_keys, policy), response_key(right, protected_keys, policy)
    return None if a is None or b is None else a == b


def edge_block_markers(exchange):
    """Recognise an explicit branded block page, never a status code alone."""
    body = getattr(exchange, "body", "") or ""
    if not isinstance(body, str) or not re.search(r"<(?:html|iframe|body)\b", body, re.I):
        return []
    markers = []
    if re.search(r"/_Incapsula_Resource\b", body, re.I):
        markers.append("/_Incapsula_Resource")
    if re.search(r"Incapsula\s+incident\s+ID\s*:", body, re.I):
        markers.append("Incapsula incident ID")
    elif re.search(r"Request\s+unsuccessful", body, re.I):
        markers.append("Request unsuccessful")
    return markers if len(markers) == 2 else []


def field_validation_observed(exchange, field_name):
    """An explicit field validation rejection is an observation, not a lead.

    HTTP 400/422 alone, field echoes, and generic denials are insufficient.
    The response must associate the input with a structured validation error
    or a named field plus a constraint/validation message.
    """
    if exchange.status not in (400, 422) or not field_name or str(field_name).isdigit():
        return False
    token = str(field_name)
    def contains(value):
        return isinstance(value, str) and bool(re.search(
            r"(?<![\w])" + re.escape(token) + r"(?![\w])", value, re.I))
    try:
        parsed = json.loads(exchange.body)
    except (TypeError, ValueError):
        return False
    if not isinstance(parsed, dict):
        return False
    errors = parsed.get("errors")
    if isinstance(errors, dict) and any(contains(key) and isinstance(value, (str, list, dict)) and bool(value)
                                       for key, value in errors.items()):
        return True
    field = parsed.get("field", parsed.get("parameter", parsed.get("input")))
    detail = " ".join(str(parsed.get(key, "")) for key in ("detail", "message", "error", "title"))
    return bool(contains(field) and re.search(
        r"\b(?:validat\w*|invalid|required|must|expected|minimum|maximum|too (?:long|short)|not allowed)\b", detail, re.I))


def _header_differences(left, right, names):
    a = {str(name).lower(): str(value).strip() for name, value in left.headers.items()}
    b = {str(name).lower(): str(value).strip() for name, value in right.headers.items()}
    return [{"name": name, "left": a.get(name), "right": b.get(name)}
            for name in sorted(names) if a.get(name) != b.get(name)]


def compare_responses(left, right, protected_keys=(), policy=None, field_name=""):
    """Compare a candidate (left) with its baseline (right), retaining differences.

    Application equivalence includes status, body and every meaningful header.
    Transport/correlation/diagnostic differences are reported separately and
    the original exchanges are never modified. Incomplete evidence is unknown.
    """
    effective = normalize_policy(policy)
    a, b = response_key(left, protected_keys, effective), response_key(right, protected_keys, effective)
    metadata_names = set(effective["metadata_headers"])
    stable_names = {name for name, _ in stable_headers(left.headers, left.body, effective)}
    stable_names.update(name for name, _ in stable_headers(right.headers, right.body, effective))
    markers = edge_block_markers(left)
    result = {
        "comparable": a is not None and b is not None,
        "equivalent": None if a is None or b is None else a == b,
        "body_status_equivalent": None if a is None or b is None else a[:2] == b[:2],
        "metadata_differences": _header_differences(left, right, metadata_names),
        "meaningful_header_differences": _header_differences(left, right, stable_names),
        "edge_block_markers": markers, "classification": "unknown",
    }
    if not result["comparable"]:
        return result
    if markers:
        result["classification"] = "edge-block"
    elif result["equivalent"]:
        result["classification"] = "same-denial" if right.status in (401, 403) else "same-response"
    elif field_validation_observed(left, field_name):
        result["classification"] = "validation-observation"
    else:
        result["classification"] = "different"
    return result


def safe_comparison(comparison, *exchanges, credentials=()):
    """Redact credentials echoed into comparison metadata before saving a receipt."""
    result = copy.deepcopy(comparison)
    for category in ("metadata_differences", "meaningful_header_differences"):
        for difference in result.get(category, []):
            for side in ("left", "right"):
                value = difference.get(side)
                if not isinstance(value, str):
                    continue
                for exchange in exchanges:
                    value = exchange.safe_text(value, redact_properties=False)
                for credential in sorted(credentials, key=len, reverse=True):
                    if credential:
                        for encoded in {credential, quote(credential, safe=""), quote_plus(credential),
                                        json.dumps(credential, ensure_ascii=False)[1:-1]}:
                            value = value.replace(encoded, "<credential>")
                difference[side] = value
    return result


def comparison_facts(exchange, baseline, *, policy=None, protected_keys=()):
    """Non-secret comparison facts retained when evidence values are masked."""
    comparison = compare_responses(exchange, baseline, policy=policy, protected_keys=protected_keys)
    return {"classification": comparison["classification"], "equivalent": comparison["equivalent"],
            "body_status_equivalent": comparison["body_status_equivalent"],
            "meaningful_header_names": [item["name"] for item in comparison["meaningful_header_differences"]]}
