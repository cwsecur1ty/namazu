"""Deterministic, single-input contract probes, including denied baselines.

Planning is offline. Only request schemas are read; response schemas never
become inputs. Each request is derived afresh from the saved baseline, and a
response difference is a lead, not evidence of a particular server layer.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote_plus, urlencode, urlsplit, urlunsplit

from ..spec import _parameter_schema, _pointer, _serialise_parameter
from .model import CREDENTIAL_QUERY, REDACTED_HEADERS, redact_body
from .response_compare import compare_responses, safe_comparison, stable_headers
from .transport import SAFE_METHODS, BudgetExhausted, MutationRefused, RateLimited

MAX_STRING_LENGTH = 256
MAX_ARRAY_LENGTH = 20
MAX_SCHEMA_NODES = 4096
MAX_SCHEMA_DEPTH = 16
MAX_CASES = 8192
MAX_NUMBER = 10**12
_MISSING = object()
_OMIT = object()
_ALL_TYPES = frozenset({"string", "number", "integer", "boolean", "object", "array", "null"})


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def _escape(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def _get(value, path):
    for token in path:
        if isinstance(value, dict):
            value = value.get(token, _MISSING)
        elif isinstance(value, list) and isinstance(token, int) and token < len(value):
            value = value[token]
        else:
            return _MISSING
    return value


def _credential_name(name):
    return str(name).lower() in REDACTED_HEADERS or bool(CREDENTIAL_QUERY.match(str(name)))


def _contains_credential(value, names=()):
    if isinstance(value, dict):
        return any(_credential_name(key) or key.lower() in names or _contains_credential(item, names) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_credential(item, names) for item in value)
    return False


@dataclass
class CampaignPlan:
    operation: str
    budget: int
    fields: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    # Private execution material is deliberately excluded from to_dict().
    requests: dict = field(default_factory=dict, repr=False)
    credentials: set = field(default_factory=set, repr=False)
    credential_headers: set = field(default_factory=set, repr=False)
    credential_parameters: set = field(default_factory=set, repr=False)

    def to_dict(self):
        eligible = sum(probe["status"] == "planned" for probe in self.probes)
        return {
            "operation": self.operation, "kind": "endpoint-tests",
            "strategy": "one field at a time against the saved baseline",
            "budget": self.budget, "planned_requests": eligible,
            "budgeted_requests": min(self.budget, eligible),
            "fields": copy.deepcopy(self.fields), "probes": copy.deepcopy(self.probes),
            "notes": list(dict.fromkeys(self.notes)),
            "limits": {"string_length": MAX_STRING_LENGTH, "array_length": MAX_ARRAY_LENGTH,
                       "schema_nodes": MAX_SCHEMA_NODES, "schema_depth": MAX_SCHEMA_DEPTH,
                       "cases": MAX_CASES},
        }


def _facets(schema, document, notes, seen=(), depth=0):
    """Keep composition constraints as separate facets instead of overwriting them."""
    if not isinstance(schema, dict):
        return [{}], []
    if depth > MAX_SCHEMA_DEPTH:
        return [], ["schema-depth-limit"]
    own = {key: value for key, value in schema.items() if key not in ("$ref", "allOf", "oneOf", "anyOf")}
    out, reasons = [own], []
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return out, ["recursive-schema-reference"]
        try:
            target = _pointer(document, ref)
        except (ValueError, TypeError):
            notes.append(f"Unresolved request schema reference: {ref}")
            reasons.append("unresolved-schema-reference")
        else:
            resolved, blocked = _facets(target, document, notes, (*seen, ref), depth + 1)
            out.extend(resolved)
            reasons.extend(blocked)
    for keyword in ("allOf", "oneOf", "anyOf"):
        for branch in schema.get(keyword, []) if isinstance(schema.get(keyword), list) else []:
            resolved, blocked = _facets(branch, document, notes, seen, depth + 1)
            out.extend(resolved)
            reasons.extend(blocked)
    return out, reasons


def _schema_types(schema, document, seen=(), depth=0):
    """Intersection for allOf, union for alternatives; nullable is not contagious."""
    if schema is False:
        return set()
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return set(_ALL_TYPES)
    declared = schema.get("type")
    allowed = set(declared if isinstance(declared, list) else [declared] if declared else _ALL_TYPES)
    if "number" in allowed:
        allowed.add("integer")
    if schema.get("nullable") and declared:
        allowed.add("null")
    ref = schema.get("$ref")
    if ref and ref not in seen:
        with contextlib.suppress(TypeError, ValueError):
            allowed &= _schema_types(_pointer(document, ref), document, (*seen, ref), depth + 1)
    for branch in schema.get("allOf", []) if isinstance(schema.get("allOf"), list) else []:
        allowed &= _schema_types(branch, document, seen, depth + 1)
    for keyword in ("oneOf", "anyOf"):
        if isinstance(schema.get(keyword), list) and schema[keyword]:
            union = set()
            for branch in schema[keyword]:
                union |= _schema_types(branch, document, seen, depth + 1)
            allowed &= union
    return allowed


def _types(facets, value, effective=None):
    if effective is not None and effective != _ALL_TYPES:
        return effective
    kinds = set()
    for schema in facets:
        declared = schema.get("type")
        kinds.update(declared if isinstance(declared, list) else [declared] if declared else [])
        if "properties" in schema:
            kinds.add("object")
        if "items" in schema or "prefixItems" in schema:
            kinds.add("array")
    if not kinds:
        if isinstance(value, bool):
            kinds.add("boolean")
        elif isinstance(value, (int, float)):
            kinds.add("integer" if isinstance(value, int) else "number")
        elif isinstance(value, dict):
            kinds.add("object")
        elif isinstance(value, list):
            kinds.add("array")
        else:
            kinds.add("string")
    if any(schema.get("nullable") for schema in facets):
        kinds.add("null")
    return kinds


def _property_definitions(schema, document, seen=(), depth=0):
    """Retain alternatives when the same property appears in composed branches."""
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return {}
    properties = dict(schema.get("properties") or {})

    def intersect(other):
        for name, child in other.items():
            properties[name] = {"allOf": [properties[name], child]} if name in properties else child

    ref = schema.get("$ref")
    if ref and ref not in seen:
        with contextlib.suppress(TypeError, ValueError):
            intersect(_property_definitions(_pointer(document, ref), document, (*seen, ref), depth + 1))
    for branch in schema.get("allOf", []) if isinstance(schema.get("allOf"), list) else []:
        intersect(_property_definitions(branch, document, seen, depth + 1))
    for keyword in ("anyOf", "oneOf"):
        if isinstance(schema.get(keyword), list) and schema[keyword]:
            alternatives = [_property_definitions(branch, document, seen, depth + 1) for branch in schema[keyword]]
            names = {name for alternative in alternatives for name in alternative}
            intersect({name: {"anyOf": [alternative.get(name, {}) for alternative in alternatives]} for name in names})
    return properties


def _properties(facets, value, schemas, document):
    """Documented properties plus saved keys permitted by additionalProperties."""
    properties = {name: [child] for name, child in _property_definitions({"allOf": schemas}, document).items()}
    if isinstance(value, dict):
        extras = [schema["additionalProperties"] for schema in facets if isinstance(schema.get("additionalProperties"), dict)]
        allows_extras = not any(schema.get("additionalProperties") is False for schema in facets)
        if allows_extras:
            for name in value.keys() - properties.keys():
                properties[name] = extras or [{}]
    return properties


def _cases(facets, value, read_only=False, kinds=None):
    kinds = _types(facets, value) if kinds is None else kinds
    if read_only:
        example = next((schema["example"] for schema in facets if "example" in schema), _MISSING)
        if example is _MISSING:
            example = {} if "object" in kinds else [] if "array" in kinds else True if "boolean" in kinds else 1 if kinds & {"number", "integer"} else "readonly-probe"
        yield "read-only-property-submission", example, ""
        return
    yield "omission", _OMIT, ""
    yield "null-allowed" if "null" in kinds else "null-disallowed", None, ""
    for kind, candidate in [("string", "invalid-type"), ("boolean", True),
                            ("number", 1.25), ("object", {"probe_type": True}), ("array", [1])]:
        if kind not in kinds:
            yield f"wrong-type-{kind}", candidate, ""
    if "boolean" in kinds:
        yield "boolean-false", False, ""
        yield "boolean-true", True, ""
    if kinds & {"number", "integer"}:
        step = 1 if "integer" in kinds and "number" not in kinds else 0.5
        for schema in facets:
            for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
                boundary = schema.get(key)
                if not isinstance(boundary, (int, float)) or isinstance(boundary, bool):
                    continue
                for suffix, candidate in [("below", boundary - step), ("at", boundary), ("above", boundary + step)]:
                    reason = "bounded-number-limit" if not math.isfinite(candidate) or abs(candidate) > MAX_NUMBER else ""
                    yield f"{key}-{suffix}", candidate, reason
            multiple = schema.get("multipleOf")
            if isinstance(multiple, (int, float)) and not isinstance(multiple, bool) and multiple > 0:
                candidate = multiple + (1 if "integer" in kinds and "number" not in kinds and multiple > 1 else multiple / 2)
                yield "multipleOf-off-step", candidate, "bounded-number-limit" if abs(candidate) > MAX_NUMBER else ""
    if "string" in kinds:
        for name, candidate in [("empty-string", ""), ("whitespace", " "),
                                ("unicode", "probe-\u00e9\u6c34"), ("quote-and-delimiters", "'\"<>&\\")]:
            yield name, candidate, ""
        for schema in facets:
            for key in ("minLength", "maxLength"):
                boundary = schema.get(key)
                if isinstance(boundary, int) and not isinstance(boundary, bool) and boundary >= 0:
                    for suffix, size in [("below", max(0, boundary - 1)), ("at", boundary), ("above", boundary + 1)]:
                        yield f"{key}-{suffix}", "x" * min(size, MAX_STRING_LENGTH), "bounded-string-limit" if size > MAX_STRING_LENGTH else ""
            if schema.get("format"):
                yield "format-invalid", "invalid-format", ""
            if isinstance(schema.get("pattern"), str):
                # The pattern is untrusted: do not execute its regex in the scanner.
                yield "pattern-probe", "! pattern probe !", ""
    if "array" in kinds:
        for schema in facets:
            for key in ("minItems", "maxItems"):
                boundary = schema.get(key)
                if isinstance(boundary, int) and not isinstance(boundary, bool) and boundary >= 0:
                    item = value[0] if isinstance(value, list) and value else None
                    for suffix, size in [("below", max(0, boundary - 1)), ("at", boundary), ("above", boundary + 1)]:
                        yield f"{key}-{suffix}", [copy.deepcopy(item) for _ in range(min(size, MAX_ARRAY_LENGTH))], "bounded-array-limit" if size > MAX_ARRAY_LENGTH else ""
            if schema.get("uniqueItems") and isinstance(value, list) and value:
                yield "duplicate-array-item", [copy.deepcopy(value[0]), copy.deepcopy(value[0])], ""
    if "object" in kinds:
        for schema in facets:
            for key in ("minProperties", "maxProperties"):
                boundary = schema.get(key)
                if isinstance(boundary, int) and not isinstance(boundary, bool) and boundary >= 0:
                    for suffix, size in [("below", max(0, boundary - 1)), ("at", boundary), ("above", boundary + 1)]:
                        candidate = dict(list(value.items())[:size]) if isinstance(value, dict) else {}
                        for index in range(max(0, min(size, MAX_ARRAY_LENGTH) - len(candidate))):
                            candidate[f"probe_property_{index}"] = 1
                        yield f"{key}-{suffix}", candidate, "bounded-object-limit" if size > MAX_ARRAY_LENGTH else ""
    for schema in facets:
        if isinstance(schema.get("enum"), list) and schema["enum"]:
            candidate = "outside-enum" if "string" in kinds else False if "boolean" in kinds else -991
            if not any(type(candidate) is type(item) and candidate == item for item in schema["enum"]):
                yield "outside-enum", candidate, ""


def _body_text(built):
    if not built.get("has_body"):
        return None
    value = built.get("body")
    if isinstance(value, dict) and str(built.get("content_type") or "").split(";", 1)[0].lower() == "application/x-www-form-urlencoded":
        return urlencode([(key, _wire_scalar(item)) for key, values in value.items()
                          for item in (values if isinstance(values, list) else [values])])
    return value if isinstance(value, str) else json.dumps(value)


def _wire_scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return _json(value) if isinstance(value, (dict, list)) else str(value)


def _request_key(request):
    material = _json([request["method"], request["url"], sorted((key.lower(), value) for key, value in request["headers"].items()), request["body"]])
    return hashlib.sha256(material.encode()).hexdigest()


def _replace_body(value, path, candidate):
    changed = copy.deepcopy(value)
    if not path:
        return None if candidate is _OMIT else copy.deepcopy(candidate)
    parent = _get(changed, path[:-1])
    leaf = path[-1]
    if not isinstance(parent, (dict, list)) or (isinstance(parent, list) and (not isinstance(leaf, int) or leaf >= len(parent))):
        raise ValueError("saved-baseline-parent-missing")
    if candidate is _OMIT:
        if isinstance(parent, dict):
            parent.pop(leaf, None)
        else:
            del parent[leaf]
    else:
        parent[leaf] = copy.deepcopy(candidate)
    return changed


def _replace_pairs(raw, name, pairs, *, separator="&"):
    """Keep every unrelated serialized query/form/cookie token byte-for-byte."""
    tokens = raw.split(separator) if raw else []
    names = set(name) if isinstance(name, (list, set, tuple)) else {name}
    replacements = [f"{quote(str(key), safe='')}={quote(str(value), safe='')}" for key, value in pairs]
    kept, replaced = [], False
    for token in tokens:
        if unquote_plus(token.strip().split("=", 1)[0]) in names:
            if not replaced:
                kept.extend(replacements)
                replaced = True
        else:
            kept.append(token)
    if not replaced:
        kept.extend(replacements)
    return separator.join(kept)


def _mutate_parameter(request, parameter, candidate, operation):
    location, name = parameter.get("in"), parameter["name"]
    pairs = [] if candidate is _OMIT else _serialise_parameter(parameter, candidate, [])
    # OpenAPI's simple serialization cannot represent a JSON null; the literal
    # is an input probe, not a claim that a typed null reached the application.
    if candidate is None and not parameter.get("content"):
        pairs = [(name, "null")]
    parts = urlsplit(request["url"])
    names = parameter.get("_campaign_keys", [name])
    if location == "query":
        request["url"] = urlunsplit(parts._replace(query=_replace_pairs(parts.query, names, pairs)))
    elif location == "header":
        for key in list(request["headers"]):
            if key.lower() == name.lower():
                del request["headers"][key]
        request["headers"].update(pairs)
    elif location == "cookie":
        key = next((key for key in request["headers"] if key.lower() == "cookie"), "Cookie")
        request["headers"][key] = _replace_pairs(request["headers"].get(key, ""), names, pairs, separator=";")
    elif location == "path":
        if candidate is _OMIT:
            raise ValueError("path-omission-changes-operation")
        template = operation["path"]
        tokens = re.split(r"(\{[^{}]+\})", template)
        captures = [token[1:-1] for token in tokens if token.startswith("{")]
        pattern = "".join("([^/]+)" if token.startswith("{") else re.escape(token) for token in tokens) + "$"
        match = re.search(pattern, parts.path)
        if not match or name not in captures:
            raise ValueError("saved-baseline-path-unmatched")
        start, end = match.span(captures.index(name) + 1)
        request["url"] = urlunsplit(parts._replace(path=parts.path[:start] + pairs[0][1] + parts.path[end:]))
    else:
        raise ValueError("unsupported-parameter-location")


def plan_campaign(parsed, operation, built, *, enabled=True, allow_mutating=False, budget=220, credential_names=()):
    """Produce a complete offline plan without spending an HTTP request.

    ``budget`` is the amount available to this campaign (normally the operation
    allowance less its baseline). Blocked/deduplicated cases stay visible.
    """
    plan = CampaignPlan(operation["id"], max(0, int(budget)))
    plan.credential_headers.update(str(name).lower() for name in credential_names)
    plan.credential_parameters.update((location, str(name).lower()) for name in credential_names
                                      for location in ("header", "query", "cookie", "path", "body"))
    document = parsed.get("document", {})
    original = {"method": built["method"], "url": built["url"], "headers": dict(built.get("headers") or {}),
                "body": _body_text(built), "content_type": built.get("content_type")}
    # Names in security declarations are credential inputs even when their
    # arbitrary names contain none of the usual token/password vocabulary.
    for scheme in (parsed.get("security_schemes") or {}).values():
        if isinstance(scheme, dict) and scheme.get("type") == "apiKey":
            name, location = str(scheme.get("name") or ""), scheme.get("in")
            plan.credential_parameters.add((location, name.lower()))
            if location == "header":
                plan.credential_headers.add(name.lower())
    credential_names = {name for _, name in plan.credential_parameters}
    for name, value in original["headers"].items():
        if _credential_name(name) or name.lower() in plan.credential_headers:
            plan.credentials.add(str(value))
            if name.lower() == "authorization" and " " in str(value):
                plan.credentials.add(str(value).split(" ", 1)[1])
    for name, value in parse_qsl(urlsplit(original["url"]).query, keep_blank_values=True):
        if _credential_name(name) or ("query", name.lower()) in plan.credential_parameters:
            plan.credentials.add(value)
    body_value = built.get("body") if built.get("has_body") else _MISSING
    form_body = str(original["content_type"] or "").split(";", 1)[0].lower() == "application/x-www-form-urlencoded"
    if form_body and original["body"] is not None:
        body_value = {}
        for name, value in parse_qsl(original["body"], keep_blank_values=True):
            if name in body_value:
                if not isinstance(body_value[name], list):
                    body_value[name] = [body_value[name]]
                body_value[name].append(value)
            else:
                body_value[name] = value
    elif isinstance(body_value, str):
        try:
            body_value = json.loads(body_value)
        except ValueError:
            body_value = _MISSING

    def collect_secrets(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (_credential_name(key) or key.lower() in credential_names) and isinstance(item, (str, int, float)):
                    plan.credentials.add(str(item))
                else:
                    collect_secrets(item)
        elif isinstance(value, list):
            for item in value:
                collect_secrets(item)

    collect_secrets(body_value)
    seen = {_request_key(original): "baseline"}
    # Structural JSON equality also suppresses a no-op body with different whitespace.
    if body_value is not _MISSING and not form_body:
        canonical = dict(original, body=_json(body_value))
        seen[_request_key(canonical)] = "baseline"
    nodes = 0

    def add_field(path, schemas, value, *, location="body", parameter=None, parameter_value=_MISSING, reasons=(), inherited_readonly=False):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_SCHEMA_NODES:
            if nodes == MAX_SCHEMA_NODES + 1:
                plan.notes.append("Request schema node limit reached; remaining fields were not planned.")
            return
        facets, schema_reasons = [], []
        for schema in schemas:
            resolved, unresolved = _facets(schema, document, plan.notes)
            facets.extend(resolved)
            schema_reasons.extend(unresolved)
        pointer = "/" + "/".join(_escape(token) for token in path) if path else ""
        if location != "body":
            pointer = f"/{location}{pointer}"
        read_only = inherited_readonly or any(schema.get("readOnly") for schema in facets)
        key = f"{location}:{pointer}"
        effective_types = _schema_types({"allOf": schemas}, document)
        kinds = _types(facets, value, effective_types)
        if form_body and location == "body" and len(path) == 1 and "array" in kinds and isinstance(value, str):
            value = [value]
            body_value[path[0]] = value
        missing = list(reasons) + schema_reasons
        if not enabled:
            missing.append("profile-disallows-input-probes")
        if original["method"] not in SAFE_METHODS and not allow_mutating:
            missing.append("write-permission-required")
        protected = any(_credential_name(token) or token.lower() in credential_names for token in path if isinstance(token, str)) or _contains_credential(value, credential_names)
        if parameter:
            protected = protected or _credential_name(parameter["name"]) or (location, parameter["name"].lower()) in plan.credential_parameters
            if location == "header" and parameter["name"].lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                missing.append("transport-header-preserved")
        if protected:
            missing.append("credential-preserved")
        if location == "body":
            if "json" not in str(original["content_type"] or "").lower() and not form_body:
                missing.append("supported-request-media-required")
            if form_body and (not path or (len(path) > 1 and not isinstance(path[1], int))):
                missing.append("structured-form-encoding-required")
            if body_value is _MISSING:
                missing.append("saved-request-body-required")
            if path and _get(body_value, path[:-1]) is _MISSING:
                missing.append("saved-baseline-parent-missing")
        elif parameter:
            # Exploded structured query/cookie values can overlap other inputs.
            # Do not rebuild those unrelated fields from generated examples.
            style = parameter.get("style", "form" if location in {"query", "cookie"} else "simple")
            if "object" in kinds and (style == "deepObject" or (style == "form" and parameter.get("explode", True))) and "_campaign_keys" not in parameter:
                missing.append("structured-parameter-serialization-required")
        missing = list(dict.fromkeys(missing))
        entry = {"id": key, "operation": operation["id"], "field_pointer": pointer,
                 "location": location, "types": sorted(kinds), "read_only": read_only,
                 "category": "read-only-negative" if read_only else "writable-input",
                 "missing_prerequisites": missing, "probe_ids": []}
        plan.fields.append(entry)
        for mutation, candidate, bound_reason in _cases(facets, value, read_only, kinds):
            if len(plan.probes) >= MAX_CASES:
                plan.notes.append("Campaign case limit reached; remaining mutations were not planned.")
                entry["missing_prerequisites"].append("campaign-case-limit")
                break
            probe_id = f"schema-input-{len(plan.probes) + 1:04d}"
            blocked = [*missing, *([bound_reason] if bound_reason else [])]
            probe = {"id": probe_id, "operation": operation["id"], "field_id": key,
                     "field_pointer": pointer, "location": location, "mutation": mutation,
                     "category": entry["category"],
                     "prerequisite": "saved request, resolved request schema, profile and write permission; baseline response for comparison",
                     "prerequisites": ["saved-request", "resolved-request-schema", "profile-permission", "write-permission", "baseline-response"],
                     "missing_prerequisites": blocked, "planned_requests": 0,
                     "status": "blocked-prerequisite" if blocked else "planned",
                     "reason_code": blocked[0] if blocked else "ready", "request_sent": False}
            entry["probe_ids"].append(probe_id)
            plan.probes.append(probe)
            if blocked:
                continue
            request = copy.deepcopy(original)
            try:
                if location == "body":
                    changed = _replace_body(body_value, path, candidate)
                    if form_body:
                        field_value = changed.get(path[0], _OMIT)
                        pairs = [] if field_value is _OMIT else [(path[0], _wire_scalar(item)) for item in (field_value if isinstance(field_value, list) else [field_value])]
                        request["body"] = _replace_pairs(original["body"], path[0], pairs)
                    else:
                        request["body"] = None if not path and candidate is _OMIT else _json(changed)
                    for header in list(request["headers"]):
                        if header.lower() == "content-length":
                            del request["headers"][header]
                else:
                    changed = _replace_body(parameter_value, path[1:], candidate) if len(path) > 1 else candidate
                    _mutate_parameter(request, parameter, changed, operation)
            except (TypeError, ValueError, OverflowError) as exc:
                probe.update(status="blocked-prerequisite", reason_code=str(exc), missing_prerequisites=[str(exc)])
                continue
            fingerprint = _request_key(request)
            if fingerprint in seen:
                probe.update(status="not-sent", reason_code="unchanged-baseline" if seen[fingerprint] == "baseline" else "duplicate-request", duplicate_of=seen[fingerprint])
                continue
            seen[fingerprint] = probe_id
            probe["planned_requests"] = 1
            plan.requests[probe_id] = request
        if read_only:
            return
        if len(path) >= MAX_SCHEMA_DEPTH:
            entry["missing_prerequisites"].append("schema-depth-limit")
            return
        properties = _properties(facets, value, schemas, document)
        for name, child_schemas in sorted(properties.items()):
            add_field([*path, name], child_schemas, _get(value, [name]), reasons=reasons,
                      location=location, parameter=parameter, parameter_value=parameter_value)
        if "array" in kinds:
            size = len(value) if isinstance(value, list) else 0
            # Empty arrays have no baseline element to mutate. Their item fields
            # remain in the plan as blocked, rather than disappearing.
            for index in range(min(max(size, 1), MAX_ARRAY_LENGTH)):
                children = []
                for schema in facets:
                    prefixes = schema.get("prefixItems") or []
                    children.append(prefixes[index] if index < len(prefixes) else schema.get("items", {}))
                add_field([*path, index], children, _get(value, [index]), reasons=[*reasons, *(["saved-baseline-array-item-missing"] if index >= size else [])],
                          location=location, parameter=parameter, parameter_value=parameter_value)
            if size > MAX_ARRAY_LENGTH:
                entry["missing_prerequisites"].append("baseline-array-item-limit")

    request_body = operation.get("request_body") or {}
    media = request_body.get("content") or {}
    selected = str(built.get("content_type") or "").split(";", 1)[0].lower()
    media_schema = next((item for name, item in media.items() if name.split(";", 1)[0].lower() == selected), None)
    media_reasons = []
    if media_schema is None and media:
        media_schema = next(iter(media.values()))
        media_reasons.append("matching-request-media-schema-required")
        plan.notes.append("Saved request media type is not documented; body probes need a matching JSON request schema.")
    if media_schema and "schema" in media_schema:
        root_schema = media_schema["schema"]
        facets, reasons = _facets(root_schema, document, plan.notes)
        properties = _properties(facets, body_value, [root_schema], document)
        if properties:
            for name, children in sorted(properties.items()):
                add_field([name], children, _get(body_value, [name]), reasons=[*reasons, *media_reasons],
                          inherited_readonly=any(schema.get("readOnly") for schema in facets))
        else:
            add_field([], [root_schema], body_value, reasons=[*reasons, *media_reasons])
    elif request_body:
        add_field([], [{}], body_value, reasons=["resolved-request-schema-required"])
    for parameter in operation.get("parameters") or []:
        location, name = parameter.get("in"), parameter.get("name")
        if not name:
            continue
        parameter = dict(parameter)
        schema = _parameter_schema(parameter)
        kinds = _schema_types(schema, document)
        parameter_reasons = [] if schema is not None else ["resolved-request-schema-required"]
        if location == "query":
            values = parse_qsl(urlsplit(original["url"]).query, keep_blank_values=True)
        elif location == "cookie":
            raw = next((value for key, value in original["headers"].items() if key.lower() == "cookie"), "")
            values = [(unquote_plus(key.strip()), unquote_plus(value.strip())) for key, _, value in (piece.partition("=") for piece in raw.split(";")) if key]
        elif location == "header":
            values = [(name, value) for key, value in original["headers"].items() if key.lower() == name.lower()]
        else:
            values = []
        matches = [value for key, value in values if key == name]
        value = matches if "array" in kinds and matches else matches[0] if matches else _MISSING
        style = parameter.get("style", "form" if location in {"query", "cookie"} else "simple")
        if "object" in kinds and location in {"query", "cookie"} and style == "deepObject":
            object_pairs = [(key, item) for key, item in values if key.startswith(name + "[") and key.endswith("]")]
            value = {key[len(name) + 1:-1]: item for key, item in object_pairs}
            parameter["_campaign_keys"] = [name, *[key for key, _ in object_pairs]]
            if any("[" in key[len(name) + 1:-1] for key, _ in object_pairs):
                parameter_reasons.append("nested-deep-object-serialization-undefined")
        elif "object" in kinds and location in {"query", "cookie"} and style == "form" and parameter.get("explode", True):
            facets, _ = _facets(schema, document, plan.notes)
            property_names = {key for facet in facets for key in (facet.get("properties") or {})}
            other_names = {item.get("name") for item in operation.get("parameters") or [] if item.get("in") == location and item.get("name") != name}
            if property_names & other_names:
                parameter_reasons.append("overlapping-parameter-serialization")
            else:
                parameter["_campaign_keys"] = [name, *sorted(property_names)]
            value = {key: item for key, item in values if key in property_names}
        add_field([name], [schema], value, location=location, parameter=parameter,
                  parameter_value=value, reasons=parameter_reasons)
    # Fair scheduling spends one case per field before returning to its next
    # case. A short request budget remains visible for *every* input field.
    positions = {probe_id: index for item in plan.fields for index, probe_id in enumerate(item["probe_ids"])}
    plan.probes.sort(key=lambda probe: positions[probe["id"]])
    return plan


def _stable_headers(exchange):
    return stable_headers(exchange.headers, exchange.body)


def _field_response(exchange, probe):
    """Conservative evidence: a changed error response explicitly names this input."""
    if exchange.status < 400:
        return False
    token = probe["field_pointer"].rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
    if not token or token.isdigit():
        return False
    # A field mentioned only by a tracing header is not validation evidence.
    # Use explicitly input/error-related metadata, avoiding generic header
    # names such as Content-Length matching a request field named "length".
    header_text = "\n".join(f"{name}: {value}" for name, value in _stable_headers(exchange)
                            if re.search(r"validation|invalid|error|field|parameter|input", name))
    return bool(re.search(r"(?<![\w])" + re.escape(token) + r"(?![\w])",
                          exchange.body + "\n" + header_text, re.IGNORECASE))


def _safe_exchange(exchange, plan):
    """Full bounded wire evidence, with credentials redacted throughout."""
    out = copy.deepcopy(exchange.to_dict())
    names = plan.credential_headers | {name for _, name in plan.credential_parameters}
    out["request_body"] = exchange.safe_text(redact_body(exchange.request_body, names)) if exchange.request_body is not None else None
    out["response_body"] = exchange.safe_text(redact_body(exchange.body, names))
    for container in (out.get("request_headers", {}), out.get("response_headers", {})):
        for key in container:
            if _credential_name(key) or key.lower() in plan.credential_headers:
                container[key] = "<credential>"

    def scrub(value):
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            for credential in sorted(plan.credentials, key=len, reverse=True):
                if credential:
                    value = value.replace(credential, "<credential>").replace(quote(credential, safe=""), "<credential>")
        return value

    return scrub(out)


def execute_campaign(executor, plan, baseline):
    """Send only planned requests through the shared safety/budget executor."""
    result = plan.to_dict()
    sent = 0
    rate_limited = baseline.status == 429
    for probe in result["probes"]:
        if probe["status"] != "planned":
            continue
        if not baseline.ok or not baseline.status:
            probe.update(status="blocked-prerequisite", reason_code="baseline-response-required",
                         missing_prerequisites=["baseline-response-required"])
            continue
        if rate_limited:
            probe.update(status="blocked-prerequisite", reason_code="rate-limit-observed",
                         missing_prerequisites=["rate-limit-observed"])
            continue
        if sent >= plan.budget or executor.budget.remaining <= 0:
            probe.update(status="budget-exhausted", reason_code="request-budget-exhausted")
            continue
        request = plan.requests[probe["id"]]
        try:
            exchange = executor.send(request["method"], request["url"],
                                     label=f"schema-input:{probe['field_id']}:{probe['mutation']}",
                                     headers=request["headers"], body=request["body"],
                                     content_type=request["content_type"], identity=baseline.identity)
        except BudgetExhausted:
            probe.update(status="budget-exhausted", reason_code="request-budget-exhausted")
            continue
        except RateLimited:
            rate_limited = True
            probe.update(status="blocked-prerequisite", reason_code="rate-limit-observed",
                         missing_prerequisites=["rate-limit-observed"])
            continue
        except MutationRefused:
            probe.update(status="blocked-prerequisite", reason_code="write-permission-required",
                         missing_prerequisites=["write-permission-required"])
            continue
        except Exception as exc:
            # A malformed header or URL can fail before transport. It is not a
            # completed probe, and exception text may contain credentials.
            probe.update(status="execution-error", reason_code="request-execution-error", error=type(exc).__name__)
            continue
        sent += 1
        probe.update(request_sent=True, response_status=exchange.status,
                     exchange=_safe_exchange(exchange, plan), status="request-sent")
        field_name = probe["field_pointer"].rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
        comparison = compare_responses(exchange, baseline, protected_keys=(field_name,),
                                       policy=getattr(executor, "comparison_policy", None), field_name=field_name)
        probe["comparison"] = safe_comparison(comparison, exchange, baseline, credentials=plan.credentials)
        if exchange.error:
            probe.update(status="execution-error", reason_code="transport-error",
                         observation="Incomplete test: the request was attempted; no response established input handling.")
        elif not comparison["comparable"]:
            probe.update(reason_code="response-comparison-unavailable",
                         observation="The captured response is incomplete; comparison with the baseline and downstream handling remain unknown.")
        elif comparison["classification"] == "edge-block":
            probe.update(status="edge-block-observed", reason_code="edge-block-page",
                         observation="The HTML response contains explicit Incapsula block-page markers. Downstream application handling is unknown; HTTP 403 alone does not establish an edge block.")
        elif comparison["equivalent"]:
            if baseline.status in {401, 403}:
                probe.update(status="same-denial-as-baseline", reason_code="downstream-handling-unknown",
                             observation="Same denial as baseline; downstream handling unknown. This is not a validation pass or a vulnerability.")
            else:
                probe.update(reason_code="same-response-as-baseline",
                             observation="The response matched the baseline. Field validation was not established.")
        elif comparison["classification"] == "validation-observation":
            probe.update(status="field-specific-response-observed", reason_code="field-validation-observed",
                         observation="The response explicitly rejects the mutated field with a validation error. This is a validation observation, not evidence of a vulnerability; the processing layer and security impact remain unproven.")
            if comparison["meaningful_header_differences"]:
                probe["observation"] += " Meaningful response-header changes are recorded separately and require review."
        elif _field_response(exchange, probe):
            probe.update(status="field-specific-response-observed", reason_code="field-response-difference-lead",
                         observation="A changed error response names the mutated field. This is a lead; the processing layer and security impact are unproven.")
        else:
            probe.update(reason_code="unexpected-error-response-lead" if exchange.status >= 500 else "response-difference-lead",
                         observation="The response differed for this single-field mutation. This is a lead, not a vulnerability or evidence of a particular processing layer.")
        if exchange.status == 429:
            rate_limited = True
    # Scheduling is breadth-first by field, so a tight budget does not spend
    # every request on the first field. Coverage reports all unexecuted cases.
    fields = []
    for item in result["fields"]:
        probes = [probe for probe in result["probes"] if probe["field_id"] == item["id"]]
        counts = Counter(probe["status"] for probe in probes)
        response_classes = Counter(probe["comparison"]["classification"] for probe in probes if "comparison" in probe)
        fields.append({**item, "planned_requests": sum(probe["planned_requests"] for probe in probes),
                       "requests_sent": sum(probe["request_sent"] for probe in probes),
                       "status_counts": dict(counts),
                       "response_classification_counts": dict(response_classes),
                       "metadata_difference_cases": sum(bool(probe.get("comparison", {}).get("metadata_differences")) for probe in probes),
                       "meaningful_header_difference_cases": sum(bool(probe.get("comparison", {}).get("meaningful_header_differences")) for probe in probes),
                       "reason_codes": sorted({probe["reason_code"] for probe in probes}),
                       "missing_prerequisites": sorted(set(item["missing_prerequisites"]) | {reason for probe in probes for reason in probe["missing_prerequisites"]})})
    result["field_coverage"] = fields
    result["request_breakdown"] = {"inventory": 0, "endpoint_tests": sent,
                                   "schema_input_tests": sent, "budget": plan.budget,
                                   "budget_remaining": executor.budget.remaining,
                                   "planned_requests": result["planned_requests"],
                                   "budget_exhausted": sum(probe["status"] == "budget-exhausted" for probe in result["probes"])}
    return result
