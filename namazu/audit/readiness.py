"""Offline baseline preparation and bounded, reviewable follow-up plans.

Nothing here resolves an identity, constructs an HTTP client, or sends a request.
Imported requests are evidence and templates; credentials remain local references.
"""
from __future__ import annotations

import json
import re
from contextlib import suppress
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlsplit

from .baseline import GENERATED_FILLER, Expectation, check
from .model import (
    CREDENTIAL_QUERY,
    REDACTED_HEADERS,
    redact_body,
    redact_headers,
    redact_url,
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
KINDS = {"entitlement", "cache-isolation", "persona-options"}
REDACTION = re.compile(r"<credential>|<redacted>|\[redacted\]|\[Filtered\]", re.I)
MISSING = object()


def _credential_names(data):
    """Carry explicit credential names through saved preparation and planning."""
    names = set()

    def visit(value):
        if isinstance(value, dict):
            declared = value.get("credential_names", [])
            if not isinstance(declared, list) or any(not isinstance(name, str) for name in declared):
                raise ValueError("Credential names must be a list of names, without credential values.")
            names.update(name.strip().lower() for name in declared if name.strip())
            for key in ("prepared", "configuration", "permission_matrix", "identity_control"):
                if key in value:
                    visit(value[key])
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(data)
    if len(names) > 100 or any(len(name) > 256 for name in names):
        raise ValueError("Provide at most 100 credential names, each at most 256 characters.")
    return sorted(names)


def _sanitise(value, *, credential_names=(), preserve_metadata=False, secret_sources=(), learn_value=True):
    """Redact nested planning configuration before it can be persisted."""
    secrets = set()
    names = {str(name).lower() for name in credential_names}
    # Evidence classifications and structural IDs are not credential values.
    # Short secrets must not rewrite "request-sent", Boolean accounting, JSON
    # property names, or the original checksum while masking imported data.
    metadata = {"classification", "status", "state", "reason_code", "reason_codes", "method",
                "check", "family", "field_pointer", "mutation_id", "hash", "recorded_hash",
                "body_signature", "source_kind", "kind", "metadata_headers", "meaningful_header_names", "redacted_names", "credential_names"}
    def descriptive_metadata(name):
        return name == "signature" or str(name).endswith("_signature")

    def sensitive(name):
        lowered = str(name).lower()
        descriptors = {"token_algorithm", "key_encoding", "secret_encoding", "token_type"}
        return lowered in REDACTED_HEADERS | names or (lowered not in descriptors and CREDENTIAL_QUERY.match(str(name)))

    def credential(name, value, *, body=False):
        if preserve_metadata and body and isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str) or not value or REDACTION.search(value):
            return
        secrets.add(value)
        if str(name).lower() in {"authorization", "proxy-authorization"} and " " in value:
            if token := value.split(" ", 1)[1]:
                secrets.add(token)
        if str(name).lower() in {"cookie", "set-cookie"}:
            for part in value.split(";"):
                key, separator, token = part.strip().partition("=")
                if separator and token and key.lower() not in {"path", "domain", "expires", "max-age", "samesite"}:
                    secrets.add(token)

    def collect(item, *, body=False):
        if isinstance(item, dict):
            if sensitive(item.get("name", "")):
                credential(item.get("name"), item.get("value"))
            for key, child in item.items():
                if sensitive(key) and not (preserve_metadata and not body and (key in metadata or descriptive_metadata(key))):
                    credential(key, child, body=body)
                collect(child, body=body or key in {"body", "request_body", "response_body", "body_excerpt", "headers", "request_headers", "response_headers"})
        elif isinstance(item, list):
            for child in item:
                collect(child, body=body)
        elif isinstance(item, str):
            if item.lstrip().startswith(("{", "[")):
                with suppress(ValueError):
                    collect(json.loads(item), body=body)
            elif re.match(r"^[A-Z]+ \S+(?: HTTP/\d(?:\.\d)?)?\r?\n", item):
                # Parse raw HTTP only to collect values to redact. The dummy
                # scheme resolves relative syntax and is never contacted.
                with suppress(ValueError):
                    collect(_raw_request(item, base_url="http://local.invalid"))
            elif item.startswith(("http://", "https://")):
                with suppress(ValueError):
                    for key, child in parse_qsl(urlsplit(item).query, keep_blank_values=True):
                        if sensitive(key):
                            credential(key, child)
            elif "=" in item:
                for key, child in parse_qsl(item, keep_blank_values=True):
                    if sensitive(key):
                        credential(key, child)

    def clean(item, *, body=False):
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                structural = isinstance(child, str) or (isinstance(child, list) and all(isinstance(value, str) for value in child))
                if preserve_metadata and not body and key in metadata and structural:
                    result[key] = child
                elif sensitive(key) and not (preserve_metadata and not body and descriptive_metadata(key)) and (not preserve_metadata or isinstance(child, str)
                                         or (body and isinstance(child, (int, float, bool)))):
                    result[key] = "<credential>"
                else:
                    result[key] = clean(child, body=body or key in {"body", "request_body", "response_body", "body_excerpt", "headers", "request_headers", "response_headers"})
            return result
        if isinstance(item, list):
            return [clean(child, body=body) for child in item]
        if isinstance(item, str):
            # Response/request bodies and pasted JSON remain structurally
            # valid: redact string values rather than replacing characters in
            # JSON property names, booleans or number tokens.
            if item.lstrip().startswith(("{", "[")):
                with suppress(ValueError):
                    document = json.loads(item)
                    cleaned = clean(document, body=body)
                    return item if cleaned == document else json.dumps(cleaned, ensure_ascii=False)
            text = redact_body(item, names)
            for secret in sorted(secrets, key=len, reverse=True):
                if not secret:
                    continue
                for encoded in {secret, quote(secret, safe=""), quote_plus(secret), json.dumps(secret, ensure_ascii=False)[1:-1]}:
                    if not encoded:
                        continue
                    # Existing placeholders are structural evidence markers,
                    # even when a very short credential shares their letters.
                    pieces = re.split("(" + REDACTION.pattern + ")", text, flags=re.I)
                    text = "".join(piece if index % 2 else piece.replace(encoded, "<credential>")
                                   for index, piece in enumerate(pieces))
            if text.startswith(("http://", "https://")):
                text = redact_url(text, names)
            return text
        return item

    if learn_value:
        collect(value)
    for source in secret_sources:
        collect(source)
    return clean(value)


def _pointer(value, path):
    if not isinstance(path, str) or not path.startswith("/"):
        return MISSING
    for token in path[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            return MISSING
    return value


def _json_body(value):
    return value if isinstance(value, str) or value is None else json.dumps(value, ensure_ascii=False)


def _raw_request(source, *, base_url="") -> dict:
    """Parse locally before redaction so credential echoes can also be removed."""
    if isinstance(source, str):
        if len(source) > 1_048_576:
            raise ValueError("Keep the known-good request below 1 MiB.")
        try:
            source = json.loads(source)
        except ValueError:
            head, _, body = source.replace("\r\n", "\n").partition("\n\n")
            lines = head.splitlines()
            if not lines or not re.fullmatch(r"[A-Z]+ \S+(?: HTTP/\d(?:\.\d)?)?", lines[0]):
                raise ValueError("Paste a JSON request, one HAR entry, or a raw HTTP request.") from None
            method, url, *_ = lines[0].split()
            headers = {}
            for line in lines[1:]:
                name, separator, value = line.partition(":")
                if not separator or not name.strip():
                    raise ValueError("Each raw HTTP header needs a name and value.") from None
                headers[name.strip()] = value.strip()
            if url.startswith("/"):
                if not base_url:
                    raise ValueError("A relative raw HTTP request needs an explicit base URL and scheme.") from None
                parts = urlsplit(base_url)
                url = f"{parts.scheme}://{parts.netloc}{url}"
            source = {"method": method, "url": url, "headers": headers, "body": body or None}
    if not isinstance(source, dict):
        raise ValueError("The known-good request must be an object.")
    if "log" in source:
        entries = source.get("log", {}).get("entries", [])
        if len(entries) != 1:
            raise ValueError("Select exactly one HAR entry; Namazu will not choose an operation for you.")
        source = entries[0]
    if isinstance(source.get("request"), dict):
        source = source["request"]
    headers = source.get("headers", source.get("request_headers", {})) or {}
    if isinstance(headers, list):
        headers = {item["name"]: item.get("value", "") for item in headers if isinstance(item, dict) and "name" in item}
    if not isinstance(headers, dict):
        raise ValueError("Request headers must be an object or HAR header list.")
    url = str(source.get("url") or "")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("Use an absolute HTTP(S) URL without embedded credentials.")
    method = str(source.get("method") or "GET").upper()
    if not re.fullmatch(r"[A-Z]+", method):
        raise ValueError("The request method must contain letters only.")
    body = source.get("body", source.get("request_body"))
    if "postData" in source:
        post_data = source["postData"] or {}
        if post_data.get("params") and "text" not in post_data:
            raise ValueError("This HAR has structured postData without exact text; supply the saved request body.")
        body = post_data.get("text")
    return {"method": method, "url": url, "headers": {str(k): str(v) for k, v in headers.items()},
            "body": _json_body(body) or None}


def parse_request(source, *, base_url="", credential_names=()) -> dict:
    """Accept one JSON request, one HAR entry, or raw HTTP; never execute it."""
    raw = _raw_request(source, base_url=base_url)
    return {**raw, "url": redact_url(raw["url"], credential_names), "headers": redact_headers(raw["headers"], credential_names),
            "body": redact_body(raw["body"], credential_names) or None}


def placeholder_warnings(request: dict) -> list[dict]:
    warnings = []

    def walk(value, path):
        if isinstance(value, dict):
            for name, child in value.items():
                if not CREDENTIAL_QUERY.match(name):
                    walk(child, path + "/" + name.replace("~", "~0").replace("/", "~1"))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, path + "/" + str(index))
        elif isinstance(value, str) and (value.lower() in GENERATED_FILLER or
                re.search(r"(?:^|[/.:_-])(?:example|placeholder|your[-_]?(?:id|document|persona))(?:$|[/.:_-])", value, re.I)):
            warnings.append({"pointer": path, "reason": "likely-example-placeholder",
                             "detail": "This looks like an example value. Confirm it with the API owner; it may be legitimate."})

    with suppress(ValueError):
        walk(json.loads(request.get("body") or "null"), "/body")
    walk(urlsplit(request.get("url", "")).path, "/url/path")
    return warnings


def _assertions(items, *, credential_names=()) -> list[dict]:
    if not isinstance(items, list) or len(items) > 30:
        raise ValueError("Provide at most 30 response assertions.")
    out = []
    for item in items:
        if not isinstance(item, dict) or item.get("purpose") not in {"resource", "content"}:
            raise ValueError("Each assertion names purpose resource or content.")
        if not isinstance(item.get("pointer"), str) or not item["pointer"].startswith("/"):
            raise ValueError("Each assertion needs a response JSON pointer starting with /.")
        if item.get("operator", "equals") not in {"equals", "contains", "absent"}:
            raise ValueError("Assertion operator must be equals, contains, or absent.")
        if item.get("operator", "equals") != "absent" and item.get("expected") in (None, "", [], {}):
            raise ValueError("Resource and content assertions need a meaningful expected value.")
        if REDACTION.search(unquote(json.dumps(item.get("expected")))):
            raise ValueError("A redacted value cannot establish a resource/content assertion; choose a non-secret marker.")
        # Credentials are not acceptable resource markers or exported assertions.
        if any(CREDENTIAL_QUERY.match(part) or part.replace("~1", "/").replace("~0", "~").lower() in credential_names
               for part in item["pointer"].split("/")[1:]):
            raise ValueError("Use a non-secret resource/content marker, not a credential assertion.")
        out.append({"purpose": item["purpose"], "pointer": item["pointer"],
                    "operator": item.get("operator", "equals"), "expected": item.get("expected")})
    return out


def _response(exchange):
    return SimpleNamespace(status=int(exchange.get("status", 0)),
                           body=exchange.get("response_body", exchange.get("body", exchange.get("body_excerpt", ""))) or "",
                           header=lambda name: next((str(v) for k, v in exchange.get("response_headers", exchange.get("headers", {})).items() if k.lower() == name.lower()), ""))


def _check_business(items, response) -> list[dict]:
    try:
        body = json.loads(response.body)
    except (TypeError, ValueError):
        body = None
    results = []
    for item in items:
        value = _pointer(body, item["pointer"])
        operator = item["operator"]
        expected = item.get("expected")
        matched = (value is MISSING if operator == "absent" else
                   value is not MISSING and type(value) is type(expected) and value == expected if operator == "equals" else
                   isinstance(value, str) and isinstance(expected, str) and expected in value)
        results.append({**item, "matched": matched})
    return results


def _identity(value):
    return {"identity a": "primary", "a": "primary", "identity b": "secondary", "b": "secondary"}.get(str(value).lower(), str(value))


def _response_incomplete(exchange):
    if exchange.get("body_truncated") or exchange.get("truncated"):
        return True
    if "response_body" not in exchange and "body" not in exchange:
        with suppress(ValueError, TypeError):
            return int(exchange.get("body_length", 0)) > len(exchange.get("body_excerpt") or "")
    return False


def _safe_exchange(exchange, *, credential_names=()):
    if not exchange:
        return None
    request = parse_request(exchange, credential_names=credential_names)
    response = _response(exchange)
    return {"method": request["method"], "url": request["url"], "request_headers": request["headers"],
            "request_body": request["body"], "status": response.status,
            "response_headers": redact_headers(exchange.get("response_headers", {}), credential_names),
            "response_body": redact_body(response.body, credential_names),
            "error": redact_body(str(exchange.get("error") or ""), credential_names),
            "identity_ref": exchange.get("identity_ref", exchange.get("identity", "")),
            "body_truncated": _response_incomplete(exchange),
            "evidence_pointer": exchange.get("evidence_pointer")}


def prepare(data: dict) -> dict:
    names = _credential_names(data)
    def safe(value):
        return _sanitise({"source": data, "output": value}, credential_names=names, preserve_metadata=True)["output"]
    request = safe(parse_request(data.get("request", {}), base_url=data.get("base_url", ""), credential_names=names))
    reference = str(data.get("identity_ref") or "").strip()
    expectation = Expectation.from_dict(data.get("expectation"))
    assertions = _assertions(safe(data.get("assertions", [])), credential_names=names)
    expectation.business_assertions = assertions
    missing = []

    def add(code, detail):
        missing.append({"code": code, "detail": detail})

    if not reference:
        add("identity-reference-missing", "Assign a local identity reference; credentials are configured separately.")
    if not expectation.status:
        add("expected-status-missing", "Define the expected successful HTTP status.")
    for purpose in ("resource", "content"):
        if not any(item["purpose"] == purpose and item["operator"] != "absent" for item in assertions):
            add(f"{purpose}-assertion-missing", f"Define a positive {purpose} assertion that proves the intended business result.")
    recorded = data.get("recorded_response") or {}
    checks = []
    if not recorded or not recorded.get("status") or recorded.get("error"):
        add("successful-response-missing", "No complete response for this request establishes a successful positive control.")
    else:
        response = _response(recorded)
        if not 200 <= response.status < 300:
            add("positive-http-response-missing", "The recorded response is not a successful 2xx positive control.")
        satisfied, failures = check(expectation, response)
        if not satisfied:
            add("status-or-body-assertion-failed", "; ".join(failures))
        checks = _check_business(assertions, response)
        if any(not item["matched"] for item in checks):
            add("business-assertion-failed", "The recorded response does not satisfy every configured resource/content assertion.")
        if _response_incomplete(recorded):
            add("response-incomplete", "The recorded response body was truncated; retain the complete result for these assertions.")
        identity = recorded.get("identity_ref", recorded.get("identity", ""))
        if not identity or _identity(identity) != _identity(reference):
            add("recorded-identity-mismatch", "The recorded exchange must identify the configured local identity.")
        try:
            recorded_request = safe(parse_request(recorded, credential_names=names))
        except ValueError:
            recorded_request = None
        if not recorded_request or any(recorded_request[key] != request[key] for key in ("method", "url", "body")):
            add("recorded-request-mismatch", "The recorded response must belong to this exact method, URL and request body.")
        # A change in non-credential headers can change representation or behavior.
        if recorded_request and recorded_request["headers"] != request["headers"]:
            add("recorded-headers-mismatch", "The recorded response must use the same request headers (with credentials redacted).")
    if expectation.negative:
        add("expected-denial-is-not-positive-control", "An expected refusal is useful negative evidence and cannot unlock success-dependent tests.")
    if REDACTION.search(request.get("body") or "") or REDACTION.search(unquote(request["url"])):
        add("request-secret-needs-local-substitution", "The URL/body contains redacted values. Restore them locally before an explicitly initiated run.")
    warnings = placeholder_warnings(request)
    operation = str(data.get("operation") or f"{request['method']} {urlsplit(request['url']).path}")
    owner_request = (
        f"Please provide a known-good request for {operation}, a test document/resource and valid persona/options, "
        "and the endpoint role plus report entitlement required by the test identity. "
        "Please supply non-secret response markers for the intended resource and successful result, "
        "a second test identity with its own working resource, and an explicit allow/deny permission matrix "
        "for the same document, cached summaries, and any persona/options boundaries. "
        "Confirm authorised scope, write/replay permissions, rate limits and request budget. "
        "Share credentials through the agreed secure channel; Namazu stores only local identity references in this plan.")
    output = {"version": 1, "operation": operation, "request": request, "identity_ref": reference,
            "expectation": expectation.to_dict(), "assertions": assertions, "assertion_results": checks,
            "recorded_response": _safe_exchange(recorded, credential_names=names) if recorded and recorded.get("url") else None,
            "positive_control": not missing, "missing_prerequisites": missing,
            "warnings": warnings, "owner_request": owner_request, "requests_sent": 0,
            "credential_names": names,
            "configuration": {**safe(data.get("configuration", {})), "credential_names": names},
            "note": "Prepared offline. HTTP success alone does not establish successful summarisation, entitlement boundaries or cache isolation."}
    # Include source credentials only while collecting values to remove their
    # echoes from other evidence. The source itself never leaves this function.
    return safe(output)


def _in_scope(url, scopes):
    def path(value):
        for _ in range(16):
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        else:
            return None
        if "\\" in value or any(piece in {".", ".."} for piece in value.split("/")):
            return None
        return value

    target = urlsplit(url)
    target_path = path(target.path)
    if target_path is None:
        return False
    for scope in scopes:
        root = urlsplit(scope)
        root_path = path(root.path)
        if root_path is None:
            continue
        if ((root.scheme, root.hostname, root.port) == (target.scheme, target.hostname, target.port)
                and (target_path == root_path.rstrip("/") or target_path.startswith(root_path.rstrip("/") + "/"))):
            return True
    return False


def _policy_reasons(request, reference, data):
    reasons = []
    if not _in_scope(request["url"], data.get("scope_urls", [])):
        reasons.append("out-of-scope")
    if request["method"] not in SAFE_METHODS and (data.get("profile") != "writes" or not data.get("allow_mutating")):
        reasons.append("write-permission-required")
    if not reference or _identity(reference) not in {_identity(ref) for ref in data.get("identity_refs", [])}:
        reasons.append("local-identity-not-configured")
    if REDACTION.search(request.get("body") or "") or REDACTION.search(unquote(request["url"])):
        reasons.append("redacted-request-values")
    return reasons


def _single_field_change(before, after, pointer):
    """A constraint retry may change only its named body/query/header input."""
    if before["method"] != after["method"]:
        return False
    if pointer.startswith("/body/"):
        if before["url"] != after["url"] or before["headers"] != after["headers"]:
            return False
        try:
            left, right = json.loads(before["body"] or "null"), json.loads(after["body"] or "null")
        except ValueError:
            return False
        changed = []

        def compare(a, b, path):
            if type(a) is type(b) and a == b:
                return
            if isinstance(a, dict) and isinstance(b, dict):
                for key in set(a) | set(b):
                    compare(a.get(key, MISSING), b.get(key, MISSING), path + "/" + key.replace("~", "~0").replace("/", "~1"))
            else:
                changed.append(path)
        compare(left, right, "/body")
        return bool(changed) and all(path == pointer or path.startswith(pointer + "/") for path in changed)
    if pointer.startswith("/query/"):
        if before["body"] != after["body"] or before["headers"] != after["headers"]:
            return False
        left, right = urlsplit(before["url"]), urlsplit(after["url"])
        if left._replace(query="") != right._replace(query=""):
            return False
        name = pointer[7:].replace("~1", "/").replace("~0", "~")
        if CREDENTIAL_QUERY.match(name):
            return False
        a, b = parse_qsl(left.query, keep_blank_values=True), parse_qsl(right.query, keep_blank_values=True)
        return a != b and [(k, v) for k, v in a if k != name] == [(k, v) for k, v in b if k != name]
    return False


def _same_request_content(before, after):
    def normalise(request):
        body = request["body"]
        with suppress(ValueError, TypeError):
            body = json.loads(body)
        return {**request, "url": urlsplit(request["url"])._replace(fragment="").geturl(),
                "headers": {key.lower(): value for key, value in request["headers"].items()}, "body": body}
    return normalise(before) == normalise(after)


def plan(data: dict) -> dict:
    """Plan requests, including timeout retries; do not reinterpret retries as reproduction."""
    prepared_input = data.get("prepared") or {}
    names = _credential_names(data)
    def safe(value):
        return _sanitise({"source": data, "output": value}, credential_names=names, preserve_metadata=True)["output"]
    prepared = prepare({**prepared_input, "credential_names": names,
                        "recorded_response": data.get("baseline_exchange") or prepared_input.get("recorded_response")})
    limit = max(0, min(int(data.get("budget", 20)), 200))
    rate = max(0.1, min(float(data.get("requests_per_second", 1)), 100))
    cases, remaining, seen = [], limit, {}
    global_missing = list(prepared["missing_prerequisites"])
    identities = data.get("identity_refs", [])
    if len({_identity(ref) for ref in identities}) < 2:
        global_missing.append({"code": "second-identity-missing", "detail": "Configure a distinct second identity and its own successful control."})
    rows = data.get("permission_matrix") or []
    if not rows:
        global_missing.append({"code": "permission-matrix-missing", "detail": "Record explicit expected permissions and resource/content assertions before boundary tests."})

    def add(kind, request, reference, reasons, *, expectation=None, assertions=None, source=None, count=1, detail="", depends_on=None):
        nonlocal remaining
        fingerprint = json.dumps([kind, request, _identity(reference), expectation, assertions], sort_keys=True)
        if fingerprint in seen:
            previous = seen[fingerprint]
            if source is not None and source not in previous["source_evidence_refs"]:
                previous["source_evidence_refs"].append(source)
            return
        reasons = list(dict.fromkeys([*reasons, *_policy_reasons(request, reference, data)]))
        status = "blocked-prerequisite" if reasons else "planned"
        if not reasons and count > remaining:
            status = "budget-exhausted"
            reasons = ["request-budget-exhausted"]
        planned_count = count if status == "planned" else 0
        remaining -= planned_count
        cases.append({"id": f"followup-{len(cases) + 1}", "kind": kind, "request": request,
                      "identity_ref": reference, "status": status, "reason_codes": reasons,
                      "prerequisite": detail, "expected_permission": expectation,
                      "assertions": assertions or [], "source_evidence": source,
                      "source_evidence_refs": [source] if source is not None else [],
                      "planned_request_count": planned_count, "requested_count": count,
                      "depends_on": depends_on or [], "request_sent": False})
        seen[fingerprint] = cases[-1]
        return cases[-1]

    for row in rows:
        if not isinstance(row, dict) or row.get("kind") not in KINDS:
            raise ValueError("Permission rows need kind entitlement, cache-isolation, or persona-options.")
        reference = str(row.get("identity_ref") or "")
        request = safe(parse_request(row.get("request") or prepared["request"], credential_names=names))
        assertions = _assertions(safe(row.get("assertions", [])), credential_names=names)
        reasons = [] if prepared["positive_control"] else ["successful-business-baseline-required"]
        if row.get("expect") not in {"allow", "deny"}:
            reasons.append("explicit-permission-required")
        if not all(any(a["purpose"] == purpose and a["operator"] != "absent" for a in assertions) for purpose in ("resource", "content")):
            reasons.append("resource-and-content-assertions-required")
        if row["kind"] in {"entitlement", "cache-isolation"} and _identity(reference) == _identity(prepared["identity_ref"]):
            reasons.append("distinct-second-identity-required")
        if row["kind"] in {"entitlement", "cache-isolation"} and request != prepared["request"]:
            reasons.append("same-resource-request-required")
        if row["kind"] == "persona-options" and not row.get("boundary_definition"):
            reasons.append("application-boundary-definition-required")
        if row["kind"] == "persona-options" and (not row.get("request") or _same_request_content(request, prepared["request"])):
            reasons.append("explicit-boundary-variation-required")
        if not row.get("identity_control"):
            reasons.append("second-identity-positive-control-required")
        else:
            control = row["identity_control"]
            checked = prepare({**control, "identity_ref": reference, "credential_names": names})
            if not checked["positive_control"]:
                reasons.append("second-identity-positive-control-required")
        # Cache access needs a controlled priming request in the same plan, not
        # an assumption that a historical response populated a cache.
        count = 2 if row["kind"] == "cache-isolation" else 1
        if count == 2:
            reasons.extend(_policy_reasons(prepared["request"], prepared["identity_ref"], data))
        added = add(row["kind"], request, reference, reasons, expectation=row.get("expect"), assertions=assertions,
            count=count, detail="Successful resource/content controls for both identities; explicit expected permission."
            + (" First prime with the baseline identity, then request with this identity; cache use still needs evidence." if count == 2 else ""),
            depends_on=[prepared["identity_ref"]] if count == 2 else [])
        if count == 2 and added:
            added["sequence"] = [{"identity_ref": prepared["identity_ref"], "request": prepared["request"], "purpose": "prime"},
                                 {"identity_ref": reference, "request": request, "purpose": "compare"}]
    for item in data.get("constraints", []):
        if not isinstance(item, dict) or not item.get("field_pointer") or not item.get("mutation"):
            raise ValueError("Constraint cases need field_pointer, mutation, and an explicit request.")
        request = safe(parse_request(item.get("request", {}), credential_names=names))
        reasons = [] if prepared["positive_control"] else ["successful-business-baseline-required"]
        if item.get("expected_handling") not in {"accept", "reject"}:
            reasons.append("declared-constraint-expectation-required")
        if not _single_field_change(prepared["request"], request, item["field_pointer"]):
            reasons.append("single-field-change-required")
        add("constraint", request, prepared["identity_ref"], reasons,
            expectation=item.get("expected_handling"), source=item.get("source_evidence"),
            detail=f"{item['field_pointer']}: {item['mutation']}; handling remains unknown until a response is observed.")
    for item in data.get("incomplete_cases", []):
        if item.get("status") or not item.get("error"):
            continue
        request = safe(parse_request(item, credential_names=names))
        reference = str(item.get("identity_ref", item.get("identity", prepared["identity_ref"])))
        count = max(1, min(int(data.get("replay_attempts", 1)), 5))
        add("incomplete-replay", request, reference, [], source=item.get("evidence_pointer", item.get("sequence")), count=count,
            detail="Explicitly initiate only after reviewing scope and write permissions. A timeout has no response to reproduce; a retry is a new attempt.")
    output = {"version": 1, "mode": "offline-plan", "baseline": prepared,
            "missing_prerequisites": global_missing, "cases": cases,
            "budget": {"limit": limit, "planned": limit - remaining, "remaining": remaining, "requests_per_second": rate},
            "scope_urls": data.get("scope_urls", []), "profile": data.get("profile", "readonly"),
            "allow_mutating": bool(data.get("allow_mutating")), "requests_sent": 0,
            "credential_names": names,
            "configuration": safe({"permission_matrix": rows, "constraints": data.get("constraints", []),
                                   "credential_names": names, "budget": limit, "requests_per_second": rate}),
            "summary": {"cases": len(cases), "planned": sum(c["status"] == "planned" for c in cases),
                        "blocked": sum(c["status"] == "blocked-prerequisite" for c in cases),
                        "budget_exhausted": sum(c["status"] == "budget-exhausted" for c in cases)},
            "limitations": ["This plan sends no requests and establishes no completed coverage.",
                            "Successful summarisation, report entitlement boundaries and cache isolation remain unestablished until their own assertions and controls pass.",
                            "Cross-identity access is judged against the supplied permission matrix, not assumed forbidden."]}
    return safe(output)
