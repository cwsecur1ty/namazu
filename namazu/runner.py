"""One explicit API exchange and response contract validation."""
from __future__ import annotations

from contextlib import nullcontext
import json
import secrets
import time
from urllib.parse import urlencode

import httpx

from .discovery import check_headers, check_url, read_bounded
from .spec import build_request, parse_spec, validate_schema

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def normalize_spec(spec: dict) -> dict:
    # Reparse source, rather than trusting client-supplied derived operations.
    if isinstance(spec.get("document"), dict):
        return parse_spec(spec["document"], source_url=str(spec.get("source_url") or ""))
    return parse_spec(spec)


def prepare_request(spec: dict, operation_id: str, **options) -> dict:
    parsed = normalize_spec(spec)
    return build_request(parsed, operation_id, **options)


def _matching_media(actual: str, content: dict) -> str | None:
    actual = actual.lower().split(";", 1)[0].strip()
    if not actual:
        return None
    for key in content:
        if key.lower() == actual:
            return key
    for key in content:
        normalized = key.lower()
        if normalized != "*/*" and normalized.endswith("/*") and actual.startswith(normalized[:-1]):
            return key
    return next((key for key in content if key == "*/*"), None)


def review_response(spec: dict, operation: dict, status: int, headers: dict, body: str, truncated: bool) -> dict:
    errors, warnings, checks = [], [], []
    responses = operation.get("responses", {})
    response_key = next((key for key in responses if key == str(status)), None)
    if response_key is None:
        response_key = next((key for key in responses if key.upper() == f"{status // 100}XX"), None)
    if response_key is None:
        response_key = next((key for key in responses if key.lower() == "default"), None)
    checks.append({"name": "Documented HTTP status", "valid": response_key is not None})
    if response_key is None:
        errors.append({"path": "$.status", "message": f"HTTP {status} is not documented for this operation"})
        return {"valid": False, "errors": errors, "warnings": warnings, "checks": checks}
    contract = responses[response_key]
    if "$ref" in contract:
        return {"valid": None, "errors": [], "warnings": ["The response definition uses an unresolved reference"], "checks": checks}
    if truncated:
        return {"valid": None, "errors": [], "warnings": ["Response exceeded 2 MiB; captured body was truncated and cannot be fully validated"], "checks": checks}
    if operation["method"] == "HEAD" or status in (204, 304):
        if body:
            errors.append({"path": "$.body", "message": "This HTTP response must not contain a body"})
        return {"valid": not errors, "errors": errors, "warnings": warnings, "checks": checks}
    content = contract.get("content", {})
    if spec["version"] == "2.0" and "schema" in contract:
        produces = operation.get("produces", [])
        content = {media: {"schema": contract["schema"]} for media in produces or ["*/*"]}
    if not isinstance(content, dict):
        return {"valid": None, "errors": [], "warnings": ["The response content definition is malformed"], "checks": checks}
    if not content:
        return {"valid": None, "errors": [], "warnings": ["Status is documented, but no response body schema is provided"], "checks": checks}
    actual_media = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    media_key = _matching_media(actual_media, content)
    checks.append({"name": "Documented Content-Type", "valid": media_key is not None})
    if media_key is None:
        errors.append({"path": "$.headers.content-type", "message": f"Content-Type {actual_media or '(missing)'} does not match {', '.join(content)}"})
        return {"valid": False, "errors": errors, "warnings": warnings, "checks": checks}
    media = content[media_key]
    schema = media.get("schema") if isinstance(media, dict) else None
    value = body
    is_json = actual_media in {"application/json", "text/json"} or actual_media.endswith("+json")
    if is_json:
        try:
            value = json.loads(body, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))
            checks.append({"name": "Valid JSON", "valid": True})
        except (ValueError, RecursionError):
            return {"valid": False, "errors": [{"path": "$.body", "message": "Response is not valid JSON"}], "warnings": [], "checks": checks + [{"name": "Valid JSON", "valid": False}]}
    elif not actual_media.startswith("text/"):
        return {"valid": None, "errors": [], "warnings": ["Body schema validation supports JSON and text responses; this media type is not decoded"], "checks": checks}
    report = validate_schema(value, schema, spec["document"], direction="response")
    checks.append({"name": "Response schema", "valid": report["valid"]})
    return {**report, "checks": checks}


def _form_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return "" if value is None else str(value)


def execute_request(spec: dict, operation_id: str, *, allow_mutating: bool = False,
                    timeout: float = 15, verify_tls: bool = True,
                    client: httpx.Client | None = None, **options) -> dict:
    parsed = normalize_spec(spec)
    built = build_request(parsed, operation_id, **options)
    operation = next(op for op in parsed["operations"] if op["id"] == operation_id)
    if built["method"] not in {"GET", "HEAD", "OPTIONS"} and not allow_mutating:
        raise ValueError("Confirm allow_mutating to send POST, PUT, PATCH, DELETE or other mutating methods")
    check_url(built["url"])
    headers = check_headers(built["headers"])
    payload = {}
    if built["has_body"]:
        media = (built["content_type"] or "application/json").split(";", 1)[0].lower()
        actual_header = next((value for name, value in headers.items() if name.lower() == "content-type"), media)
        if actual_header.split(";", 1)[0].strip().lower() != media:
            raise ValueError("Content-Type header must match the selected request body media type")
        value = built["body"]
        if media in {"application/json", "text/json"} or media.endswith("+json"):
            payload["content"] = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        elif media in ("application/x-www-form-urlencoded", "multipart/form-data"):
            if not isinstance(value, dict):
                raise ValueError("Form request bodies must be JSON objects containing field values")
            fields = [(key, _form_value(item)) for key, val in value.items() for item in (val if isinstance(val, list) else [val])]
            if media == "application/x-www-form-urlencoded":
                payload["content"] = urlencode(fields).encode("utf-8")
            else:
                headers = {key: val for key, val in headers.items() if key.lower() != "content-type"}
                if fields:
                    payload["files"] = [(key, (None, val)) for key, val in fields]
                else:
                    # httpx treats files=[] as no body, losing both the media
                    # type and multipart envelope for an explicit empty object.
                    boundary = secrets.token_hex(16)
                    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                    payload["content"] = f"--{boundary}--\r\n".encode("ascii")
        elif isinstance(value, str):
            payload["content"] = value.encode("utf-8")
        else:
            raise ValueError("Enter a text body for this media type; structured bodies require JSON or form encoding")
    started = time.monotonic()
    context = nullcontext(client) if client is not None else httpx.Client(verify=verify_tls, trust_env=False)
    with context as http:
        request = httpx.Request(built["method"], built["url"], headers=headers, **payload,
                                extensions={"timeout": dict.fromkeys(("connect", "read", "write", "pool"), timeout)})
        response = http.send(request, stream=True, follow_redirects=False, auth=None)
        try:
            data, truncated = read_bounded(response, MAX_RESPONSE_BYTES, deadline=started + timeout)
            status = response.status_code
            response_headers = dict(response.headers)
            encoding = response.encoding or "utf-8"
        finally:
            response.close()
    decoding_warning = ""
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        text = data.decode(encoding, errors="replace")
        decoding_warning = f"Response text encoding is invalid for {encoding}; replacement characters prevent complete schema validation"
    except LookupError:
        text = data.decode("utf-8", errors="replace")
        decoding_warning = "Response declares an unsupported text encoding; captured text cannot be fully validated"
    validation = review_response(parsed, operation, status, response_headers, text, truncated)
    if decoding_warning:
        if validation["valid"] is True:
            validation["valid"] = None
        validation["warnings"].append(decoding_warning)
        validation["checks"].append({"name": "Response text encoding", "valid": None})
    if status in (301, 302, 303, 307, 308):
        validation["warnings"].append("Redirect returned without following it; the request was sent exactly once")
    return {"request": {**built, "headers": dict(request.headers)},
            "response": {"status": status, "headers": response_headers, "body": text,
                         "elapsed_ms": round((time.monotonic() - started) * 1000, 2), "truncated": truncated},
            "validation": validation}
