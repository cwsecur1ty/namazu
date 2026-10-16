"""Offline adapter for the JSON reporter shipped by @usebruno/cli 4.2.1.

The reporter records logical executions, not redirect/retry wire counts. It can
omit bodies and headers and does not supply an execution timestamp or version.
Nothing in this module constructs a client or executes collection code.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from .audit.baseline import classify
from .audit.model import CREDENTIAL_QUERY, REDACTED_HEADERS, Exchange

CLI_VERSION = "4.2.1"
MAX_BYTES = 8 * 1024 * 1024
MAX_EXECUTIONS = 2000
ASSERTION_KEYS = ("assertionResults", "testResults", "preRequestTestResults", "postResponseTestResults")
MARKER = "<credential>"
AUTH_CONTAINERS = {"auth", "authentication", "bearer", "basic", "digest", "apikey", "oauth1", "oauth2", "awsv4", "ntlm", "wsse", "akamaiedgegrid"}
AUTH_METADATA = {"mode", "type", "enabled", "inherit", "key", "placement", "granttype", "scope", "region", "service",
                 "callbackurl", "authorizationurl", "accesstokenurl", "refreshtokenurl", "credentialsplacement",
                 "tokenplacement", "tokenheaderprefix", "signaturemethod", "privatekeytype", "version", "realm", "domain", "pkce", "includebodyhash",
                 "header", "reference", "mapping", "variables", "scheme", "clientid", "credentialsid", "tokensource", "tokenquerykey", "autofetchtoken", "autorefreshtoken",
                 "token_endpoint", "endpoint", "client_id", "secret_reference", "credential_placement", "grant"}
AUTH_CONTAINERS.update({"oauth_client_credentials", "authentication_config"})


def bounded(value):
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Provide finite, valid JSON with bounded nesting.") from exc
    if len(raw.encode()) > MAX_BYTES:
        raise ValueError("Bruno imports are limited to 8 MiB. Split the report or select fewer files.")
    def depth(item, level=0):
        if level > 40:
            raise ValueError("Bruno input exceeds 40 nesting levels.")
        if isinstance(item, dict):
            for child in item.values():
                depth(child, level + 1)
        elif isinstance(item, list):
            for child in item:
                depth(child, level + 1)
    depth(value)


def sensitive(name, names=()):
    return str(name).lower() in REDACTED_HEADERS | {"username", "privatekey", "private_key"} | {str(n).lower() for n in names} or bool(CREDENTIAL_QUERY.match(str(name)))


def sanitise(value, names=(), extra_secrets=()):
    """Mask named credentials and their echoes without rewriting numeric counts.

    Also understands Bruno's name/value arrays. Script source is deliberately
    omitted: arbitrary code can contain secrets under unrecognisable names.
    """
    if not isinstance(names, (list, tuple, set)) or len(names) > 100 or any(not isinstance(n, str) or len(n) > 120 for n in names):
        raise ValueError("Credential names must be an array of at most 100 names, each at most 120 characters.")
    names = {str(n).lower() for n in names}
    aliases = set()
    variable_rows = []
    metadata = {
        "method": {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "get", "post", "put", "patch", "delete", "head", "options", "trace"},
        "status": {"pass", "fail", "error", "skipped", "success", "failed", "passed", "imported"},
        "observation": {"not-executed", "timeout/incomplete", "incomplete", "explicit-edge-block", "validation-observation", "application-denial; downstream handling unknown", "response-observed; business success unverified"},
        "classification": {"application-denial", "validation-observation", "explicit-edge-block", "security-lead", "demonstrated-vulnerability"},
        "source_kind": {"bruno-cli-report"}, "outcome": {"pass", "fail", "unknown"},
        "purpose": {"resource", "content"}, "operator": {"equals", "contains", "absent"},
        "mode": {"none", "inherit", "bearer", "basic", "digest", "apikey", "oauth1", "oauth2", "awsv4", "ntlm", "wsse", "akamai-edgegrid"},
        "auth": {"none", "inherit", "bearer", "basic", "digest", "apikey", "oauth1", "oauth2", "awsv4", "ntlm", "wsse", "akamai-edgegrid"},
        "scheme": {"bearer", "basic", "digest", "negotiate", "ntlm", "unresolved"},
        "body_mode": {"none", "json", "text", "xml", "form-urlencoded", "multipart-form", "file", "graphql", "sparql"},
    }
    metadata["authentication_mode"] = metadata["auth"]
    secrets = {str(s) for s in extra_secrets if s}
    def learn(name, val):
        if str(name).lower() == "authentication_mode" and isinstance(val, str) and val in metadata["auth"]:
            return
        if str(name).lower() in AUTH_CONTAINERS:
            if isinstance(val, str) and val in metadata["auth"]:
                return
            if isinstance(val, dict):
                for field, child in val.items():
                    if field.lower() not in AUTH_METADATA:
                        learn(field, child)
                return
        if isinstance(val, (dict, list)):
            for child in val.values() if isinstance(val, dict) else val:
                learn(name, child)
        if isinstance(val, (str, int, float)) and not isinstance(val, bool):
            text = str(val)
            aliases.update(match.strip().lower() for match in re.findall(r"\{\{([^{}]+)\}\}", text)
                           if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", match.strip()))
            if text and text != MARKER and "{{" not in text:
                secrets.add(text)
                if str(name).lower() in {"authorization", "proxy-authorization"} and " " in text:
                    secrets.add(text.split(" ", 1)[1])
                if str(name).lower() in {"cookie", "set-cookie"}:
                    secrets.update(part.partition("=")[2].strip() for part in text.split(";") if "=" in part)
    def collect(item, auth_context=False):
        if isinstance(item, dict):
            if isinstance(item.get("name"), str) and "value" in item:
                variable_rows.append((item["name"].lower(), item["value"]))
            if sensitive(item.get("name", ""), names) or item.get("secret") is True:
                learn(item.get("name", ""), item.get("value"))
            for key, child in item.items():
                if sensitive(key, names) and not (auth_context and key.lower() in AUTH_METADATA):
                    learn(key, child)
                collect(child, auth_context or (key.lower() in AUTH_CONTAINERS and isinstance(child, (dict, list))))
        elif isinstance(item, list):
            for child in item:
                collect(child, auth_context)
        elif isinstance(item, str):
            if item.lstrip().startswith(("{", "[")):
                with contextlib.suppress(ValueError, RecursionError):
                    collect(json.loads(item))
            try:
                if item.startswith(("http://", "https://")):
                    parts = urlsplit(item)
                    if parts.username:
                        learn("username", parts.username)
                    if parts.password:
                        learn("password", parts.password)
                    query = parts.query
                else:
                    query = item
            except ValueError:
                query = ""
            for key, val in parse_qsl(query, keep_blank_values=True):
                if sensitive(key, names):
                    learn(key, val)
            for match in re.finditer(r"(?im)^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([^\r\n]+)", item):
                if sensitive(match[1], names):
                    learn(match[1], match[2])
    collect(value)
    # Credential aliases may have harmless names, and may refer to another
    # static variable. Learn them before serialising any environment/source.
    for _ in range(40):
        previous = set(aliases)
        for name, val in variable_rows:
            if name in aliases:
                learn(name, val)
        if aliases == previous:
            break
    names.update(aliases)
    variants = sorted({v for s in secrets if s for v in (s, quote(s, safe=""), quote_plus(s), json.dumps(s)[1:-1])}, key=len, reverse=True)
    def text(item):
        for secret in variants:
            if len(secret) >= 4:
                item = item.replace(secret, MARKER)
            else:
                item = re.sub(r"(?<!\w)" + re.escape(secret) + r"(?!\w)", lambda _: MARKER, item)
        return item
    def clean(item, key="", preserve_metadata=True):
        if key in {"data", "body", "request_body", "response_body", "body_excerpt", "headers", "request_headers", "response_headers"}:
            preserve_metadata = False
        if isinstance(item, dict):
            out = {}
            for name, child in item.items():
                if preserve_metadata and isinstance(child, str) and ((name == "exchange_id" and re.fullmatch(r"bruno-[0-9a-f]{16}-\d+-\d+", child)) or (name in {"source", "source_id", "source_redacted_hash", "definition_hash", "content_hash"} and re.fullmatch(r"[0-9a-f]{64}", child)) or child in metadata.get(name, ())):
                    out[name] = child
                elif name in {"script", "tests", "docs"} and isinstance(child, (dict, str)):
                    out[name] = "[source omitted; never executed]"
                elif preserve_metadata and ((name.lower() in AUTH_CONTAINERS and isinstance(child, (dict, list))) or
                                             (key.lower() in AUTH_CONTAINERS and name.lower() in AUTH_METADATA)):
                    out[name] = clean(child, name, preserve_metadata)
                elif sensitive(name, names) or (name == "value" and (key.lower() == "apikey" or sensitive(item.get("name", ""), names) or item.get("secret") is True)):
                    out[name] = MARKER
                else:
                    out[name] = clean(child, name, preserve_metadata)
            return out
        if isinstance(item, list):
            return [clean(child, key, preserve_metadata) for child in item]
        if isinstance(item, str):
            if item.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(item)
                    cleaned = clean(parsed, preserve_metadata=preserve_metadata)
                    return item if cleaned == parsed else json.dumps(cleaned, ensure_ascii=False)
                except (ValueError, RecursionError):
                    pass
            if item.startswith(("http://", "https://")):
                try:
                    parts = urlsplit(item)
                    netloc = parts.netloc.rsplit("@", 1)[-1]
                    pairs = [(k, MARKER if sensitive(k, names) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
                    if parts.username or any(sensitive(k, names) for k, _ in pairs):
                        item = urlunsplit((parts.scheme, netloc, parts.path, urlencode(pairs), parts.fragment))
                except ValueError:
                    return "[invalid URL omitted]"
            return text(item)
        return item
    return clean(value)


def _headers(value, reference):
    if value is None:
        return None
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, (str, int, float, list, type(None))) for k, v in value.items()):
        raise ValueError(f"{reference}: headers must be a JSON object or null.")
    # Preserve the original list/null values in bruno.source; the evidence viewer
    # accepts strings. An empty object may mean --reporter-skip-all-headers.
    return {k: v if isinstance(v, str) else json.dumps(v, ensure_ascii=False) for k, v in value.items() if v is not None}


def _body(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _observation(exchange):
    if exchange.error or not exchange.status or exchange.truncated:
        return "timeout/incomplete" if "timeout" in exchange.error.lower() else "incomplete"
    # Reuse the current evidence classifier when available. Older releases have
    # only baseline classification; this adapter remains usable on those trees.
    try:
        from .audit.response_compare import (
            edge_block_markers,
            field_validation_observed,
        )
        if edge_block_markers(exchange):
            return "explicit-edge-block"
        document = json.loads(exchange.body)
        fields = list((document.get("errors") or {}).keys()) if isinstance(document, dict) and isinstance(document.get("errors"), dict) else []
        fields += [document.get("field", "")] if isinstance(document, dict) else []
        if any(field_validation_observed(exchange, field) for field in fields):
            return "validation-observation"
    except ImportError:
        # Same two explicit markers used by Namazu's response classifier.
        # Keep this small compatibility path for installed releases that predate it.
        if re.search(r"<(?:html|iframe|body)\b", exchange.body, re.I) and re.search(r"/_Incapsula_Resource\b", exchange.body, re.I) and re.search(r"Incapsula\s+incident\s+ID\s*:|Request\s+unsuccessful", exchange.body, re.I):
            return "explicit-edge-block"
    except ValueError:
        pass
    verdict = classify(exchange)
    if exchange.status in (401, 403):
        return "application-denial; downstream handling unknown"
    if verdict.outcome == "invalid-data":
        return "validation-observation"
    return "response-observed; business success unverified"


def import_report(report, *, version=CLI_VERSION, credential_names=(), collection_name=None):
    bounded(report)
    if version != CLI_VERSION:
        raise ValueError("Supported reporter version: Bruno CLI 4.2.1. Generate a JSON report with --reporter-json and select that version.")
    if not isinstance(report, list) or not report or any(not isinstance(it, dict) or not isinstance(it.get("results"), list) or type(it.get("iterationIndex")) is not int for it in report):
        raise ValueError("Expected Bruno CLI 4.2.1 JSON: an array of {iterationIndex, results, summary?}. Collection JSON, legacy reports and JUnit are not run reports.")
    if sum(len(it["results"]) for it in report) > MAX_EXECUTIONS:
        raise ValueError("Import at most 2,000 executions per report.")
    source = sanitise(copy.deepcopy(report), credential_names)
    collection_name = sanitise({"source": report, "label": collection_name}, credential_names)["label"]
    source_id = hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    source_redacted_hash = hashlib.sha256(json.dumps(source, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    requests, executions = [], []
    assertion_counts = {key: {"pass": 0, "fail": 0, "unknown": 0} for key in ASSERTION_KEYS}
    unknown_attempts = 0
    warnings = []
    assertion_missing = {key: 0 for key in ASSERTION_KEYS}
    for iteration_pos, iteration in enumerate(report):
        for result_pos, result in enumerate(iteration["results"]):
            ref = f"/{iteration_pos}/results/{result_pos}"
            if not isinstance(result, dict) or not isinstance(result.get("request"), dict) or not isinstance(result.get("response"), dict) or not isinstance(result.get("test"), dict):
                raise ValueError(f"{ref}: expected test, request and response objects from the JSON reporter.")
            req, res = result["request"], result["response"]
            status = res.get("status")
            if status not in (None, "error", "skipped") and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError(f"{ref}/response/status: expected an HTTP status, error, skipped or null.")
            method, url = req.get("method"), req.get("url")
            if method is not None and (not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method)):
                raise ValueError(f"{ref}/request/method: invalid HTTP method.")
            if url is not None and not isinstance(url, str):
                raise ValueError(f"{ref}/request/url: expected a resolved URL string or null.")
            safe = source[iteration_pos]["results"][result_pos]
            eid = f"bruno-{source_id[:16]}-{iteration_pos}-{result_pos}"
            responded = type(status) is int
            skipped = (result.get("skipped") is True or status == "skipped") and not responded
            if result.get("skipped") is True and responded:
                warnings.append(f"{ref}: source says skipped but includes an HTTP response; the response is retained and the skip claim is inconsistent.")
            # Even a resolved URL plus a timeout does not prove dispatch: the
            # reporter may fail during scripts or connection establishment.
            attempt = False if skipped else True if responded else None
            unknown_attempts += int(attempt is None)
            rh = _headers(req.get("headers"), ref + "/request")
            sh = _headers(res.get("headers"), ref + "/response")
            missing = [name for name, present in (("request headers (empty or omitted)", bool(rh)), ("response headers (empty or omitted)", bool(sh)), ("request body (absent or omitted)", "data" in req), ("response body", "data" in res and status not in ("error", "skipped"))) if not present]
            timing = res.get("responseTime")
            if timing is not None and (isinstance(timing, bool) or not isinstance(timing, (int, float)) or timing < 0):
                raise ValueError(f"{ref}/response/responseTime: expected non-negative milliseconds.")
            exchange = Exchange(label=str(safe.get("name") or safe["test"].get("filename") or "Bruno execution"), method=(method or "UNKNOWN").upper(), url=url or "", request_headers=rh or {}, request_body=_body(req["data"]) if "data" in req else None, status=status if responded else 0, headers=sh or {}, body=_body(res["data"]) if "data" in res and responded else "", error=str(result.get("error") or ""), truncated=bool(res.get("truncated") or res.get("bodyTruncated") or (responded and "data" not in res)), identity="unmapped Bruno identity")
            observation = "not-executed" if skipped else _observation(exchange)
            assertions = {}
            for key in ASSERTION_KEYS:
                values = result.get(key)
                assertion_missing[key] += int(values is None)
                if values is not None and (not isinstance(values, list) or any(not isinstance(v, dict) for v in values)):
                    raise ValueError(f"{ref}/{key}: expected an array of assertion/test outcomes.")
                assertions[key] = safe.get(key)
                for item in values or []:
                    outcome = item.get("status") if item.get("status") in ("pass", "fail") else "unknown"
                    assertion_counts[key][outcome] += 1
            row = sanitise({"exchange_id": eid, "label": exchange.label, "endpoint": f"{exchange.method} {exchange.url}", "method": method.upper() if method else None, "url": url, "request_headers": rh, "request_body": exchange.request_body, "status": status if responded else None, "response_headers": sh, "response_body": exchange.body if "data" in res and responded else None, "elapsed_ms": timing if responded else None, "error": exchange.error, "truncated": exchange.truncated, "identity": exchange.identity, "evidence_ref": {"source": source_id, "pointer": ref}, "source_kind": "bruno-cli-report", "observation": observation, "request_sent": attempt, "missing_evidence": missing, "body_representation": "CLI-decoded data; not exact wire bytes"}, credential_names)
            entry = {"id": eid, "iteration": iteration["iterationIndex"], "source_ref": ref, "name": safe.get("name"), "path": safe.get("path"), "filename": safe["test"].get("filename"), "suite": safe.get("suitename"), "folder": str(safe["test"].get("filename") or "").replace("\\", "/").rpartition("/")[0] or None, "status": safe.get("status"), "request_sent": attempt, "response_received": responded, "observation": observation, "assertions": assertions, "missing_evidence": missing}
            executions.append(entry)
            if not skipped:
                requests.append(row)
    responses = sum(row["response_received"] for row in executions)
    imported = datetime.now(timezone.utc).isoformat()
    requests = sanitise({"source": report, "requests": requests}, credential_names)["requests"]
    return {"application": "Namazu", "export": "security-audit", "exported_at": imported, "started_at": None,
            "api": {"title": sanitise(collection_name) if collection_name else "Imported Bruno run"},
            "run": {"status": "imported", "accounting_uncertain": True},
            "provenance": {"kind": "imported-bruno-run", "label": "Imported Bruno run", "imported_at": imported, "requests_sent_during_current_action": 0, "source_run": {"tool_version": CLI_VERSION, "version_basis": "operator-selected; reporter is unversioned", "started_at": None, "status": "historical"}},
            "scope": {"requests_sent": None, "responses_received": responses, "endpoints_audited": None, "endpoints_in_scope": None},
            "findings": [], "requests": requests, "coverage": {"checks": [], "baselines": [], "fields": [], "probes": []},
            "bruno": {"format": "cli-json-4.2.1", "source_id": source_id, "source_hash_basis": "original-canonical-json", "source_redacted_hash": source_redacted_hash,
                      "source_redacted": source != report, "source": source, "collection": collection_name, "executions": executions,
                      "assertion_counts": assertion_counts, "assertion_evidence_missing": assertion_missing,
                      "recorded_iterations": len(report), "iteration_indexes": [row["iterationIndex"] for row in report],
                      "recorded_executions": len(executions), "observed_responses": responses, "dispatch_unknown": unknown_attempts,
                      "recorded_skipped": sum(row["request_sent"] is False for row in executions),
                      "observed_execution_dispatches": sum(row["request_sent"] is True for row in executions),
                      "wire_attempts": None, "warnings": warnings},
            "notes": ["Imported Bruno run. Zero target requests sent during import, viewing or export.", "CLI results are logical executions, not a complete wire-attempt ledger. Redirect/retry counts and execution time are unknown. Repeated iterations remain distinct.", "Bruno assertions are reported separately. Passes, failures and HTTP 2xx are not security findings or successful business baselines.", "No baseline comparisons or field mutations were inferred. Application denials leave downstream handling unknown; omitted data cannot be reconstructed from templates."]}
