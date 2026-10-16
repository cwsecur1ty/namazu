"""Parse/serialize Bruno definitions with the pinned official parser, offline."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from .bruno import MARKER, bounded, sanitise, sensitive
from .runner import normalize_spec

METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"})
PARSER_VERSION = "0.40.0"
FILESTORE_VERSION = "0.13.0"
MAX_COLLECTION_FILES = 2200
VARIABLE = re.compile(r"\{\{([^{}]+)\}\}")
BRIDGE = Path(__file__).parent / "bruno_node" / "bridge.cjs"


def parser(action, items, *, cancel_event=None):
    node = shutil.which("node")
    if not node:
        raise ValueError("Bruno definitions require Node.js 20 or newer on the Namazu server. JSON run reports do not require Node.")
    try:
        with subprocess.Popen([node, "--max-old-space-size=192", str(BRIDGE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) as process:
            payload = json.dumps({"action": action, "items": items})
            deadline = time.monotonic() + 15
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    process.kill()
                    process.communicate()
                    raise ValueError("Bruno parsing cancelled.")
                if time.monotonic() >= deadline:
                    process.kill()
                    process.communicate()
                    raise subprocess.TimeoutExpired("Bruno parser", 15)
                try:
                    stdout, _stderr = process.communicate(input=payload, timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    payload = None
            output = json.loads(stdout)
            returncode = process.returncode
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        if cancel_event is not None and cancel_event.is_set():
            raise ValueError("Bruno parsing cancelled.") from None
        raise ValueError("Bruno parser could not complete within its limits. Check Node.js and reduce the selected files.") from exc
    if returncode or output.get("error"):
        raise ValueError(output.get("error") or "Bruno syntax was rejected by parser 0.40.0.")
    return output["result"]


def file_map(files):
    bounded(files)
    if not isinstance(files, list) or not files or len(files) > MAX_COLLECTION_FILES:
        raise ValueError("Select 1–2200 Bruno definition and metadata files per collection.")
    out = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            raise ValueError("Each uploaded file needs path and UTF-8 content strings.")
        name = item["path"]
        path = PurePosixPath(name)
        if not name or "\\" in name or ":" in name or "\x00" in name or path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")) or len(name) > 240:
            raise ValueError("Use relative collection paths without traversal, drive letters or empty segments.")
        if name.casefold() in {key.casefold() for key in out}:
            raise ValueError("Duplicate file paths are not supported (including case-only duplicates).")
        if not (name.endswith((".bru", ".yml", ".yaml")) or path.name == "bruno.json"):
            raise ValueError("Only Bruno BRU/YAML definitions and bruno.json are accepted; referenced files are never read.")
        if len(item["content"].encode()) > 256 * 1024:
            raise ValueError("Each Bruno definition is limited to 256 KiB.")
        out[name] = item["content"]
    # Folder uploads include one outer directory; remove exactly the bruno.json root.
    roots = [str(PurePosixPath(name).parent) for name in out if PurePosixPath(name).name in {"bruno.json", "opencollection.yml", "opencollection.yaml"}]
    if len(roots) > 1:
        raise ValueError("Select exactly one collection root.")
    if roots and roots[0] != ".":
        prefix = roots[0] + "/"
        if any(not name.startswith(prefix) for name in out):
            raise ValueError("All selected files must belong to the same collection root.")
        out = {name[len(prefix):]: content for name, content in out.items()}
    return out


def _vars(value):
    # A missing higher-precedence secret must shadow a lower static value.
    return {row["name"]: None if row.get("secret") else row.get("value", "") for row in value or [] if row.get("enabled", True)}


def _redacted_values(original, cleaned):
    """Learn source secrets once instead of rescanning every definition per row."""
    if cleaned == MARKER and isinstance(original, str):
        yield original
        if original.lower().startswith(("bearer ", "basic ")):
            yield original.split(" ", 1)[1]
    elif isinstance(original, dict) and isinstance(cleaned, dict):
        for key in original.keys() & cleaned.keys():
            yield from _redacted_values(original[key], cleaned[key])
    elif isinstance(original, list) and isinstance(cleaned, list):
        for raw, safe in zip(original, cleaned, strict=False):
            yield from _redacted_values(raw, safe)


def _oauth_mapping(auth, resolve):
    if auth.get("mode") != "oauth2":
        return None
    value = auth.get("oauth2") or {}
    if (value.get("grantType") != "client_credentials" or value.get("credentialsPlacement", "body") not in {"body", "header"}
            or value.get("tokenPlacement", "header") != "header" or value.get("tokenHeaderPrefix", "") not in {"", "Bearer", "bearer"}
            or value.get("tokenSource", "access_token") != "access_token"
            or any(value.get(key) for key in ("additionalParameters", "accessTokenAdditionalParameters", "refreshTokenAdditionalParameters"))):
        return None
    result = {"grant": "client_credentials", "endpoint": resolve(value.get("accessTokenUrl", "")),
              "client_id": resolve(value.get("clientId", "")), "scope": resolve(value.get("scope", "")),
              "credential_placement": "basic" if value.get("credentialsPlacement", "body") == "header" else "post",
              "secret_reference": ", ".join(VARIABLE.findall(value.get("clientSecret") or "")) or "local client secret required"}
    try:
        parts = urlsplit(result["endpoint"])
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            return None
    except ValueError:
        return None
    if not result["client_id"] or "{{" in json.dumps(result):
        return None
    return result


def _resolve_config(value, resolve):
    if isinstance(value, dict):
        return {key: _resolve_config(item, resolve) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_config(item, resolve) for item in value]
    return resolve(value)


def operation_matches(request, spec):
    if not spec:
        return []
    parsed = normalize_spec(spec)
    url = urlsplit(request.get("url") or "")
    base = urlsplit(parsed.get("base_url") or "")
    if base.hostname and (url.scheme, url.hostname, url.port) != (base.scheme, base.hostname, base.port):
        return []
    path = unquote(url.path)
    prefix = base.path.rstrip("/")
    if prefix and not path.startswith(prefix + "/"):
        return []
    path = path[len(prefix):]
    return [op["id"] for op in parsed["operations"] if op["method"] == request.get("method") and re.fullmatch(re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(op["path"])), path)]


def import_collection(files, *, environment=None, spec=None, credential_names=(), global_variables=(), cancel_event=None):
    files = file_map(files)
    config = {}
    if "bruno.json" in files:
        try:
            config = json.loads(files["bruno.json"])
        except ValueError as exc:
            raise ValueError("bruno.json is not valid JSON.") from exc
        if not isinstance(config, dict) or str(config.get("version")) != "1" or config.get("type") != "collection":
            raise ValueError("Expected a Bruno bruno.json collection manifest, version 1.")
    from .bruno_yaml import definition as yaml_definition
    from .bruno_yaml import unsupported_features
    paths, kinds, parsed = [], [], {}
    parse_items = []
    for name in files:
        if name == "bruno.json":
            continue
        yaml = name.endswith((".yml", ".yaml"))
        basename = PurePosixPath(name).name
        kind = ("environment" if name.startswith("environments/") else "collection"
                if basename in {"collection.bru", "folder.bru", "opencollection.yml", "opencollection.yaml", "folder.yml", "folder.yaml"} else "request")
        parser_kind = ("yamlEnvironment" if kind == "environment" else "yamlCollection" if basename.startswith("opencollection.")
                       else "yamlFolder" if kind == "collection" else "yamlRequest") if yaml else kind
        if yaml:
            unsupported_features(files[name], parser_kind)
        paths.append(name)
        kinds.append(kind)
        parse_items.append({"kind": parser_kind, "value": files[name]})
    values = []
    for offset in range(0, len(parse_items), 200):
        values.extend(parser("parse", parse_items[offset:offset + 200], cancel_event=cancel_event))
    for name, item, value in zip(paths, parse_items, values, strict=True):
        if item["kind"] == "yamlCollection":
            config = value["brunoConfig"]
            if config.get("opencollection") != "1.0.0":
                raise ValueError("Only OpenCollection 1.0.0 collections verified with Bruno 4.2.1 are supported.")
        converted = yaml_definition(value, item["kind"]) if item["kind"].startswith("yaml") else value
        if item["kind"].startswith("yaml") and (unsupported := unsupported_features(files[name], item["kind"])):
            converted["unsupported_yaml_features"] = unsupported
        canonical = ("collection.bru" if item["kind"] == "yamlCollection" else str(PurePosixPath(name).with_suffix(".bru"))
                     if item["kind"] in {"yamlFolder", "yamlEnvironment"} else name)
        if canonical in parsed:
            raise ValueError("Ambiguous BRU and YAML metadata for the same scope.")
        parsed[canonical] = converted
    envs = sorted(name[len("environments/"):-4] for name in parsed if name.startswith("environments/"))
    if envs and environment is None:
        return {"requires_environment": True, "environments": envs, "requests": [], "warnings": ["Explicitly choose an environment, or No environment, before resolving requests."], "requests_sent": 0}
    if environment and environment not in envs:
        raise ValueError("Selected environment is absent. Upload its .bru file or choose No environment.")
    env = parsed.get(f"environments/{environment}.bru", {})
    if env.get("extends"):
        entries = [{**item, "name": name[len("environments/"):-4], "uid": name} for name, item in parsed.items() if name.startswith("environments/")]
        env = parser("parse", [{"kind": "resolveEnvironment", "value": {"environments": entries,
            "targetEnvironment": {**env, "name": environment, "uid": environment}, "merge": True}}], cancel_event=cancel_event)[0]
        if env.get("missingInheritedEnvironmentName") or env.get("cyclicInheritancePath") or not isinstance(env.get("extends"), str):
            env["unresolvedInheritance"] = True
        else:
            env = {key: item for key, item in env.items() if key not in {"extends", "name", "uid", "missingInheritedEnvironmentName", "cyclicInheritancePath"}}
    collection = parsed.get("collection.bru", {})
    raw_source = {"manifest": config, "definitions": parsed, "global_variables": list(global_variables)}
    source = sanitise(raw_source, credential_names)
    source_secrets = tuple(set(_redacted_values(raw_source, source)))
    results = []
    for path, kind in zip(paths, kinds, strict=True):
        if kind != "request":
            continue
        definition = parsed[path]
        warnings, blockers = [], []
        http = definition.get("http") or {}
        method = str(http.get("method") or "").upper()
        if method not in METHODS:
            blockers.append("Unsupported method/protocol; only standard HTTP methods are represented.")
        ancestors = []
        parent = PurePosixPath(path).parent
        for folder in reversed([parent, *parent.parents]):
            key = (str(folder) + "/" if str(folder) != "." else "") + "folder.bru"
            if key in parsed:
                ancestors.append(parsed[key])
        scopes = [collection, *ancestors, definition]
        variables = _vars(global_variables)
        variables.update(_vars((collection.get("vars") or {}).get("req")))
        variables.update(_vars(env.get("variables")))
        for scope in [*ancestors, definition]:
            variables.update(_vars((scope.get("vars") or {}).get("req")))
        missing = set()
        def resolve(value, stack=(), variables=variables, missing=missing):
            if not isinstance(value, str):
                return value
            def replace(match):
                key = match[1].strip()
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key) or key not in variables or key in stack or len(stack) >= 12:
                    missing.add(key)
                    return match[0]
                val = variables[key]
                if not isinstance(val, str):
                    missing.add(key)
                    return match[0]
                return resolve(val, (*stack, key))
            return VARIABLE.sub(replace, value)
        headers, auth_refs = {}, []
        inherited_auth = {"mode": "none"}
        for scope in scopes:
            if scope.get("script"):
                blockers.append("Scripts/hooks are inert and omitted; their effect on this request is unknown.")
            if scope.get("tests") or scope.get("assertions"):
                warnings.append("Bruno tests/assertions are inert and are not Namazu baseline assertions.")
            if (scope.get("vars") or {}).get("res"):
                warnings.append("Post-response/runtime variables are not evaluated.")
            for h in scope.get("headers") or []:
                if not h.get("enabled", True):
                    continue
                name = resolve(h["name"])
                # Credentials become references; never materialize an auth header.
                if sensitive(name, credential_names):
                    reference = {"header": name, "reference": VARIABLE.findall(str(h.get("value", ""))) or ["local identity required"]}
                    if name.lower() in {"authorization", "proxy-authorization"}:
                        scheme = re.match(r"^\s*(Bearer|Basic|Digest|Negotiate|NTLM)\s+", str(h.get("value", "")), re.I)
                        reference["scheme"] = scheme[1].lower() if scheme else "unresolved"
                    auth_refs.append(reference)
                else:
                    headers[name] = resolve(h.get("value", ""))
            if scope is collection:
                inherited_auth = scope.get("auth") or {"mode": "none"}
            elif scope is not definition and (scope.get("auth") or {}).get("mode") not in (None, "none", "inherit"):
                inherited_auth = scope["auth"]
        # CLI 4.2.1 merges inherited headers with a case-sensitive Map; Axios
        # then collapses case variants in insertion order. Updating an existing
        # spelling does not move it after a later, differently cased spelling.
        collapsed = {}
        for name, value in headers.items():
            if any(key.lower() == name.lower() and key != name for key in collapsed):
                warnings.append("Case-variant inherited headers use Bruno CLI 4.2.1 insertion-order precedence; review the resolved header value.")
            collapsed = {key: val for key, val in collapsed.items() if key.lower() != name.lower()}
            collapsed[name] = value
        headers = collapsed
        mode = http.get("auth", "none")
        auth = inherited_auth if mode == "inherit" else {"mode": mode, **(definition.get("auth") or {})}
        oauth_mapping = _oauth_mapping(auth, resolve)
        if auth.get("mode") not in (None, "none"):
            auth_refs.append({"mode": auth.get("mode"), "variables": VARIABLE.findall(json.dumps(auth)), "mapping": "local identity required"})
            warnings.append("Authentication must be mapped to a Namazu identity; no token acquisition or signing is performed.")
        url = resolve(http.get("url", ""))
        for param in definition.get("params") or []:
            if param.get("enabled", True) and param.get("type") == "path":
                blockers.append("Bruno :path parameters require manual conversion to an explicit resolved URL.")
        query = [(resolve(p["name"]), resolve(p.get("value", ""))) for p in definition.get("params") or [] if p.get("enabled", True) and p.get("type") == "query"]
        if query:
            parts = urlsplit(url)
            # The pinned CLI's prepareRequest uses http.url, not params:query.
            # A divergent table is ambiguous input; don't invent another URL.
            if parse_qsl(parts.query, keep_blank_values=True) != query:
                blockers.append("Query table differs from the URL used by Bruno CLI 4.2.1. Resolve the URL/table mismatch explicitly.")
        body_mode = http.get("body", "none")
        body = None
        if body_mode in ("json", "text", "xml"):
            body = resolve((definition.get("body") or {}).get(body_mode, ""))
            if body_mode == "json":
                try:
                    json.loads(body)
                except (ValueError, TypeError):
                    blockers.append("JSON body is unresolved or invalid; interpolation cannot be represented faithfully.")
            if not any(name.lower() == "content-type" for name in headers):
                headers["Content-Type"] = {"json": "application/json", "text": "text/plain", "xml": "application/xml"}[body_mode]
        elif body_mode == "form-urlencoded":
            body = urlencode([(resolve(v["name"]), resolve(v.get("value", ""))) for v in (definition.get("body") or {}).get("formUrlEncoded", []) if v.get("enabled", True)])
            if not any(name.lower() == "content-type" for name in headers):
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body_mode != "none":
            blockers.append("Unsupported body mode: file, multipart, binary and GraphQL bodies are not converted or read.")
        if env.get("extends") or env.get("inherits") or env.get("parent"):
            blockers.append("Environment inheritance requires a flattened, explicitly reviewed environment.")
        if set(env) - {"variables", "color"}:
            blockers.append("Environment inheritance/external secret providers are not evaluated; upload a flattened static environment.")
        if any(v.get("type") not in (None, "string") for scope in scopes for v in (scope.get("vars") or {}).get("req", [])):
            blockers.append("Typed variables require manual review; only static string interpolation is supported.")
        if missing:
            blockers.append("Unresolved variables: " + ", ".join(sorted(missing)))
        try:
            destination = urlsplit(url)
            if destination.scheme not in ("http", "https") or not destination.hostname or destination.username or destination.password:
                blockers.append("A resolved HTTP(S) URL without userinfo is required.")
        except ValueError:
            blockers.append("Invalid request URL.")
        if any(scope.get("settings") for scope in scopes) or config.get("clientCertificates") or config.get("proxy"):
            warnings.append("Bruno transport/settings are not applied. Review Namazu TLS, redirect, timeout, proxy and rate settings separately.")
        for scope in scopes:
            unknown = set(scope) - {"meta", "http", "headers", "params", "auth", "body", "vars", "script", "tests", "assertions", "settings", "docs", "examples"}
            if unknown:
                blockers.append("Unsupported definition features: " + ", ".join(sorted(unknown)))
            if scope.get("examples"):
                warnings.append("Saved examples are retained as inert definitions, not independently observed network evidence.")
        request = {"method": method, "url": url, "headers": headers, "body": body,
                   "body_mode": body_mode, "has_body": body is not None,
                   "content_type": next((value for name, value in headers.items() if name.lower() == "content-type"), None)}
        safe = sanitise({"variables": variables, "request": request}, credential_names, extra_secrets=source_secrets)["request"]
        if MARKER in json.dumps(safe):
            blockers.append("Redacted request values require local substitution before baseline preparation.")
        results.append({"id": path, "name": source["definitions"][path].get("meta", {}).get("name") or path,
                        "source_ref": path, "folder": str(PurePosixPath(path).parent) if PurePosixPath(path).parent != PurePosixPath(".") else "",
                        "sequence": definition.get("meta", {}).get("seq"), "definition": source["definitions"][path],
                        "variables": sanitise(variables, credential_names, extra_secrets=source_secrets),
                        "request": safe, "authentication": sanitise(auth_refs, credential_names), "authentication_mode": auth.get("mode") or "none",
                        "authentication_config": sanitise({"auth": _resolve_config(auth, resolve)}, credential_names, extra_secrets=source_secrets)["auth"],
                        "oauth_client_credentials": sanitise({"oauth_client_credentials": oauth_mapping}, credential_names, extra_secrets=source_secrets)["oauth_client_credentials"] if oauth_mapping else None,
                        "unresolved": sorted(missing), "warnings": list(dict.fromkeys(warnings)), "blockers": list(dict.fromkeys(blockers)),
                        "can_prepare": not blockers, "operation_matches": operation_matches(safe, spec)})
    return {"source_kind": "bruno-collection", "format": "bruno-request-definitions", "format_version": 1,
            "parser_version": PARSER_VERSION, "filestore_version": FILESTORE_VERSION,
            "definition_hash": hashlib.sha256(json.dumps({"files": files, "environment": environment, **({"global_variables": list(global_variables)} if global_variables else {})}, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
            "response_contract": False, "collection": source["manifest"].get("name") or "Selected Bruno requests",
            "environment": environment or None, "environments": envs, "requests": results, "source": source, "requests_sent": 0,
            "warnings": ["Definitions are templates, not captured wire evidence or an authoritative response contract. Imports never execute requests, scripts or dynamic expressions."]}


def export_collection(requests, *, credential_names=()):
    bounded(requests)
    if not isinstance(requests, list) or not 1 <= len(requests) <= 100:
        raise ValueError("Select 1–100 requests to export.")
    sanitized = sanitise(requests, credential_names)
    items, warnings, variables = [], [], {}
    for index, row in enumerate(sanitized, 1):
        if not isinstance(row, dict):
            raise ValueError("Each selected request must be an object.")
        warnings.extend(f"Request {index}: {note}" for note in row.get("conversion_warnings", []) if isinstance(note, str))
        request = row.get("request", row)
        if not isinstance(request, dict):
            raise ValueError("Each selected request must contain a request object.")
        method = str(request.get("method") or "").upper()
        url = request.get("url")
        if method not in METHODS or not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError(f"Request {index}: select a supported HTTP method and absolute URL.")
        parts = urlsplit(url)
        if not parts.hostname or any(c in url for c in "\r\n\x00"):
            raise ValueError("Export requires a single-line absolute HTTP(S) URL.")
        if parts.username or parts.password:
            raise ValueError("Remove URL userinfo; map authentication to a named credential variable.")
        def variable(label, index=index):
            name = f"NAMAZU_{index}_" + re.sub(r"[^A-Z0-9_]", "_", label.upper())
            variables[name] = ""
            return "{{" + name + "}}"
        query = [(k, variable(k) if sensitive(k, credential_names) or MARKER in v else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, safe="{}"), parts.fragment))
        if MARKER in unquote(url):
            url = unquote(url).replace(MARKER, variable("URL_SECRET"))
        headers = request.get("headers", request.get("request_headers")) or {}
        if not isinstance(headers, dict):
            raise ValueError("Export headers must be an object.")
        out_headers = []
        for name, value in headers.items():
            if name.lower() in {"host", "content-length", "connection", "transfer-encoding", "accept-encoding"}:
                warnings.append(f"Request {index}: transport header {name} omitted; Bruno computes it.")
                continue
            if not isinstance(value, str) or "\n" in name or "\r" in name or "\n" in value or "\r" in value:
                raise ValueError("Export supports single-line string header names and values only.")
            if sensitive(name, credential_names) or MARKER in value:
                value = variable(name)
                warnings.append(f"Request {index}: supply the complete {name} value locally, including any Bearer/Basic prefix.")
            out_headers.append({"name": name, "value": value, "enabled": True})
        body = request.get("body", request.get("request_body"))
        content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), request.get("content_type") or "")
        if not isinstance(content_type, str) or any(char in content_type for char in "\r\n\x00"):
            raise ValueError("Export requires a valid single-line Content-Type.")
        media = content_type.lower()
        body_encoding = request.get("body_encoding")
        if body_encoding not in (None, "raw", "json-value"):
            raise ValueError("Choose raw body text or an explicit JSON value representation for export.")
        explicit_json_value = body_encoding == "json-value" or request.get("definition_only") is True
        has_body = body is not None or request.get("has_body") is True
        if body is None and "has_body" not in request:
            warnings.append(f"Request {index}: body presence was not retained; no body is reconstructed from missing evidence.")
        mode, body_obj = "none", None
        if has_body:
            if body is None and "json" not in media:
                raise ValueError("An explicit null body requires a JSON media type; missing bytes are not reconstructed.")
            if body is not None and not isinstance(body, (str, dict, list, int, float, bool)):
                raise ValueError("Binary/file bodies cannot be exported.")
            body = body if isinstance(body, str) and not (explicit_json_value and "json" in media) else json.dumps(body, ensure_ascii=False)
            secret_index = 0
            while MARKER in body:
                secret_index += 1
                body = body.replace(MARKER, variable(f"BODY_SECRET_{secret_index}"), 1)
            if content_type and not any(header["name"].lower() == "content-type" for header in out_headers):
                out_headers.append({"name": "Content-Type", "value": content_type, "enabled": True})
            if "multipart/" in media or "octet-stream" in media:
                raise ValueError("Multipart and binary bodies cannot be exported faithfully. Select a text/JSON request.")
            mode = "json" if "json" in media else "xml" if "xml" in media else "text"
            if mode == "json":
                warnings.append(f"Request {index}: Bruno CLI reserializes JSON; whitespace and exact wire bytes may differ.")
            body_obj = {mode: body}
        definition = {"meta": {"name": f"Namazu request {index}", "type": "http", "seq": index}, "http": {"method": method.lower(), "url": url, "body": mode, "auth": "none"}, "headers": out_headers}
        if body_obj:
            definition["body"] = body_obj
        items.append({"kind": "requestText", "value": definition})
    items.append({"kind": "environmentText", "value": {"variables": [{"name": k, "value": v, "enabled": True, "secret": False} for k, v in variables.items()]}})
    texts = parser("serialize", items)
    # Verify our serializer output with the same official grammar before download.
    verified = parser("parse", [{"kind": "request", "value": v} for v in texts[:-1]] + [{"kind": "environment", "value": texts[-1]}])
    if any(row.get("script") or row.get("tests") for row in verified[:-1]):
        raise ValueError("Request content cannot be represented without introducing executable Bruno blocks.")
    for original, decoded in zip(items[:-1], verified[:-1], strict=True):
        definition = original["value"]
        if decoded.get("http") != definition["http"] or decoded.get("headers", []) != definition["headers"] or decoded.get("body") != definition.get("body"):
            raise ValueError("The official Bruno serializer cannot preserve this URL, header or body. Resolve its syntax before exporting.")
    files = [{"path": "bruno.json", "content": json.dumps({"version": "1", "name": "Namazu reviewed requests", "type": "collection", "ignore": ["node_modules", ".git"]}, indent=2)}]
    files.extend({"path": f"request-{index:03d}.bru", "content": value} for index, value in enumerate(texts[:-1], 1))
    files.append({"path": "environments/Local.bru", "content": texts[-1]})
    return {"files": files, "warnings": list(dict.fromkeys([*warnings, "Scripts, hooks, assertions, signing/auth flows, cookies from jars and binary/file attachments are not exported. No roundtrip fidelity is claimed for those features.", "Review every request and fill the empty named credential variables locally before explicitly running Bruno."])), "requests_sent": 0, "format": "Bruno collection v1 / BRU grammar v2; CLI 4.2.1"}
