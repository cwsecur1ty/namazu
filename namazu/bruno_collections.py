"""Parse/serialize Bruno definitions with the pinned official parser, offline."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from .bruno import MARKER, bounded, sanitise, sensitive
from .runner import normalize_spec

METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"})
VARIABLE = re.compile(r"\{\{([^{}]+)\}\}")
BRIDGE = Path(__file__).parent / "bruno_node" / "bridge.cjs"


def parser(action, items):
    node = shutil.which("node")
    if not node:
        raise ValueError("Bruno definitions require Node.js 20 or newer on the Namazu server. JSON run reports do not require Node.")
    try:
        result = subprocess.run([node, "--max-old-space-size=192", str(BRIDGE)], input=json.dumps({"action": action, "items": items}), capture_output=True, encoding="utf-8", timeout=15, check=False)
        output = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise ValueError("Bruno parser could not complete within its limits. Check Node.js and reduce the selected files.") from exc
    if result.returncode or output.get("error"):
        raise ValueError(output.get("error") or "Bruno syntax was rejected by parser 0.40.0.")
    return output["result"]


def file_map(files):
    bounded(files)
    if not isinstance(files, list) or not files or len(files) > 200:
        raise ValueError("Select 1–200 .bru files and optionally bruno.json. Archives are not accepted.")
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
        if not (name.endswith(".bru") or path.name == "bruno.json"):
            raise ValueError("Only .bru and bruno.json files are accepted; referenced files and archives are never read.")
        if len(item["content"].encode()) > 256 * 1024:
            raise ValueError("Each Bruno definition is limited to 256 KiB.")
        out[name] = item["content"]
    # Folder uploads include one outer directory; remove exactly the bruno.json root.
    roots = [str(PurePosixPath(name).parent) for name in out if PurePosixPath(name).name == "bruno.json"]
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


def import_collection(files, *, environment=None, spec=None, credential_names=()):
    files = file_map(files)
    config = {}
    if "bruno.json" in files:
        try:
            config = json.loads(files["bruno.json"])
        except ValueError as exc:
            raise ValueError("bruno.json is not valid JSON.") from exc
        if not isinstance(config, dict) or str(config.get("version")) != "1" or config.get("type") != "collection":
            raise ValueError("Expected a Bruno bruno.json collection manifest, version 1.")
    paths = [name for name in files if name.endswith(".bru")]
    kinds = ["environment" if name.startswith("environments/") else "collection" if PurePosixPath(name).name in ("collection.bru", "folder.bru") else "request" for name in paths]
    parsed = dict(zip(paths, parser("parse", [{"kind": kind, "value": files[name]} for name, kind in zip(paths, kinds, strict=True)]), strict=True))
    envs = sorted(name[len("environments/"):-4] for name in paths if name.startswith("environments/"))
    if envs and environment is None:
        return {"requires_environment": True, "environments": envs, "requests": [], "warnings": ["Explicitly choose an environment, or No environment, before resolving requests."], "requests_sent": 0}
    if environment and environment not in envs:
        raise ValueError("Selected environment is absent. Upload its .bru file or choose No environment.")
    env = parsed.get(f"environments/{environment}.bru", {})
    collection = parsed.get("collection.bru", {})
    source = sanitise({"manifest": config, "definitions": parsed}, credential_names)
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
        variables = _vars((collection.get("vars") or {}).get("req"))
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
                    auth_refs.append({"header": name, "reference": VARIABLE.findall(str(h.get("value", ""))) or ["local identity required"]})
                else:
                    headers = {k: v for k, v in headers.items() if k.lower() != name.lower()}
                    headers[name] = resolve(h.get("value", ""))
            if scope is not definition and (scope.get("auth") or {}).get("mode") not in (None, "inherit"):
                inherited_auth = scope["auth"]
        mode = http.get("auth", "none")
        auth = inherited_auth if mode == "inherit" else {"mode": mode, **(definition.get("auth") or {})}
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
            headers.setdefault("Content-Type", {"json": "application/json", "text": "text/plain", "xml": "application/xml"}[body_mode])
        elif body_mode == "form-urlencoded":
            body = urlencode([(resolve(v["name"]), resolve(v.get("value", ""))) for v in (definition.get("body") or {}).get("formUrlEncoded", []) if v.get("enabled", True)])
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
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
            unknown = set(scope) - {"meta", "http", "headers", "params", "auth", "body", "vars", "script", "tests", "assertions", "settings", "docs"}
            if unknown:
                blockers.append("Unsupported definition features: " + ", ".join(sorted(unknown)))
        request = {"method": method, "url": url, "headers": headers, "body": body}
        safe = sanitise({"source": {"parsed": parsed, "variables": variables}, "request": request}, credential_names)["request"]
        if MARKER in json.dumps(safe):
            blockers.append("Redacted request values require local substitution before baseline preparation.")
        results.append({"id": path, "name": source["definitions"][path].get("meta", {}).get("name") or path, "source_ref": path, "request": safe, "authentication": sanitise(auth_refs, credential_names), "unresolved": sorted(missing), "warnings": list(dict.fromkeys(warnings)), "blockers": list(dict.fromkeys(blockers)), "can_prepare": not blockers, "operation_matches": operation_matches(safe, spec)})
    return {"collection": source["manifest"].get("name") or "Selected Bruno requests", "environment": environment or None, "environments": envs, "requests": results, "source": source, "requests_sent": 0, "warnings": ["Definitions are templates, not captured wire evidence or an authoritative response contract. Imports never execute requests, scripts or dynamic expressions."]}


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
        mode, body_obj = "none", None
        if body is not None:
            if not isinstance(body, (str, dict, list, int, float, bool)):
                raise ValueError("Binary/file bodies cannot be exported.")
            body = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
            secret_index = 0
            while MARKER in body:
                secret_index += 1
                body = body.replace(MARKER, variable(f"BODY_SECRET_{secret_index}"), 1)
            content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
            if "multipart/" in content_type or "octet-stream" in content_type:
                raise ValueError("Multipart and binary bodies cannot be exported faithfully. Select a text/JSON request.")
            mode = "json" if "json" in content_type else "xml" if "xml" in content_type else "text"
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
