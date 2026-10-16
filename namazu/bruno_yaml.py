"""Shape adapter from the official filestore parser to the existing BRU model.

No YAML request grammar is implemented here. The pinned official converter owns
syntax and field conversion; unsupported capabilities remain explicit blockers.
"""
from __future__ import annotations

import copy

import yaml


def unsupported_features(content, kind):
    """Reject ambiguous YAML and flag fields the pinned adapter cannot retain."""
    try:
        if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)) for token in yaml.scan(content)):
            raise ValueError()
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict) or any(not isinstance(key, str) for key in doc):
            raise ValueError()
        for name in ("http", "runtime", "settings"):
            nested = doc.get(name)
            if nested is not None and (not isinstance(nested, dict) or any(not isinstance(key, str) for key in nested)):
                raise ValueError()
    except (yaml.YAMLError, ValueError, RecursionError):
        raise ValueError("YAML definitions must be plain bounded mappings without aliases or custom tags.") from None
    allowed = {
        "yamlRequest": {"info", "http", "graphql", "grpc", "websocket", "runtime", "settings", "examples", "docs", "app", "type"},
        "yamlCollection": {"opencollection", "info", "request", "config", "docs", "extensions"},
        "yamlFolder": {"info", "request", "docs"},
        "yamlEnvironment": {"name", "variables", "color", "extends", "externalSecrets"},
    }
    unknown = set(doc) - allowed[kind]
    if isinstance(doc.get("http"), dict):
        unknown.update("http." + key for key in set(doc["http"]) - {"method", "url", "headers", "params", "body", "auth"})
    if isinstance(doc.get("runtime"), dict):
        unknown.update("runtime." + key for key in set(doc["runtime"]) - {"variables", "scripts", "assertions", "actions"})
    if (doc.get("settings") or {}).get("omitHeaders"):
        unknown.add("settings.omitHeaders")
    return sorted(str(name) for name in unknown)


def stable(value):
    if isinstance(value, dict):
        return {key: stable(item) for key, item in value.items() if key not in {"uid", "itemUid"}}
    if isinstance(value, list):
        return [stable(item) for item in value]
    return value


def scope(value):
    value = stable(copy.deepcopy(value or {}))
    result = {key: value[key] for key in ("headers", "params", "auth", "body", "vars", "tests", "assertions", "docs") if value.get(key)}
    scripts = {key: item for key, item in (value.get("script") or {}).items() if item}
    if scripts:
        result["script"] = scripts
    for variable in (result.get("vars") or {}).get("req", []):
        variable["type"] = variable.get("dataType") or "string"
    return result


def definition(value, kind):
    value = stable(value)
    if kind == "yamlEnvironment":
        result = {key: value[key] for key in ("variables", "color", "extends", "externalSecrets") if key in value}
        if any(row.get("dataType") not in (None, "string") for row in result.get("variables", [])):
            result["unsupportedTypedVariables"] = True
        return result
    if kind in {"yamlFolder", "yamlCollection"}:
        root = value.get("collectionRoot", {}) if kind == "yamlCollection" else value
        return {**scope(root.get("request")), "meta": root.get("meta") or {}, "docs": root.get("docs")}
    result = scope(value.get("request"))
    request = value.get("request") or {}
    result["meta"] = {"name": value.get("name"), "seq": value.get("seq"), "type": value.get("type")}
    result["http"] = {"method": request.get("method", "GET"), "url": request.get("url", ""),
                      "auth": (request.get("auth") or {}).get("mode", "none"),
                      "body": (request.get("body") or {}).get("mode", "none")}
    if value.get("type") != "http-request":
        result["unsupported_protocol"] = value.get("type") or "unknown"
    if value.get("settings"):
        result["settings"] = value["settings"]
    if value.get("app"):
        result["unsupported_app"] = True
    if value.get("examples"):
        # Examples are inert source material, never independent wire evidence.
        result["examples"] = value["examples"]
    return result
