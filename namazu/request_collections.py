"""Persist Bruno request definitions separately from OpenAPI response contracts.

The existing Bruno parser owns conversion. This adapter namespaces its reviewed
output and supplies the existing ordinary-request executor with an empty response
schema carrier. It neither evaluates scripts nor obtains credentials.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit, urlunsplit

from .bruno import MARKER, bounded, sanitise
from .discovery import check_headers, check_url


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def origin(value):
    parts = urlsplit(check_url(value))
    if parts.username or parts.password:
        raise ValueError("Request collection URLs must not contain credentials")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _review_definition(row):
    """Recheck capability boundaries on saved input; never execute source code."""
    request, definition = row["request"], row.get("definition")
    blockers = row.get("blockers") or []
    if not isinstance(blockers, list) or any(not isinstance(item, str) for item in blockers):
        raise ValueError("Invalid request definition blockers")
    blockers = list(blockers)
    if MARKER in json.dumps(request, ensure_ascii=False):
        blockers.append("Redacted request values cannot be dispatched; replace and review this definition locally.")
    if not isinstance(definition, dict) or not isinstance(definition.get("http"), dict):
        blockers.append("The parsed request definition is missing; import the original collection again.")
    else:
        declared = definition["http"]
        mode = declared.get("body", "none")
        if mode not in {"none", "json", "text", "xml", "form-urlencoded"}:
            blockers.append("Unsupported body mode: file, multipart, binary and GraphQL bodies are not converted or read.")
        if request.get("body_mode") != mode or request.get("method", "").lower() != str(declared.get("method", "")).lower():
            blockers.append("Prepared method or body mode differs from the parsed definition; import and review it again.")
        if definition.get("script"):
            blockers.append("Scripts/hooks are inert and omitted; their effect on this request is unknown.")
        if not isinstance(request.get("has_body"), bool) or request["has_body"] != (request.get("body") is not None):
            blockers.append("Body presence is inconsistent with the saved request definition.")
        if mode == "json":
            try:
                json.loads(request.get("body", ""))
            except (ValueError, TypeError):
                blockers.append("The saved JSON request body is invalid or unresolved.")
    authentication = row.get("authentication", [])
    if not isinstance(authentication, list) or any(not isinstance(ref, dict) for ref in authentication):
        raise ValueError("Invalid saved authentication references")
    for ref in authentication:
        if "header" in ref and not isinstance(ref["header"], str):
            raise ValueError("Invalid saved credential header reference")
    if row.get("authentication_mode") == "oauth2":
        from .bruno_collections import _oauth_mapping
        config = row.get("authentication_config")
        derived = _oauth_mapping(config, lambda value: value) if isinstance(config, dict) else None
        supplied = row.get("oauth_client_credentials")
        if (not derived or not isinstance(supplied, dict)
                or any(supplied.get(key) != value for key, value in derived.items() if key != "secret_reference")):
            row["oauth_client_credentials"] = None
            blockers.append("OAuth authentication is not a faithfully reviewed client-credentials mapping; configure it explicitly in advanced tools.")
    row["blockers"] = list(dict.fromkeys(blockers))
    row["can_prepare"] = row.get("can_prepare") is True and not blockers


def collection(imported, *, identifier=None):
    bounded(imported)
    if not isinstance(imported, dict) or imported.get("requires_environment"):
        raise ValueError("Resolve an explicit Bruno environment before adding the collection")
    rows = imported.get("requests")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 2000:
        raise ValueError("A request collection must contain 1–2000 request definitions")
    clean = sanitise(copy.deepcopy(rows))
    cid, operations, seen, targets = identifier or uuid.uuid4().hex, [], set(), []
    if not isinstance(cid, str) or not re.fullmatch(r"[a-f0-9]{32}", cid):
        raise ValueError("Invalid request collection identity")
    for row in clean:
        if not isinstance(row, dict) or not isinstance(row.get("request"), dict):
            raise ValueError("Invalid request collection entry")
        key = row.get("id")
        if not isinstance(key, str) or not key or len(key) > 4096 or key in seen:
            raise ValueError("Request definition source identities must be unique")
        if key.startswith(("/", "\\")) or ".." in key.replace("\\", "/").split("/") or ":" in key:
            raise ValueError("Unsafe request definition source path")
        seen.add(key)
        request = row["request"]
        if request.get("method") not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}:
            raise ValueError("Unsupported request definition method")
        check_headers(request.get("headers") or {})
        _review_definition(row)
        try:
            target = origin(request.get("url", ""))
        except ValueError:
            target = ""
            row["can_prepare"] = False
            row.setdefault("blockers", []).append("Choose a resolved HTTP(S) request URL.")
        if target and target not in targets:
            targets.append(target)
        path = urlsplit(request.get("url", "")).path or "/"
        operations.append({"id": cid + "::" + key, "local_id": key, "contract_id": cid,
            "method": request["method"], "path": path, "summary": str(row.get("name") or key),
            "operation_id": key, "tags": [row.get("folder") or "Requests"], "parameters": [],
            "request_definition": row, "target": target, "request_body": {}, "responses": {}})
    material = {"requests": clean, "environment": imported.get("environment"),
                "title": str(imported.get("collection") or "Bruno requests")}
    provenance = imported.get("provenance")
    if provenance is not None:
        if not isinstance(provenance, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(provenance.get("source_id", ""))):
            raise ValueError("Invalid request collection source boundary")
        material["provenance"] = sanitise(provenance)
    snapshot_hash = digest(material)
    return {"id": cid, "request_collection": True, "source_kind": "bruno-collection",
        "format_version": 1, "response_contract": False, "title": material["title"],
        "version": "Bruno definitions", "hash": snapshot_hash, "snapshot_hash": snapshot_hash,
        "source_hash": imported.get("definition_hash"), "parser_version": imported.get("parser_version"),
        "environment": material["environment"], "provenance": material.get("provenance"), "source": "Imported Bruno request definitions",
        "material": material, "operations": operations, "operation_count": len(operations),
        "target": targets[0] if len(targets) == 1 else "", "targets": targets,
        "target_review_required": False, "scope_review_required": False,
        "config": {"allow_mutating": False}, "identity_assignment": None, "identity_override": None, "request_assignments": {},
        "warnings": list(imported.get("warnings") or []), "readiness": {"status": "unestablished",
            "reason": "Request definitions contain no authoritative response contract or successful controls"}}


def restore(value):
    if not isinstance(value, dict) or value.get("format_version") != 1 or not isinstance(value.get("material"), dict):
        raise ValueError("Unsupported saved request collection format")
    material = value["material"]
    rebuilt = collection({"requests": material.get("requests"), "environment": material.get("environment"),
        "collection": material.get("title"), "definition_hash": value.get("source_hash"),
        "parser_version": value.get("parser_version"), "provenance": material.get("provenance"), "warnings": value.get("warnings", [])}, identifier=value.get("id"))
    if rebuilt["hash"] != value.get("hash"):
        rebuilt["recorded_hash"] = value.get("hash")
        rebuilt["warnings"].append("Imported definition hash differs; new requests use a freshly verified snapshot.")
    # Restore references for review only. Credentials themselves are unavailable.
    assignments = value.get("request_assignments") or {}
    if not isinstance(assignments, dict) or len(assignments) > len(rebuilt["operations"]):
        raise ValueError("Invalid request identity assignments")
    for key, assignment in assignments.items():
        if key not in {operation["id"] for operation in rebuilt["operations"]}:
            raise ValueError("Request identity assignment refers to a different collection")
        if isinstance(assignment, dict):
            if assignment.get("anonymous") is True:
                rebuilt["request_assignments"][key] = {"anonymous": True, "source": "request-specific no identity"}
                continue
            scopes = assignment.get("allowed_scopes")
            if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes):
                raise ValueError("Invalid saved request collection identity scope")
            for scope in scopes:
                origin(scope)
            rebuilt["request_assignments"][key] = {"profile_id": str(assignment.get("profile_id") or ""), "allowed_scopes": scopes,
                                                  "source": "request-specific override"}
    for key in ("identity_assignment", "identity_override"):
        binding = value.get(key)
        if binding:
            rebuilt[key] = _restore_binding(binding, "shared profile" if key == "identity_assignment" else "contract-specific override")
    environments = value.get("environment_assignments") or {}
    if not isinstance(environments, dict) or len(environments) > 100:
        raise ValueError("Invalid imported environment assignments")
    rebuilt["environment_assignments"] = {str(key): _restore_binding(binding, "environment assignment") for key, binding in environments.items()}
    return rebuilt


def _restore_binding(binding, source):
    if not isinstance(binding, dict) or not isinstance(binding.get("profile_id"), str):
        raise ValueError("Invalid saved collection identity reference")
    scopes = binding.get("allowed_scopes")
    if not isinstance(scopes, list) or not scopes or len(scopes) > 100:
        raise ValueError("Invalid saved collection identity scopes")
    for scope in scopes:
        origin(scope)
    return {"profile_id": binding["profile_id"], "allowed_scopes": scopes, "source": source}


def safe_collection(value, *, extra_secrets=()):
    """Redact and rebind active material, operations and hash as one unit.

    Newly recognised live credentials can change a previously harmless value.
    Such a change gets a new snapshot and a blocked definition, while previous
    hashes remain historical references without retaining plaintext material.
    """
    clean = sanitise(copy.deepcopy(value), extra_secrets=extra_secrets)
    rebuilt = restore(clean)
    for key in ("removed_at", "identity"):
        if key in clean:
            rebuilt[key] = clean[key]
    identities = {row.get("id"): row.get("identity") for row in clean.get("operations", []) if isinstance(row, dict)}
    for operation in rebuilt["operations"]:
        if isinstance(identities.get(operation["id"]), dict):
            operation["identity"] = identities[operation["id"]]
    previous = [*value.get("historical_snapshot_hashes", []), value.get("recorded_hash"), value.get("hash")]
    previous = list(dict.fromkeys(item for item in previous if isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) and item != rebuilt["hash"]))
    if previous:
        rebuilt["historical_snapshot_hashes"] = previous
        rebuilt["recorded_hash"] = previous[-1]
    return rebuilt


def execution_spec(operation):
    """Internal carrier for the shared HTTP executor, never a response contract."""
    path = operation["path"]
    document = {"openapi": "3.0.3", "info": {"title": "Request definition (no response contract)", "version": "1"},
        "paths": {path: {operation["method"].lower(): {"responses": {}}}}}
    return {"document": document}, f"{operation['method']} {path}"
