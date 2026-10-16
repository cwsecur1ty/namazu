"""Offline, durable contract workspaces and explicitly scoped bearer references.

The existing parser, documentation resolver and audit engine remain the source of
truth. This layer gives each imported document its own namespace and binds a
reviewed plan to immutable document snapshots, targets and credential revisions.
Bearer values default to process memory; explicitly opted-in Windows persistence
uses current-user DPAPI outside workspace/export data. Resolving an external
reference only reads explicitly supplied companions.
"""
from __future__ import annotations

import copy
import hashlib
import json
import posixpath
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urldefrag, urljoin, urlsplit, urlunsplit

import yaml

from . import discovery
from .audit.engine import PROFILES, _apply_example, _check_example_scope, audit_plan
from .audit.importing import sanitise_saved_audit
from .audit.readiness import _sanitise
from .audit.run_store import default_db_path
from .audit.transport import MAX_CONCURRENCY
from .credential_store import CredentialStore, CredentialStoreError
from .desktop_state import data_paths, desktop_enabled
from .spec import MAX_DOCUMENT_BYTES, _bounded_json, _pointer, build_request, parse_spec

FORMAT = "namazu-workspace"
FORMAT_VERSION = 1
SCHEMA_VERSION = 1
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
LITERALS = frozenset({"example", "examples", "enum", "const", "default"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _document(raw) -> dict:
    if isinstance(raw, str):
        if len(raw.encode()) > MAX_DOCUMENT_BYTES:
            raise ValueError("Specification exceeds the 8 MiB limit")
        try:
            raw = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError("Invalid JSON or YAML document") from exc
    if not isinstance(raw, dict):
        raise ValueError("A specification or companion must be a JSON/YAML object")
    return _bounded_json(raw)


def _source_uri(source: str) -> str:
    source = str(source or "openapi.json").replace("\\", "/")
    if source.startswith(("http://", "https://", "file://")):
        return urldefrag(source)[0]
    return urljoin("file:///workspace/", source)


def _bundle(raw, source: str, companions: dict | None = None) -> tuple[dict, list[str], dict]:
    """Rebase every supplied document's refs into a private, local bundle."""
    document = _document(raw)
    origin = _source_uri(source)
    supplied = {origin: document}
    if companions is not None and (not isinstance(companions, dict) or len(companions) > 50):
        raise ValueError("Provide at most 50 named companion documents per contract")
    for name, value in (companions or {}).items():
        item = _document(value)
        for uri in {_source_uri(name), urljoin(origin, str(name).replace("\\", "/"))}:
            if uri in supplied and supplied[uri] != item:
                raise ValueError("Companion document names resolve ambiguously within this contract")
            supplied[uri] = item
    bundled: dict = {}
    unresolved: set[str] = set()
    used: dict = {}

    def include(uri):
        if uri == origin:
            return ""
        key = _hash(uri)[:20]
        if key not in bundled:
            bundled[key] = {}  # Reserve first: cycles remain finite local refs.
            used[uri] = supplied[uri]
            bundled[key] = visit(supplied[uri], uri)
        return "/x-namazu-documents/" + key

    def visit(value, uri):
        if isinstance(value, list):
            return [visit(item, uri) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str):
                resolved, fragment = urldefrag(urljoin(uri, item))
                if resolved not in supplied:
                    unresolved.add(resolved + ("#" + fragment if fragment else ""))
                    result[key] = resolved + ("#" + fragment if fragment else "")
                    continue
                try:
                    _pointer(supplied[resolved], "#" + fragment)
                except ValueError:
                    unresolved.add(resolved + "#" + fragment)
                prefix = include(resolved)
                result[key] = "#" + prefix + fragment
            else:
                result[key] = copy.deepcopy(item) if key in LITERALS else visit(item, uri)
        return result

    result = visit(document, origin)
    if bundled:
        result["x-namazu-documents"] = bundled
    # Dependencies' contents are part of the historical contract hash.
    def dependency_name(uri):
        base, location = urlsplit(origin), urlsplit(uri)
        if (base.scheme, base.netloc) == (location.scheme, location.netloc):
            relative = posixpath.relpath(location.path, posixpath.dirname(base.path))
            return relative + ("?" + location.query if location.query else "")
        return uri
    material = {"document": document, "dependencies": {dependency_name(uri): value for uri, value in sorted(used.items())}}
    return _bounded_json(result), sorted(unresolved), material


def normalise_target(value: str) -> str:
    discovery.check_url(value)
    parts = urlsplit(value)
    if parts.username or parts.password or parts.query or parts.fragment or "{" in value or "}" in value:
        raise ValueError("Choose an absolute API base URL without credentials, query, fragment or unresolved variables")
    path = unquote(parts.path)
    if "\\" in path or any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("API base paths must not contain traversal segments")
    if "%" in path or "//" in path:
        raise ValueError("API base paths must not contain ambiguous encoded or repeated separators")
    host = parts.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    default_port = 443 if parts.scheme.lower() == "https" else 80
    authority = host + (f":{parts.port}" if parts.port and parts.port != default_port else "")
    return urlunsplit((parts.scheme.lower(), authority, parts.path.rstrip("/"), "", ""))


def url_in_scopes(url: str, scopes: list[str]) -> bool:
    """Origin and decoded segment boundary check, also used by execution guards."""
    try:
        parts = urlsplit(url)
        if parts.username or parts.password:
            return False
        path = unquote(parts.path or "/")
        if "\\" in path or "%" in path or "//" in path or any(p in {".", ".."} for p in path.split("/")):
            return False
        origin = discovery.origin(url)
        for scope in scopes:
            allowed = urlsplit(normalise_target(scope))
            base = unquote(allowed.path).rstrip("/")
            if origin == discovery.origin(scope) and (not base or path == base or path.startswith(base + "/")):
                return True
    except (ValueError, TypeError):
        return False
    return False


def _expanded(value, document, seen=()):
    if isinstance(value, list):
        return [_expanded(child, document, seen) for child in value]
    if not isinstance(value, dict):
        return value
    ref = value.get("$ref")
    if isinstance(ref, str) and ref not in seen and len(seen) < 32:
        try:
            target = _expanded(_pointer(document, ref), document, (*seen, ref))
            if isinstance(target, dict):
                return {**target, **{k: _expanded(v, document, seen) for k, v in value.items() if k != "$ref"}}
        except ValueError:
            pass
    return {k: _expanded(v, document, seen) for k, v in value.items() if k not in {"description", "summary", "operationId", "tags"}}


def operation_semantics(spec: dict, operation: dict) -> str:
    return _hash(_expanded({key: operation.get(key) for key in
                           ("method", "parameters", "request_body", "responses", "security", "produces", "unresolved_parameters")}, spec["document"]))


def _templates_overlap(first: str, second: str) -> bool:
    left, right = first.strip("/").split("/"), second.strip("/").split("/")
    if len(left) != len(right):
        return False
    def match(a, b):
        if a == b:
            return True
        if "{" in a and "{" in b:
            return True  # Conservative: composite template constraints need review.
        template, literal = (a, b) if "{" in a else (b, a)
        return bool(re.fullmatch(re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(template)), literal))
    return all(match(a, b) for a, b in zip(left, right, strict=True))


class WorkspaceService:
    def __init__(self, path: str | Path | None = None, *, credential_store=None):
        self.path = Path(path) if path else data_paths().workspaces_db if desktop_enabled() else default_db_path().with_name("workspaces.db")
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            self._conn.close()
            raise ValueError("The workspace database uses an unsupported schema version; upgrade Namazu before opening it.")
        self._conn.execute("CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self._conn.commit()
        self._lock = threading.RLock()
        self._secrets: dict[tuple[str, str], str] = {}
        self._secret_revisions: dict[tuple[str, str], int] = {}
        if credential_store is not None:
            self.credentials = credential_store
        elif path is not None:
            self.credentials = CredentialStore(self.path.parent / "secrets")
        else:
            from .credential_store import store
            self.credentials = store()

    def close(self):
        self._conn.close()

    def _load(self, workspace_id):
        row = self._conn.execute("SELECT body FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
        if not row:
            raise ValueError("Workspace not found")
        return json.loads(row[0])

    def _safe(self, value, workspace_id):
        from .request_collections import safe_collection
        secrets = [secret for (wid, _), secret in self._secrets.items() if wid == workspace_id]
        sources = [{"authorization": "Bearer " + secret} for secret in secrets]
        # The Bruno adapter understands auth modes and reference metadata. The
        # generic evidence cleaner otherwise mistakes these enums for secrets.
        if isinstance(value, dict) and value.get("request_collection") is True:
            return safe_collection(value, extra_secrets=secrets)
        if isinstance(value, dict) and any(key in value for key in ("request_collections", "archived_request_collections")):
            ordinary = {key: item for key, item in value.items() if key not in {"request_collections", "archived_request_collections"}}
            safe = _sanitise(ordinary, preserve_metadata=True, secret_sources=sources)
            for key in ("request_collections", "archived_request_collections"):
                if key in value:
                    safe[key] = [safe_collection(item, extra_secrets=secrets) for item in value[key]]
            return safe
        return _sanitise(value, preserve_metadata=True, secret_sources=sources)

    def sanitise_local_data(self, value):
        """Mask available profile values in explicit local data migration.

        Decrypting a saved local profile is not token acquisition. No identity
        is assigned, no request is made and no stored workspace is changed.
        """
        from .desktop_state import sanitise_ui_state
        with self._lock:
            for row in self._conn.execute("SELECT body FROM workspaces").fetchall():
                workspace = json.loads(row[0])
                for profile in workspace.get("profiles", []):
                    self._credential(workspace["id"], profile)
            sources = [{"authorization": "Bearer " + secret} for secret in self._secrets.values()]
            return sanitise_ui_state(value, secret_sources=sources)

    def _save(self, workspace):
        safe = self._safe(workspace, workspace["id"])
        with self._conn:
            self._conn.execute("INSERT OR REPLACE INTO workspaces(id,body) VALUES(?,?)", (workspace["id"], json.dumps(safe)))

    def _invalidate(self, workspace, reason, affected=()):
        workspace["revision"] += 1
        workspace["updated_at"] = _now()
        for plan in workspace["plans"]:
            if plan.get("status") == "reviewed":
                plan["status"] = "invalidated"
                plan["invalidation_reason"] = reason
        for contract in workspace["contracts"]:
            # Evidence remains historical. Its readiness cannot cross contexts.
            if contract["id"] in affected:
                contract["readiness"] = {"status": "unestablished", "reason": reason}

    def create(self, title="Untitled workspace"):
        if isinstance(title, dict):
            title = title.get("title") or "Untitled workspace"
        with self._lock:
            workspace = {"id": uuid.uuid4().hex, "title": str(title), "revision": 1,
                         "created_at": _now(), "updated_at": _now(), "contracts": [],
                         "archived_contracts": [], "profiles": [], "overlaps": [], "decisions": [],
                         "plans": [], "runs": [], "import_errors": []}
            self._save(workspace)
            return self.get(workspace["id"])

    def list(self):
        with self._lock:
            rows = self._conn.execute("SELECT id,body FROM workspaces").fetchall()
            return [{"id": row[0], "title": (body := json.loads(row[1]))["title"],
                     "contract_count": len(body["contracts"]), "updated_at": body["updated_at"]} for row in rows]

    @staticmethod
    def _contract(workspace, contract_id):
        for contract in [*workspace["contracts"], *workspace.get("request_collections", [])]:
            if contract["id"] == contract_id:
                return contract
        raise ValueError("Contract not found in this workspace")

    def _identity(self, workspace, contract, operation_key=None):
        assignment = contract.get("identity_override") or contract.get("identity_assignment")
        if contract.get("request_collection"):
            assignment = ((contract.get("request_assignments") or {}).get(operation_key)
                          or (contract.get("environment_assignments") or {}).get(contract.get("environment"))
                          or assignment)
        if assignment and assignment.get("anonymous") is True:
            return {"profile_id": None, "source": "request-specific no identity", "revision": None,
                    "allowed_scopes": [], "credential_available": False}
        if not assignment:
            return {"profile_id": None, "source": "no identity configured", "revision": None,
                    "allowed_scopes": [], "credential_available": False}
        profile = next((p for p in workspace["profiles"] if p["id"] == assignment["profile_id"]), None)
        return {**copy.deepcopy(assignment), "revision": profile["revision"] if profile else None,
                "name": profile["name"] if profile else "Missing profile", "credential_available":
                self._credential(workspace["id"], profile) is not None if profile else False,
                "persistence": profile.get("persistence", "session") if profile else "session"}

    def _credential(self, workspace_id, profile):
        key = (workspace_id, profile["id"])
        if profile.get("kind") == "oauth-client-credentials":
            import time
            expiry = (profile.get("acquisition") or {}).get("expires_at")
            if isinstance(expiry, (int, float)) and expiry <= time.time():
                self._secrets.pop(key, None)
                return None
        if not profile.get("credential_ref") and self._secret_revisions.get(key) == profile["revision"] and key in self._secrets:
            return self._secrets[key]
        self._secrets.pop(key, None)
        if profile.get("credential_ref"):
            try:
                value = self.credentials.get(profile["credential_ref"])
            except CredentialStoreError:
                return None
            if value is not None:
                self._secrets[key] = value
                self._secret_revisions[key] = profile["revision"]
                return value
        return None

    def get(self, workspace_id):
        with self._lock:
            workspace = self._load(workspace_id)
            workspace["overlaps"] = self._overlaps(workspace)
            for contract in [*workspace["contracts"], *workspace.get("request_collections", [])]:
                contract["identity"] = self._identity(workspace, contract)
                if contract.get("request_collection"):
                    for operation in contract["operations"]:
                        operation["identity"] = self._identity(workspace, contract, operation["id"])
            for profile in workspace["profiles"]:
                profile["credential_available"] = self._credential(workspace_id, profile) is not None
                profile["masked_credential"] = "••••••••" if profile["credential_available"] else "Not loaded"
                from .identity_profiles import profile_status
                profile_status(self, workspace_id, profile)
            return self._safe(workspace, workspace_id)

    def import_bruno_collection(self, workspace_id, body):
        from .bruno_collections import import_collection
        from .request_collections import collection
        parsed = import_collection(body.get("files"), environment=body.get("environment"),
                                   credential_names=body.get("credential_names", []))
        created = collection(parsed)
        with self._lock:
            workspace = self._load(workspace_id)
            collections = workspace.setdefault("request_collections", [])
            existing = next((item for item in collections if item.get("source_hash") == created["source_hash"]
                             and item.get("hash") == created["hash"]), None)
            if existing:
                return {"workspace": self.get(workspace_id), "collection_id": existing["id"], "duplicate": True,
                        "requests_sent": 0}
            if len(collections) >= 100:
                raise ValueError("A workspace supports at most 100 request collections")
            collections.append(created)
            self._invalidate(workspace, "A request collection was added; existing controls remain unchanged")
            self._save(workspace)
            return {"workspace": self.get(workspace_id), "collection_id": created["id"], "duplicate": False,
                    "requests_sent": 0}

    def _import_one(self, item, *, contract_id=None):
        if isinstance(item, str):
            item = {"url": item}
        if not isinstance(item, dict):
            raise ValueError("Each import must be a specification or URL")
        source = str(item.get("source_url") or item.get("filename") or "openapi.json")
        warnings = []
        documentation_url = ""
        raw = item.get("raw_spec", item.get("raw", item.get("document")))
        if item.get("url"):
            documentation_url = str(item["url"])
            # Never consult identity profiles, imported headers or cookie jars.
            raw, source, warnings = discovery.fetch_document(documentation_url, headers={})
        document, unresolved, material = _bundle(raw, source, item.get("documents"))
        spec = parse_spec(document, source if source.startswith(("http://", "https://")) else "")
        metadata = discovery.setup_metadata(spec, documentation_url=documentation_url)
        target = metadata["suggested_target"] or ""
        declared_servers = list(document.get("servers") or [])
        for path_item in (document.get("paths") or {}).values():
            if isinstance(path_item, dict):
                declared_servers.extend(path_item.get("servers") or [])
                for operation in path_item.values():
                    if isinstance(operation, dict):
                        declared_servers.extend(operation.get("servers") or [])
        if any(isinstance(server, dict) and not str(server.get("url", "")).startswith(("http://", "https://")) for server in declared_servers):
            target = ""  # Relative declarations need confirmation of their API origin.
        if target:
            try:
                target = normalise_target(target)
            except ValueError:
                target = ""
        if item.get("target"):
            target = normalise_target(str(item["target"]))
        cid = contract_id or uuid.uuid4().hex
        digest = _hash(material)
        operations = [{**copy.deepcopy(op), "id": cid + "::" + op["id"], "local_id": op["id"], "contract_id": cid} for op in spec["operations"]]
        return {"id": cid, "title": spec["title"], "version": spec["api_version"], "source": source,
                "documentation_url": documentation_url, "hash": digest, "snapshot_hash": digest,
                "servers": metadata["server_choices"], "proposed_target": metadata["suggested_target"], "target": target,
                "target_review_required": not bool(target), "scope_review_required": False,
                "operation_count": len(operations), "operations": operations, "spec": spec,
                "unresolved_references": unresolved, "warnings": list(dict.fromkeys(warnings + spec["warnings"])),
                "errors": [], "config": {"examples": {}, "baselines": {}, "expectations": {}, "assertions": {},
                                          "allow_mutating": False, "operation_ids": [op["id"] for op in operations], "budget": None},
                "identity_assignment": None, "identity_override": None,
                "readiness": {"status": "unestablished", "reason": "Imported contracts have not established successful controls"},
                "control_contexts": {},
                "snapshots": {digest: {"hash": digest, "created_at": _now(), "source": source, "spec": spec,
                                        "material": material, "document_hash": _hash(spec["document"])}}}

    def import_contracts(self, workspace_id, items):
        if isinstance(items, str):
            items = [line.strip() for line in items.splitlines() if line.strip()]
        if not isinstance(items, list) or not 1 <= len(items) <= 50:
            raise ValueError("Import between 1 and 50 contracts at a time")
        with self._lock:
            self._load(workspace_id)  # Validate existence without holding a lock over I/O.
        contracts, errors = [], []
        for index, item in enumerate(items):
            try:
                contracts.append(self._import_one(item))
            except (ValueError, TypeError, KeyError, RecursionError) as exc:
                source = item if isinstance(item, str) else (item.get("url") or item.get("filename") or item.get("source_url") or "") if isinstance(item, dict) else ""
                errors.append({"index": index, "source": source, "error": str(exc)})
        with self._lock:
            # Concurrent identity/configuration updates must survive a slow
            # documentation fetch. Guards and cancellation remain responsive.
            workspace = self._load(workspace_id)
            workspace["contracts"].extend(self._safe(contract, workspace_id) for contract in contracts)
            workspace["import_errors"] = errors
            self._invalidate(workspace, "Contract imports changed the reviewed inventory")
            self._save(workspace)
            return self.get(workspace_id)

    def update_contract(self, workspace_id, contract_id, patch):
        with self._lock:
            if self._contract(self._load(workspace_id), contract_id).get("request_collection"):
                raise ValueError("Bruno definitions are separate from OpenAPI contracts. Edit the request draft or import a new definition snapshot; contract target/configuration replacement is unavailable.")
        replacement = None
        if any(key in patch for key in ("raw_spec", "raw", "document", "url")):
            with self._lock:
                source = self._contract(self._load(workspace_id), contract_id)["source"]
            replacement = self._import_one({"source_url": source, **patch}, contract_id=contract_id)
        with self._lock:
            workspace = self._load(workspace_id)
            contract = self._contract(workspace, contract_id)
            if replacement is not None:
                replacement["snapshots"] = {**contract["snapshots"], **replacement["snapshots"]}
                for key in ("identity_assignment", "identity_override"):
                    replacement[key] = contract.get(key)
                replacement["scope_review_required"] = bool(replacement["identity_assignment"] or replacement["identity_override"])
                contract.clear()
                contract.update(replacement)
            if "target" in patch:
                target = normalise_target(str(patch["target"]))
                if target != contract["target"]:
                    contract["scope_review_required"] = bool(contract.get("identity_assignment") or contract.get("identity_override"))
                contract["target"] = target
                contract["target_review_required"] = False
            if "config" in patch:
                changes = patch["config"]
                if not isinstance(changes, dict):
                    raise ValueError("Contract configuration must be an object")
                for key in ("examples", "baselines", "expectations", "assertions"):
                    if key in changes and not isinstance(changes[key], dict):
                        raise ValueError(f"Contract {key} must be keyed by operation")
                if "allow_mutating" in changes and not isinstance(changes["allow_mutating"], bool):
                    raise ValueError("Contract write authorization must be an explicit boolean")
                if "operation_ids" in changes:
                    valid_keys = {key for op in contract["operations"] for key in (op["id"], op["local_id"])}
                    if not isinstance(changes["operation_ids"], list) or any(key not in valid_keys for key in changes["operation_ids"]):
                        raise ValueError("Select operation keys belonging to this contract")
                contract["config"].update({key: self._safe(value, workspace_id) for key, value in changes.items()
                                           if key in contract["config"]})
                for key in ("baselines", "expectations", "assertions"):
                    if key in changes:
                        contexts = contract.setdefault("control_contexts", {}).setdefault(key, {})
                        for operation_key in changes[key]:
                            reviewed = patch.get("review_operation_ids")
                            if reviewed is None or operation_key in reviewed:
                                contexts[operation_key] = self._control_context(workspace, contract)
            self._invalidate(workspace, "Contract configuration or target changed", [contract_id])
            self._save(workspace)
            return self.get(workspace_id)

    def remove_contract(self, workspace_id, contract_id):
        with self._lock:
            workspace = self._load(workspace_id)
            contract = self._contract(workspace, contract_id)
            is_collection = contract.get("request_collection")
            workspace["request_collections" if is_collection else "contracts"].remove(contract)
            contract["removed_at"] = _now()
            workspace.setdefault("archived_request_collections" if is_collection else "archived_contracts", []).append(contract)
            self._invalidate(workspace, "A request collection was removed" if is_collection else "A contract was removed")
            self._save(workspace)
            return self.get(workspace_id)

    def set_profile(self, workspace_id, profile):
        with self._lock:
            workspace = self._load(workspace_id)
            pid = str(profile.get("id") or uuid.uuid4().hex)
            existing = next((p for p in workspace["profiles"] if p["id"] == pid), None)
            token = profile.get("token", profile.get("bearer_token"))
            if token is not None and (not isinstance(token, str) or not token.strip() or "\n" in token or "\r" in token):
                raise ValueError("Enter a non-empty bearer token without line breaks")
            if token is not None:
                token = token.removeprefix("Bearer ").strip()
                if not token or len(token) > 16384:
                    raise ValueError("Enter a bearer token between 1 and 16384 characters")
            if not existing:
                existing = {"id": pid, "name": str(profile.get("name") or "Bearer identity"), "kind": "bearer", "revision": 0}
                workspace["profiles"].append(existing)
            if "name" in profile:
                existing["name"] = str(profile["name"])
            persistence = profile.get("persistence", existing.get("persistence", "session"))
            if persistence not in {"session", "windows"}:
                raise ValueError("Choose session or windows credential persistence explicitly")
            previous_ref = existing.get("credential_ref")
            if token is None and persistence != existing.get("persistence", "session"):
                token = self._credential(workspace_id, existing)
                if token is None:
                    raise ValueError("Re-enter the bearer value before changing its persistence mode")
            if token is not None:
                existing["revision"] += 1
                reference = f"workspace:{workspace_id}:profile:{pid}:revision:{existing['revision']}"
                self.credentials.put(reference, token, mode=persistence)
                existing["credential_ref"] = reference
                existing["persistence"] = persistence
                self._secrets[(workspace_id, pid)] = token
                self._secret_revisions[(workspace_id, pid)] = existing["revision"]
            affected = [c["id"] for c in workspace["contracts"] if self._identity(workspace, c)["profile_id"] == pid]
            self._invalidate(workspace, "An identity profile changed; reviewed plans and readiness must be renewed", affected)
            self._save(workspace)
            if previous_ref and previous_ref != existing.get("credential_ref"):
                self.credentials.delete(previous_ref)
            return self.get(workspace_id)

    def assign_identity(self, workspace_id, contract_id, assignment):
        with self._lock:
            workspace = self._load(workspace_id)
            contract = self._contract(workspace, contract_id)
            if contract.get("request_collection"):
                operation_key = assignment.get("operation_key")
                operation = next((item for item in contract["operations"] if item["id"] == operation_key), None)
                if operation is None:
                    raise ValueError("Explicitly select the Bruno request receiving this identity")
                bindings = contract.setdefault("request_assignments", {})
                if assignment.get("remove") or assignment.get("profile_id") is None:
                    bindings.pop(operation_key, None)
                else:
                    pid = assignment["profile_id"]
                    if not any(profile["id"] == pid for profile in workspace["profiles"]):
                        raise ValueError("Identity profile not found")
                    scopes = assignment.get("allowed_scopes")
                    if not isinstance(scopes, list) or not scopes:
                        raise ValueError("Choose explicit allowed API origins/base paths")
                    scopes = list(dict.fromkeys(normalise_target(str(scope)) for scope in scopes))
                    if not url_in_scopes(operation["request_definition"]["request"]["url"], scopes):
                        raise ValueError("The selected request URL must fall inside the explicit identity scope")
                    bindings[operation_key] = {"profile_id": pid, "allowed_scopes": scopes, "source": "request-specific override"}
                self._invalidate(workspace, "Explicit request identity changed; no other request inherits it")
                self._save(workspace)
                return self.get(workspace_id)
            key = "identity_override" if assignment.get("override") else "identity_assignment"
            if assignment.get("remove") or assignment.get("profile_id") is None:
                contract[key] = None
            else:
                pid = str(assignment["profile_id"])
                if not any(p["id"] == pid for p in workspace["profiles"]):
                    raise ValueError("Identity profile not found")
                scopes = assignment.get("allowed_scopes")
                if not isinstance(scopes, list) or not scopes:
                    raise ValueError("Assign explicit allowed API origins/base paths")
                scopes = list(dict.fromkeys(normalise_target(str(scope)) for scope in scopes))
                if not contract.get("request_collection") and (not contract["target"] or not url_in_scopes(contract["target"] + "/", scopes)):
                    raise ValueError("The selected API target must fall inside an explicitly assigned scope")
                contract[key] = {"profile_id": pid, "allowed_scopes": scopes,
                                 "source": "contract-specific override" if assignment.get("override") else "shared profile"}
            if key == "identity_override" or not contract.get("identity_override"):
                contract["scope_review_required"] = False
            active = self._identity(workspace, contract)
            if active["profile_id"] and not contract.get("request_collection") and not url_in_scopes(contract["target"] + "/", active["allowed_scopes"]):
                contract["scope_review_required"] = True
            self._invalidate(workspace, "Identity assignment changed; no successful controls are inherited", [contract_id])
            self._save(workspace)
            return self.get(workspace_id)

    def _overlaps(self, workspace):
        rows = [(contract, operation) for contract in workspace["contracts"] for operation in contract["operations"]]
        decisions = {decision["overlap_id"]: decision for decision in workspace["decisions"]}
        endpoints = {}
        for contract, operation in rows:
            declared = normalise_target(contract["target"]) + operation["path"] if contract["target"] else ""
            effective, prepared = declared, ""
            example = self._setting(contract, "examples", operation)
            if declared and isinstance(example, dict) and example.get("url"):
                try:
                    built = build_request(contract["spec"], operation["local_id"], base_url=contract["target"])
                    built, _note = _apply_example(built, example, {})
                    _check_example_scope(built, contract["target"])
                    parts = urlsplit(discovery.check_url(built["url"]))
                    prepared = built["url"]
                    # Query parameters remain request semantics, while endpoint
                    # ownership is compared at the effective origin/path.
                    effective = normalise_target(urlunsplit((parts.scheme, parts.netloc, "", "", ""))) + parts.path
                except (ValueError, TypeError, KeyError):
                    pass  # The offline planner reports invalid/out-of-scope examples.
            endpoints[operation["id"]] = (declared, effective, prepared, _hash(example))
        results = []
        for index, (left, a) in enumerate(rows):
            for right, b in rows[index + 1:]:
                if left["id"] == right["id"] or a["method"] != b["method"]:
                    continue
                same_path = a["path"] == b["path"]
                declared_first, first, prepared_first, example_first = endpoints[a["id"]]
                declared_second, second, prepared_second, example_second = endpoints[b["id"]]
                same_origin = bool(first and second and discovery.origin(first) == discovery.origin(second))
                declared_origin = bool(declared_first and declared_second and discovery.origin(declared_first) == discovery.origin(declared_second))
                same_endpoint = bool((first and first == second) or (declared_first and declared_first == declared_second))
                if same_endpoint:
                    equivalent = operation_semantics(left["spec"], a) == operation_semantics(right["spec"], b)
                    kind = "identical-contract" if left["hash"] == right["hash"] else "same-operation" if equivalent else "conflicting-endpoint"
                    requires = True
                elif (same_origin and _templates_overlap(urlsplit(first).path, urlsplit(second).path)) or (declared_origin and _templates_overlap(urlsplit(declared_first).path, urlsplit(declared_second).path)):
                    kind, requires = "potential-template-overlap", True
                elif same_path:
                    kind, requires = "similar-path-different-target", False
                else:
                    continue
                identity = _hash([a["id"], b["id"], left["hash"], right["hash"], left["target"], right["target"],
                                  first, second, example_first, example_second, kind])[:24]
                results.append({"id": identity, "kind": kind, "operations": [a["id"], b["id"]],
                                "contract_ids": [left["id"], right["id"]], "endpoints": [first, second],
                                "declared_endpoints": [declared_first, declared_second], "prepared_urls": [prepared_first, prepared_second],
                                "reason": "Saved request examples change the effective endpoint; review their request and response semantics." if prepared_first or prepared_second else "",
                                "identical_contract": left["hash"] == right["hash"], "requires_review": requires,
                                "decision": decisions.get(identity)})
        return results

    def decide_overlap(self, workspace_id, decision):
        with self._lock:
            workspace = self._load(workspace_id)
            overlap = next((row for row in self._overlaps(workspace) if row["id"] == decision.get("overlap_id")), None)
            if not overlap:
                raise ValueError("Overlap not found; review the current contract snapshots and targets")
            action = decision.get("action")
            if action not in {"owner", "exclude", "separate"}:
                raise ValueError("Choose an owner, exclusions, or separate contract assessments")
            if action == "owner" and decision.get("owner") not in overlap["operations"]:
                raise ValueError("The owner must belong to this overlap")
            excluded = decision.get("excluded") or []
            if action == "exclude" and (not excluded or any(key not in overlap["operations"] for key in excluded)):
                raise ValueError("Select operations from this overlap to exclude")
            record = {"overlap_id": overlap["id"], "action": action, "owner": decision.get("owner"),
                      "excluded": excluded, "reviewed_at": _now()}
            workspace["decisions"] = [row for row in workspace["decisions"] if row["overlap_id"] != overlap["id"]] + [record]
            self._invalidate(workspace, "Overlap review changed")
            self._save(workspace)
            return self.get(workspace_id)

    @staticmethod
    def _setting(contract, key, operation):
        settings = contract["config"].get(key) or {}
        return settings.get(operation["id"], settings.get(operation["local_id"]))

    def _control_context(self, workspace, contract):
        identity = self._identity(workspace, contract)
        return {"snapshot_hash": contract["hash"], "target": contract["target"],
                "identity_ref": identity["profile_id"], "identity_revision": identity["revision"]}

    def plan(self, workspace_id, options=None):
        options = dict(options or {})
        with self._lock:
            workspace = self._load(workspace_id)
            budget = int(options.get("budget", 200))
            rate = float(options.get("requests_per_second", 2))
            if not 1 <= budget <= 100000 or not 0 < rate <= 1000:
                raise ValueError("Choose a budget of 1–100000 and a rate above 0 and at most 1000")
            options.update(budget=budget, requests_per_second=rate, profile=options.get("profile") or "readonly",
                           inventory=bool(options.get("inventory")))
            if options["profile"] not in PROFILES:
                raise ValueError("Choose a supported audit profile")
            concurrency = options.get("concurrency", PROFILES[options["profile"]]["concurrency"])
            if isinstance(concurrency, bool) or not isinstance(concurrency, int) or not 1 <= concurrency <= MAX_CONCURRENCY:
                raise ValueError(f"Choose a concurrency between 1 and {MAX_CONCURRENCY}")
            options["concurrency"] = concurrency
            if "allow_mutating" in options and not isinstance(options["allow_mutating"], bool):
                raise ValueError("Run write authorization must be an explicit boolean")
            selected = options.get("contract_ids")
            contracts = [c for c in workspace["contracts"] if selected is None or c["id"] in selected]
            blockers, operations = [], []
            def block(code, detail, cid=None):
                blockers.append({"code": code, "detail": detail, "contract_id": cid})
            for contract in contracts:
                cid, identity = contract["id"], self._identity(workspace, contract)
                if contract["target_review_required"] or not contract["target"]:
                    block("target-choice-required", "Choose an API target explicitly; documentation locations do not establish API scope", cid)
                if contract.get("scope_review_required"):
                    block("identity-scope-review-required", "The target changed; reassign identity scope explicitly", cid)
                if identity["profile_id"] and not identity["credential_available"]:
                    block("credential-unavailable", "Re-enter this identity's bearer value in this process before reviewing execution", cid)
                if identity["profile_id"] and contract["target"] and not url_in_scopes(contract["target"] + "/", identity["allowed_scopes"]):
                    block("identity-out-of-scope", "The target is outside this identity assignment", cid)
                control_context = self._control_context(workspace, contract)
                selected_ops = contract["config"].get("operation_ids", [op["id"] for op in contract["operations"]])
                for operation in contract["operations"]:
                    if operation["id"] not in selected_ops and operation["local_id"] not in selected_ops:
                        continue
                    for setting in ("baselines", "expectations", "assertions"):
                        controls = contract["config"].get(setting, {})
                        key = operation["id"] if operation["id"] in controls else operation["local_id"]
                        if controls.get(key) and contract.get("control_contexts", {}).get(setting, {}).get(key) != control_context:
                            block("control-scope-review-required", f"Review {operation['local_id']} {setting} for the current snapshot, target and identity before reusing them", cid)
                    per_limit = contract["config"].get("budget")
                    if per_limit is not None and (not isinstance(per_limit, int) or isinstance(per_limit, bool) or per_limit < 1):
                        raise ValueError("Per-contract budgets must be positive integers")
                    row = {"contract_id": cid, "operation_key": operation["id"], "operation_id": operation["local_id"],
                           "method": operation["method"], "path": operation["path"], "snapshot_hash": contract["hash"],
                           "base_url": contract["target"], "identity_ref": identity["profile_id"], "identity_revision": identity["revision"],
                           "identity_source": identity["source"], "allowed_scopes": identity["allowed_scopes"],
                           "example": self._setting(contract, "examples", operation),
                           "expectation": self._setting(contract, "expectations", operation),
                           "assertions": self._setting(contract, "assertions", operation),
                           "baseline": self._setting(contract, "baselines", operation),
                           "allow_mutating": bool(contract["config"].get("allow_mutating")) and bool(options.get("allow_mutating")),
                           "request_budget": per_limit, "semantics_hash": operation_semantics(contract["spec"], operation)}
                    if options["profile"] == "writes" and not row["allow_mutating"]:
                        block("write-authorization-required", "Authorize writes for this contract and the reviewed run; shared authentication grants no write permission", cid)
                    if operation["method"] not in SAFE_METHODS and not row["allow_mutating"]:
                        row["excluded"] = True
                        row["exclusion_reason"] = "write-authorization-required"
                    if contract["target"] and not row.get("excluded"):
                        try:
                            built = build_request(contract["spec"], operation["local_id"], base_url=contract["target"])
                            if row["example"]:
                                built, _note = _apply_example(built, row["example"], {})
                            row["built_request_hash"] = _hash({key: built.get(key) for key in ("method", "url", "body", "headers", "content_type", "has_body")})
                            row["engine_plan"] = audit_plan(contract["spec"], operation["local_id"],
                                                            base_url=contract["target"], profile=options["profile"],
                                                            allow_mutating=row["allow_mutating"], example=row["example"],
                                                            request_budget=per_limit, response_comparison=options.get("response_comparison"),
                                                            credential_names=options.get("credential_names") or ())
                            planned = row["engine_plan"]["test_plan"]
                            row["traffic_review"] = {
                                "baseline_requests": planned["baseline_requests"],
                                "schema_input_cases": planned["planned_requests"],
                                "conditional_families": sum(check.get("conditional", False) for check in planned["supplemental_checks"]),
                                "operation_request_ceiling": row["engine_plan"]["request_budget"],
                                "note": "Schema cases are not a total traffic estimate. Conditional checks may add requests; operation, contract and shared run budgets cap all dispatch."}
                        except (ValueError, TypeError, KeyError) as exc:
                            block("operation-plan-invalid", str(exc), cid)
                    operations.append(row)
            keys = {row["operation_key"] for row in operations}
            overlaps = [row for row in self._overlaps(workspace) if all(key in keys for key in row["operations"])]
            excluded = {row["operation_key"] for row in operations if row.get("excluded")}
            separate = set()
            for overlap in overlaps:
                decision = overlap["decision"]
                if overlap["requires_review"] and not decision:
                    block("overlap-review-required", f"Review {overlap['kind']} before execution")
                if not decision:
                    continue
                if decision["action"] == "owner":
                    excluded.update(key for key in overlap["operations"] if key != decision["owner"])
                elif decision["action"] == "exclude":
                    excluded.update(decision["excluded"])
                else:
                    separate.add(frozenset(overlap["operations"]))
            by_fingerprint = {}
            for row in operations:
                if row["operation_key"] in excluded:
                    row.update(excluded=True, exclusion_reason=row.get("exclusion_reason") or "overlap-exclusion")
                    continue
                fingerprint = _hash({key: value for key, value in row.items() if key not in
                                     {"contract_id", "operation_key", "snapshot_hash", "operation_id", "identity_source", "engine_plan", "traffic_review"}})
                row["execution_fingerprint"] = fingerprint
                prior = by_fingerprint.get(fingerprint)
                if prior and frozenset((prior, row["operation_key"])) in separate:
                    row["reuse_from"] = prior
                else:
                    by_fingerprint[fingerprint] = row["operation_key"]
            if not any(not row.get("excluded") for row in operations):
                block("no-operations", "Select at least one executable operation")
            plan = {"id": uuid.uuid4().hex, "workspace_id": workspace_id, "revision": workspace["revision"],
                    "created_at": _now(), "status": "reviewed", "ready": not blockers, "blockers": blockers,
                    "options": self._safe(options, workspace_id), "operations": operations,
                    "contracts": [{"id": c["id"], "title": c["title"], "target": c["target"], "hash": c["hash"],
                                   "identity": self._identity(workspace, c)} for c in contracts],
                    "overlaps": overlaps, "exclusions": sorted(excluded),
                    "traffic": {"inventory": bool(options["inventory"]), "endpoint_operations": sum(not r.get("excluded") and not r.get("reuse_from") for r in operations),
                                "contract_assessments": sum(not r.get("excluded") for r in operations), "shared_request_budget": budget,
                                "requests_per_second": rate, "concurrency": concurrency,
                                "operation_scheduling": "sequential; probes within the current operation share this concurrency limit"},
                    "prerequisites": ["Successful controls and permission expectations remain specific to contract, target, operation and identity.",
                                      "This offline plan sends no requests, acquires no tokens and replays no baselines."]}
            workspace["plans"].append(plan)
            self._save(workspace)
            return self._safe(plan, workspace_id)

    def request_context(self, workspace_id, contract_id, snapshot_hash, operation_key, *, require_credential=True):
        """Bind one ordinary request to persisted scope without dispatch or OAuth."""
        with self._lock:
            workspace = self._load(workspace_id)
            contract = self._contract(workspace, contract_id)
            if snapshot_hash != contract["hash"]:
                raise ValueError("The contract snapshot changed; reload and review this request")
            operation = next((op for op in contract["operations"] if op["id"] == operation_key), None)
            if operation is None:
                raise ValueError("The operation key does not belong to this contract snapshot")
            if contract.get("request_collection"):
                from .bruno import MARKER
                from .request_collections import execution_spec, safe_collection
                identity = self._identity(workspace, contract, operation_key)
                checked = safe_collection(contract, extra_secrets=[secret for (wid, _), secret in self._secrets.items() if wid == workspace_id])
                if checked["hash"] != snapshot_hash:
                    raise ValueError("The request definition snapshot changed after credential redaction; reload and review it")
                contract = checked
                operation = next(op for op in checked["operations"] if op["id"] == operation_key)
                definition = operation["request_definition"]
                if definition.get("can_prepare") is not True or MARKER in json.dumps(definition["request"], ensure_ascii=False):
                    raise ValueError("This definition cannot be sent faithfully: " + "; ".join(definition.get("blockers") or ["Review unsupported request features"]))
                target = operation["target"]
                warnings = list(definition.get("warnings") or [])
                if require_credential and identity["profile_id"] and (
                    not identity["credential_available"] or not url_in_scopes(definition["request"]["url"], identity["allowed_scopes"])):
                    raise ValueError("Explicitly configure an available identity within this request's allowed API scope")
                if require_credential and definition.get("authentication") and not identity["profile_id"] and identity["source"] != "request-specific no identity":
                    raise ValueError("This definition requires authentication. Explicitly map a local identity; imported credentials are never activated.")
                selected_profile = next((p for p in workspace["profiles"] if p["id"] == identity["profile_id"]), {})
                oauth_mapping = definition.get("oauth_client_credentials")
                mapped_oauth = (definition.get("authentication_mode") == "oauth2" and isinstance(oauth_mapping, dict)
                                and oauth_mapping.get("grant") == "client_credentials"
                                and selected_profile.get("kind") == "oauth-client-credentials")
                if require_credential and definition.get("authentication_mode") not in (None, "none", "bearer") and not mapped_oauth:
                    raise ValueError("This request uses authentication that the bearer-only workspace editor cannot reproduce. Use explicit advanced authentication mapping; no request was sent.")
                if require_credential and any(ref.get("header") and (
                    ref["header"].lower() != "authorization" or ref.get("scheme") != "bearer")
                    for ref in definition.get("authentication", [])):
                    raise ValueError("This credential header cannot be replaced by a bearer identity. Use explicit advanced authentication mapping; no request was sent.")
                identities = {"primary": {"headers": {"Authorization": "Bearer " + self._secrets[(workspace_id, identity["profile_id"])]}}} if require_credential and identity["profile_id"] else {}
                spec, local_id = execution_spec(operation)
                return {"spec": spec, "operation_id": local_id, "base_url": target,
                    "contract_id": contract_id, "operation_key": operation_key, "snapshot_hash": contract["hash"],
                    "identity_ref": identity["profile_id"], "identity_revision": identity["revision"],
                    "identity_source": identity["source"], "allowed_scopes": identity["allowed_scopes"],
                    "identities": identities, "scope_guard": self._scope_guard(workspace_id, contract, identity, operation_key),
                    "allow_mutating": False, "warnings": warnings, "request_definition": copy.deepcopy(definition),
                    "source_kind": "bruno-collection", "response_contract": False}
            if contract.get("target_review_required") or not contract.get("target"):
                raise ValueError("Choose an explicit API target before preparing this request")
            identity = self._identity(workspace, contract)
            warnings = []
            if contract.get("scope_review_required"):
                warnings.append("The target changed; explicitly review the identity scope before sending")
            if identity["profile_id"] and not url_in_scopes(contract["target"] + "/", identity["allowed_scopes"]):
                warnings.append("The target is outside the assigned identity scope")
            if identity["profile_id"] and not identity["credential_available"]:
                warnings.append("The assigned credential is unavailable; re-enter or unlock it before sending")
            if require_credential and warnings:
                raise ValueError(". ".join(warnings))
            identities = {}
            if require_credential and identity["profile_id"]:
                identities = {"primary": {"headers": {"Authorization": "Bearer " + self._secrets[(workspace_id, identity["profile_id"])]}}}
            return {"spec": copy.deepcopy(contract["spec"]), "operation_id": operation["local_id"],
                    "base_url": contract["target"], "contract_id": contract_id, "operation_key": operation_key,
                    "snapshot_hash": contract["hash"], "identity_ref": identity["profile_id"],
                    "identity_revision": identity["revision"], "identity_source": identity["source"],
                    "allowed_scopes": identity["allowed_scopes"], "identities": identities,
                    "scope_guard": self._scope_guard(workspace_id, contract, identity),
                    "allow_mutating": bool(contract["config"].get("allow_mutating")), "warnings": warnings}

    def execution_config(self, workspace_id, plan_id):
        with self._lock:
            workspace = self._load(workspace_id)
            plan = next((p for p in workspace["plans"] if p["id"] == plan_id), None)
            if not plan or plan["status"] != "reviewed" or plan["revision"] != workspace["revision"]:
                raise ValueError("This plan is stale; review the current contracts, targets and identities again")
            if not plan["ready"]:
                raise ValueError("Resolve every plan prerequisite before execution")
            operations = copy.deepcopy(plan["operations"])
            for row in operations:
                contract = self._contract(workspace, row["contract_id"])
                identity = self._identity(workspace, contract)
                if identity["profile_id"] and not identity["credential_available"]:
                    raise ValueError("Identity credential is unavailable; enter it and review a new plan")
                row["spec"] = copy.deepcopy(contract["spec"])
                row["identities"] = {}
                if identity["profile_id"] and not row.get("excluded"):
                    row["identities"] = {"primary": {"headers": {"Authorization": "Bearer " + self._secrets[(workspace_id, identity["profile_id"])]}}}
                row["scope_guard"] = self._scope_guard(workspace_id, contract, identity)
            options = plan["options"]
            return {**options, "operations": operations, "allow_mutating": bool(options.get("allow_mutating")),
                    "per_contract_limits": {c["id"]: c["config"]["budget"] for c in workspace["contracts"] if c["config"].get("budget")},
                    "workspace": {"id": workspace_id, "title": workspace["title"], "revision": workspace["revision"],
                                  "contracts": copy.deepcopy(plan["contracts"]),
                                  "assignments": {c["id"]: self._identity(workspace, c) for c in workspace["contracts"]},
                                  "overlap_decisions": copy.deepcopy(workspace["decisions"]), "reviewed_plan": copy.deepcopy(plan)},
                    "context": {"title": workspace["title"], "workspace_id": workspace_id, "base_url": "Multiple reviewed API targets"}}

    def _scope_guard(self, workspace_id, contract, identity, operation_key=None):
        """Fail closed on changed assignments/credentials/configuration during a run."""
        contract_id = contract["id"]
        def state(current, active):
            return _hash({"hash": current["hash"], "target": current["target"], "config": current["config"],
                          "scope_review_required": current.get("scope_review_required"),
                          "identity": {key: active.get(key) for key in ("profile_id", "revision", "allowed_scopes", "source", "credential_available")}})
        expected = state(contract, identity)
        def guard():
            with self._lock:
                try:
                    workspace = self._load(workspace_id)
                    current = self._contract(workspace, contract_id)
                    return expected == state(current, self._identity(workspace, current, operation_key))
                except (ValueError, KeyError):
                    return False
        return guard

    def attach_run(self, workspace_id, run_id):
        with self._lock:
            workspace = self._load(workspace_id)
            if run_id not in workspace["runs"]:
                workspace["runs"].append(run_id)
            self._save(workspace)
            return self.get(workspace_id)

    def export(self, workspace_id):
        workspace = self.get(workspace_id)
        return {"format": FORMAT, "version": FORMAT_VERSION, "workspace": workspace,
                "saved_runs": copy.deepcopy(workspace.get("saved_runs", []))}

    def restore(self, payload):
        if not isinstance(payload, dict) or payload.get("format") != FORMAT or payload.get("version") != FORMAT_VERSION:
            raise ValueError("Expected a supported Namazu workspace export; single-contract reports remain readable in the saved report importer")
        workspace = copy.deepcopy(payload.get("workspace"))
        if not isinstance(workspace, dict) or not isinstance(workspace.get("contracts"), list):
            raise ValueError("Workspace export has no contract inventory")
        with self._lock:
            workspace["id"] = uuid.uuid4().hex
            workspace.setdefault("plans", [])
            workspace.setdefault("archived_contracts", [])
            workspace.setdefault("profiles", [])
            workspace.setdefault("decisions", [])
            workspace.setdefault("runs", [])
            workspace["historical_run_ids"] = list(dict.fromkeys(workspace.get("historical_run_ids", []) + workspace["runs"]))
            workspace["runs"] = []
            workspace.setdefault("import_errors", [])
            from .request_collections import restore as restore_collection
            collections = workspace.get("request_collections", [])
            if not isinstance(collections, list) or len(collections) > 100:
                raise ValueError("Invalid request collection inventory")
            workspace["request_collections"] = [restore_collection(item) for item in collections]
            workspace.setdefault("revision", 0)
            workspace["saved_runs"] = [sanitise_saved_audit(run) for run in payload.get("saved_runs", workspace.get("saved_runs", []))]
            ids = set()
            for contract in workspace["contracts"]:
                if not isinstance(contract, dict) or not contract.get("id") or contract["id"] in ids:
                    raise ValueError("Workspace contract identities must be unique")
                ids.add(contract["id"])
                # Reparse supplied documents. Never trust executable operation data in exports.
                spec = parse_spec(contract["spec"]["document"], contract["spec"].get("source_url", ""))
                contract["spec"] = spec
                contract["operations"] = [{**op, "id": contract["id"] + "::" + op["id"], "local_id": op["id"], "contract_id": contract["id"]} for op in spec["operations"]]
                if contract.get("target"):
                    contract["target"] = normalise_target(contract["target"])
                contract.pop("identity", None)
                contract.setdefault("control_contexts", {})
                snapshots = contract.setdefault("snapshots", {})
                snapshot = snapshots.get(contract.get("hash"), {})
                material = snapshot.get("material")
                verified = (isinstance(material, dict) and _hash(material) == contract.get("hash")
                            and snapshot.get("document_hash") == _hash(spec["document"])
                            and isinstance(snapshot.get("spec"), dict)
                            and _hash(snapshot["spec"].get("document")) == _hash(spec["document"]))
                if verified:
                    try:
                        # A checksum of supplied material is insufficient unless
                        # that material actually derives the executable document.
                        # Rebuild only from retained, explicitly supplied inputs;
                        # no reference fetch or filesystem lookup is permitted.
                        source = str(snapshot.get("source") or contract.get("source") or "openapi.json")
                        rebuilt, _unresolved, _material = _bundle(material["document"], source, material.get("dependencies") or {})
                        parsed = parse_spec(rebuilt, source if source.startswith(("http://", "https://")) else "")
                        verified = _hash(parsed["document"]) == _hash(spec["document"])
                    except (ValueError, TypeError, KeyError, RecursionError):
                        verified = False
                if not verified:
                    # Historical hashes are claims about the original evidence. Keep
                    # them, but bind new execution to exactly the parsed document.
                    material = {"document": spec["document"], "dependencies": {}}
                    digest = _hash(material)
                    contract["recorded_hash"] = contract.get("hash")
                    contract["hash"] = contract["snapshot_hash"] = digest
                    contract.setdefault("warnings", []).append("Imported snapshot integrity could not be verified; historical hashes are preserved and current execution uses a freshly hashed document.")
                    snapshots[digest] = {"hash": digest, "created_at": _now(), "source": contract.get("source", ""),
                                         "spec": spec, "material": material, "document_hash": _hash(spec["document"])}
            collection_ids = [item["id"] for item in workspace["request_collections"]]
            if len(set(collection_ids)) != len(collection_ids) or ids.intersection(collection_ids):
                raise ValueError("Request collection identities must remain unique in a workspace")
            for profile in workspace["profiles"]:
                for key in list(profile):
                    if key not in {"id", "name", "kind", "revision", "oauth_config"}:
                        del profile[key]
                if profile.get("kind") == "oauth-client-credentials":
                    from .identity_profiles import _config
                    profile["oauth_config"] = _config({**profile.get("oauth_config", {}), "name": profile.get("name", "Identity")})
            self._invalidate(workspace, "Restored workspaces require fresh identity values and plan review; historical evidence remains preserved", ids)
            self._save(workspace)
            return self.get(workspace["id"])


_SERVICE: WorkspaceService | None = None
_SERVICE_LOCK = threading.Lock()


def service() -> WorkspaceService:
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is None:
            _SERVICE = WorkspaceService()
        return _SERVICE


def set_service(instance: WorkspaceService | None):
    global _SERVICE
    with _SERVICE_LOCK:
        _SERVICE = instance
