"""One explicit workbench exchange, with durable receipts and no automatic replay."""
from __future__ import annotations

import copy
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx

from . import workspaces
from .audit.model import CREDENTIAL_QUERY, REDACTED_HEADERS
from .audit.run_store import default_db_path
from .audit.workspace_execution import ScopedClient, in_scope, operation_context
from .discovery import Connection, check_headers, check_url
from .runner import (
    credential_names_for,
    execute_request,
    normalize_spec,
    redact_evidence,
)
from .spec import build_request

ACTIVE = {"pending", "running", "stopping"}


def now():
    return datetime.now(timezone.utc).isoformat()


def prepare(payload, *, dispatch=False):
    """Resolve only persisted contract/identity references; never trust client spec."""
    row = workspaces.service().request_context(
        payload["workspace_id"], payload["contract_id"], payload["snapshot_hash"],
        payload["operation_key"], require_credential=dispatch)
    parsed = normalize_spec(row["spec"])
    operation = next(op for op in parsed["operations"] if op["id"] == row["operation_id"])
    draft = payload.get("request") or {}
    names = credential_names_for(parsed)
    headers = check_headers(draft.get("headers") or {})
    if any(key.lower() in REDACTED_HEADERS | names for key in headers):
        raise ValueError("Store credentials in an identity profile and explicitly assign it to this contract.")
    options = {"base_url": row["base_url"], "headers": headers,
               "parameters": draft.get("parameters") or {}}
    if "body" in draft:
        options["body"] = draft["body"]
    if draft.get("content_type"):
        options["content_type"] = draft["content_type"]
    definition = row.get("request_definition")
    if definition:
        original = definition["request"]
        body = draft.get("body", original.get("body"))
        media = draft.get("content_type") or original.get("content_type") or "application/json"
        if "body" not in draft and original.get("body_mode") == "json" and isinstance(body, str):
            body = json.loads(body)
        built = {"method": original["method"], "url": draft.get("url") or original["url"],
                 "headers": headers if "headers" in draft else check_headers(original.get("headers") or {}),
                 "body": body, "has_body": "body" in draft or bool(original.get("has_body")),
                 "content_type": media, "warnings": ["Bruno request definition: no authoritative response contract is attached."],
                 "definition_only": True, "raw_form_body": isinstance(body, str) and "x-www-form-urlencoded" in media,
                 "request_validation": {"valid": None, "errors": [], "warnings": ["No request schema is declared by this collection."]}}
    else:
        built = build_request(parsed, row["operation_id"], **options)
    if definition and any(key.lower() in REDACTED_HEADERS | names for key in built["headers"]):
        raise ValueError("Imported credential headers cannot be sent directly. Explicitly assign a supported identity profile.")
    if not definition and not draft.get("url"):
        # The request editor must not turn an undocumented resource identifier
        # into a plausible ID. Retain a visible placeholder until supplied.
        for param in operation.get("parameters", []):
            if param.get("in") == "path" and "path." + param["name"] not in options["parameters"] \
                    and not any(key in param for key in ("example", "examples")) \
                    and not any(key in (param.get("schema") or {}) for key in ("example", "examples", "default", "enum")):
                options["parameters"]["path." + param["name"]] = "{" + param["name"] + "}"
        built = build_request(parsed, row["operation_id"], **options)
        built["url"] = built["url"].replace("%7B", "{").replace("%7D", "}")
    elif draft.get("url"):
        built["url"] = str(draft["url"])
    built["method"] = str(draft.get("method") or built["method"]).upper()
    if built["method"] not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}:
        raise ValueError("Choose a supported HTTP method.")
    check_url(built["url"])
    if not in_scope(built["url"], row["base_url"]):
        raise ValueError("The request target changed. Review the contract target and identity scope before sending.")
    if any(CREDENTIAL_QUERY.match(key) or key.lower() in names for key, _ in parse_qsl(urlsplit(built["url"]).query)):
        raise ValueError("Credentials in URL parameters are not saved or sent by the workspace editor; use an assigned identity.")
    base_path = urlsplit(row["base_url"]).path.rstrip("/")
    endpoint = base_path + operation["path"]
    pattern = re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(endpoint))
    built["contract_match"] = not definition and built["method"] == operation["method"] and bool(
        re.fullmatch(pattern, urlsplit(built["url"]).path))
    context = operation_context(row, payload["workspace_id"])
    if definition:
        context.update(source_kind="bruno-collection", response_contract=False, source_ref=definition["source_ref"])
    context["environment_id"] = payload.get("environment_id")
    if dispatch:
        if re.search(r"\{|\}|%7b|%7d", built["url"], re.I):
            raise ValueError("Supply the actual path parameters before sending. Generated placeholders are not resource IDs.")
        if built["method"] not in {"GET", "HEAD", "OPTIONS"} and not payload.get("allow_mutating"):
            raise ValueError("Explicitly authorize this ordinary request's possible writes before sending.")
        if row["scope_guard"]() is False:
            raise ValueError("Contract or identity changed; reload and review this request.")
        identity = (row.get("identities") or {}).get("primary") or {}
        built["headers"].update(identity.get("headers") or {})
    safe = redact_evidence(built, sources=[built], credential_names=names)
    return row, built, {"request": safe, "context": context, "warnings": (built.get("warnings") or []) + row.get("warnings", []),
                        "identity": {"reference": row.get("identity_ref"), "source": row.get("identity_source")}}


class _Cancelled(Exception):
    pass


class RequestManager:
    def __init__(self, path=None, *, client_factory=None):
        self.path = Path(path) if path else default_db_path().with_name("requests.db")
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        if self._db.execute("PRAGMA user_version").fetchone()[0] > 1:
            self._db.close()
            raise ValueError("This request history was written by a newer Namazu version. Use that version or restore a backup.")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, created TEXT, data TEXT NOT NULL)")
        self._db.execute("PRAGMA user_version=1")
        self._db.commit()
        self._tasks = {}
        self._volatile = {}
        self.client_factory = client_factory
        # Only startup performs recovery. No worker or token is recreated.
        for record in self.list():
            if record["status"] in ACTIVE:
                record.update(status="interrupted", in_flight=False, finished_at=now(),
                              error="Application ended before the outcome was retained. This request was not replayed.")
                self._save(record)

    def _save(self, record):
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO requests VALUES (?,?,?)", (
                record["request_id"], record["created_at"], json.dumps(record, ensure_ascii=False, allow_nan=False)))

    def get(self, rid):
        with self._lock:
            if rid in self._volatile:
                return copy.deepcopy(self._volatile[rid])
            item = self._db.execute("SELECT data FROM requests WHERE id=?", (rid,)).fetchone()
            if not item:
                raise ValueError("Request history entry not found.")
            return json.loads(item[0])

    def list(self, limit=200, *, summaries=False):
        with self._lock:
            projection = "json_remove(data, '$.result', '$.contract_snapshot', '$.request.body')" if summaries else "data"
            return [json.loads(row[0]) for row in self._db.execute(
                f"SELECT {projection} FROM requests ORDER BY created DESC LIMIT ?", (limit,)).fetchall()]

    def active_count(self):
        with self._lock:
            return sum(thread.is_alive() for _, thread in self._tasks.values())

    def start(self, payload):
        row, built, preview = prepare(payload, dispatch=True)
        connection_options = payload.get("connection") or {}
        accepted = {"verify_tls", "proxy", "ca_bundle", "client_cert", "client_key", "client_key_password", "user_agent", "quiet"}
        if set(connection_options) - accepted:
            raise ValueError("Unsupported connection option.")
        connection = Connection.build(**connection_options)
        connection.validate()
        with self._lock:
            if self.active_count() >= 16:
                raise ValueError("Wait for an in-flight request before starting another (16 maximum).")
            rid = uuid.uuid4().hex
            record = {"request_id": rid, "status": "pending", "created_at": now(),
                      "context": preview["context"], "request": preview["request"],
                      "contract_snapshot": redact_evidence(copy.deepcopy(row["spec"])),
                      "requests_sent": 0, "in_flight": False, "cancellation_requested": False,
                      "provenance": {"kind": "ordinary-request", "automatically_replayed": False}}
            self._save(record)  # A failed write prevents dispatch.
            stop = threading.Event()
            thread = threading.Thread(target=self._execute, args=(rid, row, built, payload, connection, stop),
                                      daemon=True, name="namazu-request-" + rid[:8])
            self._tasks[rid] = stop, thread
            thread.start()
            return record

    def cancel(self, rid):
        with self._lock:
            record = self.get(rid)
            task = self._tasks.get(rid)
            if task and task[1].is_alive():
                task[0].set()
                record.update(cancellation_requested=True, status="stopping")
                record["note"] = "No new request will start. An already dispatched exchange is retained when it settles."
                self._save(record)
            return record

    def stop_all(self):
        with self._lock:
            for rid in list(self._tasks):
                self.cancel(rid)

    def _execute(self, rid, row, built, payload, connection, stop):
        manager = self
        names = credential_names_for(row["spec"])
        sources = [built]

        class ReceiptClient(ScopedClient):
            def send(self, request, **kwargs):
                # A slow workspace/vault read must not prevent Cancel from
                # setting its signal. Recheck it after the scope guard returns.
                self.check_request_scope(str(request.url), request.headers)
                with manager._lock:
                    if stop.is_set():
                        raise _Cancelled()
                    current = manager.get(rid)
                    current.update(status="running", requests_sent=1, in_flight=True)
                    manager._save(current)
                return super().send(request, **kwargs)

        try:
            raw = self.client_factory() if self.client_factory else connection.open()
            with raw as client:
                guarded = ReceiptClient(client, row["base_url"], row.get("allowed_scopes") or [], names, row["scope_guard"])
                result = execute_request(row["spec"], row["operation_id"], prepared_request=built,
                                         client=guarded, connection=connection,
                                         timeout=float(payload.get("timeout", 15)),
                                         expectation=(payload.get("request") or {}).get("assertions") or {},
                                         allow_mutating=bool(payload.get("allow_mutating")))
            result = redact_evidence(result, sources=sources, credential_names=names)
            with self._lock:
                record = self.get(rid)
                record.update(result=result, status="cancelled" if stop.is_set() else "completed",
                              in_flight=False, finished_at=now())
                self._save(record)
        except Exception as exc:
            with self._lock:
                record = self.get(rid)
                message = "Request cancelled before dispatch." if isinstance(exc, _Cancelled) else (
                    "Request timed out; target handling remains unknown." if isinstance(exc, httpx.TimeoutException) else
                    "Request could not complete: " + type(exc).__name__ + ". Review target, identity scope and connection settings.")
                record.update(status="cancelled" if stop.is_set() else "failed", in_flight=False,
                              error=message, finished_at=now())
                try:
                    self._save(record)
                except (OSError, sqlite3.Error):
                    # Keep captured evidence visible even when the disk fails
                    # after dispatch. The prior durable receipt remains honest
                    # on restart, when it becomes interrupted/unknown.
                    if "result" in locals():
                        record["result"] = result
                    record["persistence_error"] = "Evidence could not be saved. It remains available in this window; export it before closing. Check disk space and permissions."
                    self._volatile[rid] = copy.deepcopy(record)
        finally:
            with self._lock:
                self._tasks.pop(rid, None)


_manager = None
_manager_lock = threading.Lock()


def manager():
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = RequestManager()
        return _manager


def set_manager(value):
    global _manager
    with _manager_lock:
        _manager = value
