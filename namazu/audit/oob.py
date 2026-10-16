"""Explicit callback payloads and offline Interactsh JSONL correlation.

No client registration, polling, DNS lookup, token acquisition or dispatch is
performed here. A payload is a draft value; ordinary requests retain their own
scope, write consent and cancellation. Imported callbacks are observations,
never automatic vulnerability or server-side attribution claims.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ..discovery import check_url
from ..runner import credential_names_for
from ..spec import MAX_DOCUMENT_BYTES, _bounded_json
from .model import CREDENTIAL_QUERY, REDACTED_HEADERS
from .run_store import default_db_path
from .workspace_execution import operation_context

FORMAT = "namazu-oob-evidence"
VERSION = 1
CONTEXT_KEYS = ("workspace_id", "contract_id", "operation_key", "snapshot_hash", "target", "identity_ref", "identity_revision", "identity_source")
SOURCES = ["https://github.com/projectdiscovery/interactsh",
           "https://github.com/projectdiscovery/interactsh/blob/main/pkg/server/server.go",
           "https://github.com/projectdiscovery/interactsh/blob/main/pkg/server/http_server.go"]
LIMITATIONS = [
    "An imported callback is user-supplied evidence, not an authenticated sensor result or demonstrated vulnerability.",
    "DNS may reflect a resolver, previewer or scanner. HTTP may reflect an intermediary. The initiating component and security impact require independent evidence.",
    "Receipt links show where a payload was submitted. They do not prove the target caused an imported interaction.",
    "No callback observed does not establish safety: collection, timing, protocol support and network policy may differ.",
    "This workflow neither starts nor polls Interactsh. Use an explicitly authorized session host and import its JSON Lines output.",
]


def _now():
    return datetime.now(timezone.utc)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def callback_base(value):
    parts = urlsplit(check_url(str(value)))
    host = parts.hostname.lower().rstrip(".")
    if parts.path not in {"", "/"} or parts.query or parts.fragment or len(host) > 190:
        raise ValueError("Use only the explicitly authorized callback origin, without a path, query or fragment.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Use an explicit callback session hostname; per-case DNS labels cannot be appended to an IP address.")
    if "." not in host or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise ValueError("Use an explicit DNS callback session hostname.")
    authority = host + (":" + str(parts.port) if parts.port else "")
    return urlunsplit((parts.scheme, authority, "", "", ""))


def _field(value, credential_names=()):
    if not isinstance(value, dict) or set(value) - {"location", "pointer", "name"}:
        raise ValueError("Choose one body pointer, query name or noncredential header for this callback case.")
    location = value.get("location")
    name = value.get("pointer") if location == "body" else value.get("name")
    if location not in {"body", "query", "header"} or not isinstance(name, str) or not name or len(name) > 1024 or any(ord(char) < 32 for char in name):
        raise ValueError("Choose one bounded body pointer, query name or header name.")
    if location == "body" and (not name.startswith("/") or re.search(r"~(?![01])", name)):
        raise ValueError("Body fields use an explicit JSON pointer such as /callbackUrl.")
    tokens = name.split("/") if location == "body" else [name]
    for token in tokens:
        token = token.replace("~1", "/").replace("~0", "~").lower()
        if token in {"__proto__", "prototype", "constructor"} or token in REDACTED_HEADERS | set(credential_names) or CREDENTIAL_QUERY.match(token):
            raise ValueError("Credential fields and structural object properties cannot carry callback probes.")
    if location == "header" and (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or name.lower() in {"host", "content-length", "transfer-encoding", "connection"}):
        raise ValueError("Choose a noncredential application header, not a transport-control header.")
    return {"location": location, "pointer" if location == "body" else "name": name}


def field_value(request, field):
    """Read one exact selected input, without searching unrelated text for hits."""
    location = field["location"]
    if location == "query":
        values = [value for name, value in parse_qsl(urlsplit(request.get("url", "")).query) if name == field["name"]]
        return values[0] if len(values) == 1 else None
    if location == "header":
        return next((value for name, value in request.get("headers", {}).items() if name.lower() == field["name"].lower()), None)
    value = request.get("body")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    for token in field["pointer"].split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            return None
    return value


def _event_matches(event, case):
    # Interactsh's normal full-id includes labels through its session ID but
    # omits the server domain. A bare unique-id identifies the session only;
    # accepting it would assign every event to every case in that session.
    full = str(event.get("full-id", "")).lower().rstrip(".")
    if full in {case["callback_host"], case["correlation_full_id"]}:
        return True
    if full:
        # Do not override an explicitly different case/session identifier with
        # matching text elsewhere in a supplied event.
        return False
    raw = str(event.get("raw-request", ""))
    host = re.search(r"(?im)^Host:\s*([^\s]+)\s*$", raw)
    if host:
        try:
            parsed = urlsplit("http://" + host[1]).hostname
        except ValueError:
            parsed = None
        if parsed and parsed.lower().rstrip(".") == case["callback_host"]:
            return True
    # DNS raw questions are authoritative only as imported text, still with an
    # exact hostname boundary. The marker in an HTTP body/response is no match.
    return event.get("protocol", "").lower() == "dns" and bool(re.search(
        r"(?im)^;?\s*" + re.escape(case["callback_host"]) + r"\.?\s+(?:IN\s+)?(?:A|AAAA|TXT|MX|NS|CNAME|SOA)\b", raw))


class OOBService:
    def __init__(self, path=None, *, workspace_service=None, request_manager=None, clock=None):
        self.path = Path(path) if path else default_db_path().with_name("oob.db")
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        if self._db.execute("PRAGMA user_version").fetchone()[0] not in (0, VERSION):
            self._db.close()
            raise ValueError("OOB evidence uses an unsupported database version; the original is preserved.")
        with self._db:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, workspace_id TEXT, created TEXT, body TEXT NOT NULL)")
            self._db.execute("PRAGMA user_version=1")
        self.workspace_service = workspace_service
        self.request_manager = request_manager
        self.clock = clock or _now

    def _workspaces(self):
        if self.workspace_service is not None:
            return self.workspace_service
        from ..workspaces import service
        return service()

    def _requests(self):
        if self.request_manager is not None:
            return self.request_manager
        from ..desktop_requests import manager
        return manager()

    def _save(self, case):
        with self._db:
            self._db.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?)", (
                case["id"], case["context"].get("workspace_id"), case["created_at"], json.dumps(case, ensure_ascii=False, allow_nan=False)))

    def _load(self, case_id):
        row = self._db.execute("SELECT body FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise ValueError("OOB case not found.")
        return json.loads(row[0])

    def create(self, payload):
        if payload.get("callback_scope_confirmed") is not True:
            raise ValueError("Explicitly confirm that this callback session origin is authorized before preparing a payload.")
        source = self._workspaces().request_context(payload["workspace_id"], payload["contract_id"], payload["snapshot_hash"],
                                                    payload["operation_key"], require_credential=False)
        field = _field(payload.get("field"), credential_names_for(source["spec"]))
        kind = payload.get("kind", "url-fetch")
        if kind not in {"url-fetch", "blind-injection", "xxe", "other"}:
            raise ValueError("Choose a supported callback case label.")
        base = callback_base(payload.get("callback_base", ""))
        ttl = payload.get("ttl_seconds", 86400)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= 604800:
            raise ValueError("Choose a correlation window between 60 seconds and seven days.")
        now = self.clock()
        marker = "n-" + secrets.token_hex(16)
        parts = urlsplit(base)
        host = marker + "." + parts.hostname
        authority = host + (":" + str(parts.port) if parts.port else "")
        case = {"id": uuid.uuid4().hex, "created_at": now.isoformat(), "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
                "context": operation_context(source, payload["workspace_id"]), "kind": kind, "field": field,
                "assignment_scopes": copy.deepcopy(source.get("allowed_scopes") or []),
                "callback_base": base, "callback_scope_confirmed": True, "callback_host": host,
                "correlation_full_id": marker + "." + parts.hostname.split(".")[0], "marker": marker,
                "payload": urlunsplit((parts.scheme, authority, "/namazu/" + marker, "", "")),
                "status": "prepared", "historical": False, "retired": False, "requests_sent": 0,
                "receipts": [], "interactions": [], "imports": [], "unmatched_interactions": [],
                "limitations": LIMITATIONS, "references": SOURCES,
                "execution": {"automatic_dispatch": False, "automatic_polling": False, "write_authorized": False,
                              "required_action": "Insert the payload into the selected request field, then review and explicitly Send using the existing request workflow."}}
        with self._lock:
            if self._db.execute("SELECT count(*) FROM cases").fetchone()[0] >= 2000:
                raise ValueError("OOB evidence storage contains 2,000 cases; use a separate state directory or retain an export before creating more.")
            self._save(case)
        return self.get(case["id"])

    def get(self, case_id):
        with self._lock:
            case = self._load(case_id)
        current = False
        if not case.get("historical"):
            try:
                held = case["context"]
                source = self._workspaces().request_context(held["workspace_id"], held["contract_id"], held["snapshot_hash"], held["operation_key"], require_credential=False)
                actual = operation_context(source, held["workspace_id"])
                current = (all(actual.get(key) == held.get(key) for key in CONTEXT_KEYS)
                           and sorted(source.get("allowed_scopes") or []) == sorted(case.get("assignment_scopes") or []))
            except (ValueError, KeyError):
                pass
        case["context_current"] = current
        case["can_use_payload"] = current and not case["retired"] and (_timestamp(case["expires_at"]) or self.clock()) > self.clock()
        case["accounting"] = {"linked_existing_attempts": len(case["receipts"]), "imported_interactions": len(case["interactions"]),
                              "unmatched_interactions": len(case["unmatched_interactions"]), "new_target_requests": 0,
                              "demonstrated_vulnerabilities": 0}
        return case

    def list(self, workspace_id=None):
        with self._lock:
            rows = self._db.execute("SELECT id FROM cases WHERE (? IS NULL OR workspace_id=?) ORDER BY created DESC LIMIT 500", (workspace_id, workspace_id)).fetchall()
        return [self.get(row[0]) for row in rows]

    def attach_receipt(self, case_id, request_id):
        receipt = self._requests().get(request_id)
        with self._lock:
            case = self._load(case_id)
            if case.get("historical"):
                raise ValueError("Imported historical cases cannot acquire new dispatch links. Prepare a new case.")
            if any(receipt.get("context", {}).get(key) != case["context"].get(key) for key in CONTEXT_KEYS):
                raise ValueError("The request receipt belongs to a different contract, target, snapshot or identity revision.")
            if receipt.get("requests_sent") != 1 or field_value(receipt.get("request", {}), case["field"]) != case["payload"]:
                raise ValueError("Link a dispatched receipt containing this exact payload in the selected field.")
            if not any(row["request_id"] == request_id for row in case["receipts"]):
                case["receipts"].append({"request_id": request_id, "evidence_ref": "/api/desktop/requests/" + request_id,
                                         "created_at": receipt.get("created_at"), "context": case["context"],
                                         "requests_sent": 1, "status_at_link": receipt.get("status"),
                                         "request_hash": _hash(receipt["request"]), "existing_attempt": True})
            case["status"] = "callback-observed" if case["interactions"] else "payload-submitted"
            self._save(case)
        return self.get(case_id)

    def import_interactions(self, case_id, jsonl, source_name="Interactsh JSONL"):
        if not isinstance(jsonl, str) or len(jsonl.encode()) > MAX_DOCUMENT_BYTES:
            raise ValueError("Import at most 8 MiB of Interactsh JSON Lines.")
        lines = jsonl.splitlines()
        if len(lines) > 1000:
            raise ValueError("Import at most 1,000 interaction lines at once.")
        source_name = str(source_name)[:200]
        records, errors = [], []
        for index, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                event = _bounded_json(json.loads(line))
                if len(line.encode()) > 65536 or not isinstance(event, dict) or not isinstance(event.get("protocol"), str):
                    raise ValueError("Invalid interaction")
                records.append((index, event))
            except (ValueError, RecursionError):
                errors.append({"line": index, "error": "Invalid or oversized interaction JSON; original text was not retained."})
        source_hash = hashlib.sha256(jsonl.encode()).hexdigest()
        with self._lock:
            case = self._load(case_id)
            if case.get("historical"):
                raise ValueError("Imported historical evidence is read-only. Import new interactions into the original live case or prepare a new case.")
            seen = {row["content_hash"] for row in [*case["interactions"], *case["unmatched_interactions"]]}
            matched = unmatched = duplicates = 0
            if len(seen) + len(records) > 10000:
                raise ValueError("Retain an evidence export before exceeding 10,000 interactions for one case.")
            for line, event in records:
                content_hash = _hash(event)
                if content_hash in seen:
                    duplicates += 1
                    continue
                seen.add(content_hash)
                matches = _event_matches(event, case)
                timestamp = _timestamp(event.get("timestamp"))
                window = "unknown" if timestamp is None else "inside" if _timestamp(case["created_at"]) <= timestamp <= _timestamp(case["expires_at"]) else "outside"
                safe = self._workspaces().sanitise_local_data({"event": event, "source_name": source_name})
                item = {"id": uuid.uuid4().hex, "content_hash": content_hash, "event": safe["event"],
                        "content_hash_basis": "original-canonical-json", "redacted": safe["event"] != event,
                        "evidence_representation": "sanitised-structured-json",
                        "source": {"name": safe["source_name"], "hash": source_hash, "raw_source_hash": source_hash,
                                   "raw_source_retained": False, "line": line, "format": "interactsh-jsonl"},
                        "case_id": case_id if matches else None, "context": case["context"] if matches else None,
                        "correlation": "exact-case-marker" if matches else "unmatched", "correlation_window": window,
                        "classification": "callback-observation" if matches else "unmatched-interaction",
                        "origin": "external-report", "verification": "imported-unverified", "attribution": "not-established",
                        "security_impact": "not-established", "received_at": self.clock().isoformat()}
                case["interactions" if matches else "unmatched_interactions"].append(item)
                matched += int(matches)
                unmatched += int(not matches)
            imported = {"id": uuid.uuid4().hex, "source_hash": source_hash, "received_at": self.clock().isoformat(),
                        "matched": matched, "unmatched": unmatched, "duplicates": duplicates, "errors": errors, "requests_sent": 0}
            case["imports"].append(imported)
            if matched:
                case["status"] = "callback-observed"
            self._save(case)
        return {"case": self.get(case_id), "import": imported, "requests_sent": 0}

    def retire(self, case_id):
        with self._lock:
            case = self._load(case_id)
            case["retired"] = True
            case["retired_at"] = self.clock().isoformat()
            self._save(case)
        return self.get(case_id)

    def export(self, case_id):
        return {"format": FORMAT, "version": VERSION, "case": self.get(case_id), "exported_at": self.clock().isoformat(), "requests_sent": 0}

    def restore(self, payload):
        payload = _bounded_json(payload)
        if len(json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()) > MAX_DOCUMENT_BYTES:
            raise ValueError("Import at most 8 MiB of OOB evidence.")
        if payload.get("format") != FORMAT or payload.get("version") != VERSION or not isinstance(payload.get("case"), dict):
            raise ValueError("Choose a version 1 Namazu OOB evidence export.")
        original = payload["case"]
        # Restored observations cannot become new live correlations or local
        # request links. Preserve claims as historical, user-supplied provenance.
        required = {"context", "created_at", "expires_at", "payload", "callback_host", "field", "receipts", "interactions", "imports", "unmatched_interactions"}
        if not required.issubset(original) or not isinstance(original["context"], dict) or any(not isinstance(original[key], list) for key in ("receipts", "interactions", "imports", "unmatched_interactions")):
            raise ValueError("The OOB export is missing its case context or evidence lists.")
        if _timestamp(original["created_at"]) is None or _timestamp(original["expires_at"]) is None:
            raise ValueError("The OOB export has invalid correlation timestamps.")
        if any(not isinstance(original[key], str) or not original[key] or len(original[key]) > 8192 for key in ("payload", "callback_host")):
            raise ValueError("The OOB export has invalid payload metadata.")
        _field(original["field"])
        if any(not isinstance(original["context"].get(key), (str, int, type(None))) for key in CONTEXT_KEYS):
            raise ValueError("The OOB export has invalid context metadata.")
        if len(original["interactions"]) + len(original["unmatched_interactions"]) > 10000 or len(original["receipts"]) > 10000 or len(original["imports"]) > 10000:
            raise ValueError("The OOB export exceeds the evidence record limit.")
        allowed = required | {"id", "kind", "callback_base", "correlation_full_id", "marker", "callback_scope_confirmed", "assignment_scopes"}
        safe = self._workspaces().sanitise_local_data({key: copy.deepcopy(value) for key, value in original.items() if key in allowed})
        safe.update(id=uuid.uuid4().hex, original_case_id=str(original.get("id", ""))[:128], historical=True, retired=True,
                    status="imported-historical", requests_sent=0, context_current=False, can_use_payload=False,
                    limitations=LIMITATIONS, references=SOURCES)
        for group in ("interactions", "unmatched_interactions"):
            for index, item in enumerate(safe[group]):
                if not isinstance(item, dict):
                    raise ValueError("The OOB export has invalid interaction records.")
                item["redacted"] = bool(item.get("redacted")) or item.get("event") != original[group][index].get("event")
                item["evidence_representation"] = "sanitised-structured-json"
                item.update(origin="external-report", verification="imported-unverified", attribution="not-established", security_impact="not-established",
                            classification="callback-observation" if group == "interactions" else "unmatched-interaction",
                            correlation="historical-imported-claim", case_id=safe["id"] if group == "interactions" else None)
        for row in safe["receipts"]:
            if not isinstance(row, dict):
                raise ValueError("The OOB export has invalid receipt references.")
            row.pop("evidence_ref", None)
            row["historical_reference_only"] = True
        with self._lock:
            if self._db.execute("SELECT count(*) FROM cases").fetchone()[0] >= 2000:
                raise ValueError("OOB evidence storage contains 2,000 cases; retain an export before importing more.")
            self._save(safe)
        return self.get(safe["id"])


_SERVICE = None
_LOCK = threading.Lock()


def service():
    global _SERVICE
    with _LOCK:
        if _SERVICE is None:
            _SERVICE = OOBService()
        return _SERVICE


def set_service(value):
    global _SERVICE
    with _LOCK:
        _SERVICE = value
