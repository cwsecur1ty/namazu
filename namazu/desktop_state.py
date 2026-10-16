"""Versioned desktop state, per-user paths and recoverable legacy migrations.

UI restoration is offline: this module neither resumes runs nor resolves OAuth.
Atomic replacement and compare-and-swap revisions prevent partial writes and
stale windows overwriting one another. Existing databases are copied with the
SQLite backup API so committed WAL evidence is included without moving originals.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from .audit.model import CREDENTIAL_QUERY, REDACTED_HEADERS
from .audit.readiness import _sanitise
from .spec import MAX_DOCUMENT_BYTES, _bounded_json

STATE_VERSION = 1
STATE_FORMAT = "namazu-desktop-state"
MIGRATION_FORMAT = "namazu-desktop-migration"
DEFAULT_STATE = {"tabs": [], "drafts": {}, "selectedTab": None, "layout": {},
                 "filters": {}, "environments": [], "preferences": {}, "workspaces": {}}
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_LOCK = threading.Lock()


class StateStorageError(RuntimeError):
    """A durable operation failed; existing data has not been discarded."""


class StateConflict(ValueError):
    def __init__(self, expected, current):
        super().__init__("Desktop state changed in another window; reload before saving.")
        self.expected = expected
        self.current = current


class StateVersionError(ValueError):
    """A newer state format must not be overwritten by an older application."""


@dataclass(frozen=True)
class DesktopPaths:
    root: Path

    @property
    def config(self):
        return self.root / "config"

    @property
    def workspaces(self):
        return self.root / "workspaces"

    @property
    def secrets(self):
        return self.root / "secrets"

    @property
    def evidence(self):
        return self.root / "evidence"

    @property
    def cache(self):
        return self.root / "cache"

    @property
    def logs(self):
        return self.root / "logs"

    @property
    def backups(self):
        return self.root / "backups"

    @property
    def ui_state(self):
        return self.config / "desktop-state.json"

    @property
    def runs_db(self):
        return self.evidence / "runs.db"

    @property
    def workspaces_db(self):
        return self.workspaces / "workspaces.db"

    def ensure(self):
        for path in (self.config, self.workspaces, self.secrets, self.evidence, self.cache, self.logs, self.backups):
            path.mkdir(parents=True, exist_ok=True)


def data_paths(root=None, *, environ=None, home=None, platform=None) -> DesktopPaths:
    env = os.environ if environ is None else environ
    chosen = root or env.get("NAMAZU_STATE_DIR")
    if chosen:
        return DesktopPaths(Path(chosen).expanduser().resolve())
    home = Path(home) if home else Path.home()
    platform = platform or sys.platform
    if platform == "win32":
        base = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local")
    elif platform == "darwin":
        base = home / "Library" / "Application Support"
    else:
        base = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share")
    return DesktopPaths(base / "Namazu")


def desktop_enabled() -> bool:
    return os.environ.get("NAMAZU_DESKTOP", "").lower() in {"1", "true", "yes"}


@contextlib.contextmanager
def file_lock(path: Path):
    """Serialise threads and processes sharing one tiny, application-owned lock."""
    path = Path(path)
    with _LOCKS_LOCK:
        lock = _LOCKS.setdefault(str(path.resolve()), threading.RLock())
    with lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _stage_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return staged
    except BaseException:
        with contextlib.suppress(OSError):
            staged.unlink()
        raise


def atomic_write(path: Path, data: bytes, *, backup=True):
    """Stage, flush and atomically replace; a failed write retains the original."""
    path = Path(path)
    staged = _stage_bytes(path, data)
    try:
        if backup and path.exists():
            backup_path = path.with_name(path.name + ".bak")
            held = _stage_bytes(backup_path, path.read_bytes())
            try:
                os.replace(held, backup_path)
            finally:
                with contextlib.suppress(OSError):
                    held.unlink()
        os.replace(staged, path)
    finally:
        with contextlib.suppress(OSError):
            staged.unlink()


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sanitise_ui_state(value: dict, *, secret_sources=()) -> dict:
    """Retain request/response structure and references, never draft secrets."""
    if not isinstance(value, dict):
        raise ValueError("Desktop state must be an object")
    value = _bounded_json(value)
    if len(_json_bytes(value)) > MAX_DOCUMENT_BYTES:
        raise ValueError("Desktop state exceeds the 8 MiB limit")
    names, sources = set(), list(secret_sources)
    refs = {"identity_ref", "identityRef", "credential_ref", "credentialRef", "secret_ref", "secretRef", "profile_id", "profileId",
            "id", "workspace_id", "workspaceId", "contract_id", "contractId", "operation_key", "operationKey",
            "snapshot_hash", "snapshotHash", "operationId", "localOperationId", "requestId", "run_id", "environmentId",
            "activeWorkspaceId", "activeEnvironmentId", "selectedTab",
            "type", "kind", "method", "content_type", "contentType", "requestTab", "responseTab", "theme"}
    containers = {"auth", "authentication", "authorization", "credentials"}
    contextual_values = {"value", "credential", "key", "secret", "bearer"}
    header_line = re.compile(r"(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)[ \t]*:[ \t]*)([^\r\n]+)")
    bearer = re.compile(r"(?i)\b(Bearer|Basic)[ \t]+([^\s\"'<>]+)")

    def collect(item, credential_context=False):
        if isinstance(item, dict):
            declared = item.get("credential_names")
            if isinstance(declared, list):
                names.update(str(name).lower() for name in declared if isinstance(name, str))
            name = item.get("name", item.get("key", ""))
            if isinstance(name, str) and (name.lower() in REDACTED_HEADERS or CREDENTIAL_QUERY.match(name)) and isinstance(item.get("value"), (str, int, float)):
                sources.append({"authorization": str(item["value"])})
            for key, child in item.items():
                if key not in refs and isinstance(child, str) and (key.lower() == "bearer" or (credential_context and key.lower() in contextual_values)):
                    sources.append({"authorization": child})
                collect(child, credential_context or key.lower() in containers)
        elif isinstance(item, list):
            for child in item:
                collect(child, credential_context)
        elif isinstance(item, str):
            for match in header_line.finditer(item):
                sources.append({"authorization": match[2]})
            for match in bearer.finditer(item):
                sources.append({"authorization": match[0]})
    collect(value)
    # References are opaque IDs. Temporarily replace them so short credential
    # strings cannot rewrite IDs or confuse an identity ref with a bearer value.
    protected = {}
    def protect(item, credential_context=False, path=()):
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                tab_key = key == "key" and "workspaceId" in item and "operationKey" in item
                if (key in refs or tab_key) and isinstance(child, str):
                    protected[(*path, key)] = child
                    result[key] = {"__namazu_ref_marker__": True}
                elif isinstance(child, (str, int, float)) and (key.lower() == "bearer" or (credential_context and key.lower() in contextual_values)):
                    result[key] = "<credential>"
                else:
                    result[key] = protect(child, credential_context or key.lower() in containers, (*path, key))
            return result
        return [protect(child, credential_context, (*path, index)) for index, child in enumerate(item)] if isinstance(item, list) else item
    cleaned = _sanitise(protect(value), preserve_metadata=True, secret_sources=sources, credential_names=names)
    def finish(item, path=()):
        if path in protected:
            return protected[path]
        if isinstance(item, dict):
            result = {key: finish(child, (*path, key)) for key, child in item.items()}
            name = item.get("name", item.get("key", ""))
            if isinstance(name, str) and (name.lower() in REDACTED_HEADERS | names or CREDENTIAL_QUERY.match(name)) and "value" in result:
                result["value"] = "<credential>"
            return result
        if isinstance(item, list):
            return [finish(child, (*path, index)) for index, child in enumerate(item)]
        if isinstance(item, str):
            item = header_line.sub(lambda match: match[1] + "<credential>", item)
            return bearer.sub(lambda match: match[1] + " <credential>", item)
        return item
    return finish(cleaned)


def sanitise_browser_preferences(payload, *, redact=None):
    """Review an explicit legacy-browser export without storing or applying it.

    Only the existing non-secret preference keys are accepted. JSON values are
    decoded before redaction and returned as JSON strings for the old editor.
    A supplied local redactor can additionally mask known profile values; it
    must not acquire tokens or perform requests. This function does no IO.
    """
    if not isinstance(payload, dict) or set(payload) - {"format", "version", "preferences"}:
        raise ValueError("Provide a browser preferences object.")
    if "format" in payload and payload["format"] != "namazu-browser-preferences":
        raise ValueError("Unsupported browser preferences format.")
    if "version" in payload and payload["version"] != 1:
        raise StateVersionError("Use browser preferences format version 1.")
    preferences = payload.get("preferences")
    if not isinstance(preferences, dict) or len(preferences) > 500:
        raise ValueError("Provide at most 500 named browser preferences.")
    preferences = _bounded_json(preferences)
    if len(_json_bytes(preferences)) > MAX_DOCUMENT_BYTES:
        raise ValueError("Browser preferences exceed the 8 MiB limit.")
    enums = {"namazu-theme": {"dark", "light"}, "namazu-layout": {"cols", "rows"},
             "namazu-wrap": {"1", "0"}, "namazu-group-mode": {"tag", "method", "path", "none"},
             "namazu-history-limit": {"25", "100", "250"}}
    ranges = {"namazu-panel-w": (210, 560), "namazu-req-basis": (22, 78)}
    result, documents = {}, {}

    def check_keys(value):
        if isinstance(value, dict):
            if {"__proto__", "prototype", "constructor"}.intersection(value):
                raise ValueError("Browser preferences contain an unsupported object property.")
            for child in value.values():
                check_keys(child)
        elif isinstance(value, list):
            for child in value:
                check_keys(child)

    for key, value in preferences.items():
        if not isinstance(value, str) or len(key) > 4096 or any(ord(char) < 32 for char in key):
            raise ValueError("Browser preference names and values must be bounded strings.")
        if key in enums:
            if value not in enums[key]:
                raise ValueError("A browser preference has an unsupported choice.")
            result[key] = value
        elif key in ranges:
            try:
                number = float(value)
            except ValueError as exc:
                raise ValueError("A browser layout preference is not a number.") from exc
            lower, upper = ranges[key]
            if not math.isfinite(number) or not lower <= number <= upper:
                raise ValueError("A browser layout preference is outside its supported range.")
            result[key] = str(round(number)) if key == "namazu-panel-w" else f"{number:.1f}"
        elif key.startswith(("namazu-examples:", "namazu-access:")):
            if not key.partition(":")[2] or re.search(r"(?i)(?:Bearer|Basic)\s|https?://[^/\s]*@|[?&][^=&#]*(?:token|password|secret|api[-_]?key)[^=&#]*=", key):
                raise ValueError("Browser preference context names must not contain credentials.")
            try:
                document = _bounded_json(json.loads(value))
            except (ValueError, RecursionError) as exc:
                raise ValueError("Saved examples and access preferences must contain valid bounded JSON.") from exc
            if not isinstance(document, dict):
                raise ValueError("Saved examples and access preferences must contain JSON objects.")
            if key.startswith("namazu-access:") and (set(document) - {"matrix", "sequence"} or any(
                    not isinstance(rows, list) for rows in document.values())):
                raise ValueError("Access preferences may contain only matrix rows and sequence steps.")
            check_keys(document)
            documents[key] = document
        else:
            raise ValueError("This browser preference is not part of the supported non-secret migration.")
    safe = sanitise_ui_state(documents)
    if redact is not None:
        safe = redact(safe)
    for key, value in safe.items():
        result[key] = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return {"format": "namazu-browser-preferences", "version": 1, "preferences": result}


class StateStore:
    def __init__(self, paths: DesktopPaths | str | Path | None = None):
        self.paths = paths if isinstance(paths, DesktopPaths) else data_paths(paths)
        self.path = self.paths.ui_state

    @staticmethod
    def _decode(data):
        envelope = json.loads(data)
        if not isinstance(envelope, dict) or envelope.get("format") != STATE_FORMAT:
            raise ValueError("Unknown desktop state format")
        if envelope.get("version") != STATE_VERSION:
            raise StateVersionError("Desktop state was written by an unsupported version; it has been preserved.")
        if not isinstance(envelope.get("revision"), int) or isinstance(envelope["revision"], bool) or envelope["revision"] < 0:
            raise ValueError("Invalid desktop state revision")
        if not isinstance(envelope.get("state"), dict):
            raise ValueError("Invalid desktop state contents")
        envelope["state"] = sanitise_ui_state(envelope["state"])
        return envelope

    def _read(self):
        if not self.path.exists():
            return {"format": STATE_FORMAT, "version": STATE_VERSION, "revision": 0, "state": copy.deepcopy(DEFAULT_STATE)}
        raw = self.path.read_bytes()
        try:
            return self._decode(raw)
        except StateVersionError:
            raise
        except (ValueError, UnicodeError, RecursionError):
            corrupt = self.path.with_name(self.path.name + ".corrupt-" + uuid.uuid4().hex)
            atomic_write(corrupt, raw, backup=False)
            recovered = None
            backup_path = self.path.with_name(self.path.name + ".bak")
            if backup_path.exists():
                try:
                    recovered = self._decode(backup_path.read_bytes())
                except StateVersionError:
                    raise
                except (ValueError, UnicodeError, RecursionError):
                    pass
            if recovered is None:
                recovered = {"format": STATE_FORMAT, "version": STATE_VERSION, "revision": 0, "state": copy.deepcopy(DEFAULT_STATE)}
            atomic_write(self.path, _json_bytes(recovered), backup=False)
            recovered["recovery"] = {"source": "backup" if backup_path.exists() and recovered["revision"] else "defaults",
                                     "corrupt_copy": corrupt.name,
                                     "message": "Unreadable desktop state was preserved separately; review the restored drafts before use."}
            return recovered

    def get(self):
        try:
            with file_lock(self.path.with_name(".desktop-state.lock")):
                result = self._read()
                result.pop("format", None)
                return result
        except OSError as exc:
            raise StateStorageError("Could not read desktop state; retained files have not been discarded.") from exc

    def put(self, payload):
        if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION:
            raise StateVersionError("Use desktop state format version 1.")
        expected = payload.get("revision")
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
            raise ValueError("Supply the desktop revision that was read before saving.")
        safe = sanitise_ui_state(payload.get("state"))
        try:
            with file_lock(self.path.with_name(".desktop-state.lock")):
                current = self._read()
                if current["revision"] != expected:
                    raise StateConflict(expected, {key: value for key, value in current.items() if key != "format"})
                result = {"format": STATE_FORMAT, "version": STATE_VERSION, "revision": expected + 1, "state": safe}
                atomic_write(self.path, _json_bytes(result))
                return {key: value for key, value in result.items() if key != "format"}
        except OSError as exc:
            raise StateStorageError("Could not save desktop state; the previous state has been retained.") from exc


def _snapshot_database(source: Path, destination: Path):
    uri = "file:" + quote(str(source.resolve()).replace("\\", "/"), safe="/:") + "?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as original:
        if original.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise StateStorageError("The legacy database failed its integrity check; the original has been preserved.")
        with contextlib.closing(sqlite3.connect(str(destination))) as target:
            original.backup(target)
            if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise StateStorageError("The database snapshot failed verification; the original has been preserved.")


def initialize_data(paths: DesktopPaths | None = None, *, legacy_dir=None):
    paths = paths or data_paths()
    legacy = Path(legacy_dir) if legacy_dir is not None else Path.home() / ".namazu"
    manifest_path = paths.config / "migration-v1.json"
    try:
        paths.ensure()
        with file_lock(paths.config / ".migration.lock"):
            manifest = {"format": MIGRATION_FORMAT, "version": 1, "entries": []}
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest.get("format") != MIGRATION_FORMAT or manifest.get("version") != 1:
                    raise StateVersionError("The migration manifest has an unsupported format; existing files are preserved.")
            for name, destination in (("runs.db", paths.runs_db), ("workspaces.db", paths.workspaces_db)):
                if destination.exists():
                    continue
                source = next((candidate for candidate in (paths.root / name, legacy / name) if candidate.is_file() and candidate.resolve() != destination.resolve()), None)
                if source is None:
                    continue
                fd, temporary = tempfile.mkstemp(prefix=".migration-", suffix=".db", dir=destination.parent)
                os.close(fd)
                temporary = Path(temporary)
                try:
                    _snapshot_database(source, temporary)
                    snapshot = temporary.read_bytes()
                    backup = paths.backups / (name + ".migration-" + uuid.uuid4().hex + ".db")
                    atomic_write(backup, snapshot, backup=False)
                    with temporary.open("r+b") as stream:
                        os.fsync(stream.fileno())
                    os.replace(temporary, destination)
                    manifest["entries"].append({"source": str(source), "destination": str(destination), "backup": str(backup),
                                                "sha256": hashlib.sha256(snapshot).hexdigest(), "created_at": datetime.now(timezone.utc).isoformat(),
                                                "original_preserved": True})
                    atomic_write(manifest_path, _json_bytes(manifest))
                finally:
                    with contextlib.suppress(OSError):
                        temporary.unlink()
            return {"root": str(paths.root), "manifest": manifest}
    except (OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        raise StateStorageError("Desktop migration could not finish; original databases and completed backups remain available.") from exc


_STORE: StateStore | None = None
_STORE_LOCK = threading.Lock()


def store() -> StateStore:
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = StateStore()
        return _STORE


def set_store(instance: StateStore | None):
    global _STORE
    with _STORE_LOCK:
        _STORE = instance
