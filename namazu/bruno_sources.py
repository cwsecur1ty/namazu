"""Bounded, offline, cancellable multi-collection discovery and atomic import.

Raw source snapshots exist only in memory for the review job. Native filesystem
access is a separate capability; browser uploads contain explicit bytes only.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import io
import json
import os
import stat
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

import yaml

from .bruno_collections import import_collection, parser
from .request_collections import collection

LIMITS = {"entries": 10000, "depth": 24, "source_bytes": 32 * 1024 * 1024,
          "zip_bytes": 16 * 1024 * 1024, "file_bytes": 256 * 1024,
          "collections": 100, "requests_per_collection": 2000, "jobs": 8,
          "zip_ratio": 200, "workers": 2, "job_lifetime_seconds": 1800}
SKIP = frozenset({"node_modules", ".git", ".hg", ".svn", "__pycache__", ".cache", ".pytest_cache", ".venv", "venv", ".idea", ".vscode"})
MANIFESTS = {"bruno.json", "opencollection.yml", "opencollection.yaml"}


class Cancelled(Exception):
    pass


def relative_path(name):
    if (not isinstance(name, str) or not name or len(name) > 240 or "\\" in name or ":" in name
            or any(ord(char) < 32 for char in name) or name.startswith("/")
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise ValueError("Source paths must be bounded relative paths without traversal, drive letters or empty segments.")
    if len(name.split("/")) > LIMITS["depth"]:
        raise ValueError("Source exceeds the maximum directory depth of 24.")
    return name


def relevant(name):
    return PurePosixPath(name).name in MANIFESTS | {"workspace.yml", "workspace.yaml"} or name.endswith((".bru", ".yml", ".yaml"))


def metadata(content):
    try:
        # Workspace metadata never needs aliases, tags or executable constructors.
        if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)) for token in yaml.scan(content)):
            raise ValueError()
        value = yaml.safe_load(content)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (yaml.YAMLError, ValueError, RecursionError):
        raise ValueError("Invalid or unsupported workspace YAML metadata.") from None


def _linked(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_native_path(root, path):
    # Recheck every ancestor before opening; do not follow Windows junctions,
    # symlinks, cloud placeholders or any other reparse points.
    for component in [path, *path.parents]:
        if _linked(component.lstat()):
            raise ValueError("Linked or reparse-point source paths are not read.")
        if component == root:
            break
    if not path.resolve().is_relative_to(root):
        raise ValueError("A source entry resolves outside the selected folder.")


def order_requests(imported, cancel_event=None):
    """Apply the pinned official sibling ordering at every folder level."""
    groups, folders = {"": []}, set()
    definitions = (imported.get("source") or {}).get("definitions") or {}
    def sequence(value):
        return int(value) if isinstance(value, str) and value.isdigit() else value
    for row in imported["requests"]:
        parts = row.get("folder", "").split("/") if row.get("folder") else []
        parent = ""
        for part in parts:
            path = parent + "/" + part if parent else part
            if path not in folders:
                meta = (definitions.get(path + "/folder.bru") or {}).get("meta") or {}
                groups.setdefault(parent, []).append({"name": meta.get("name") or part, "seq": sequence(meta.get("seq")), "folder": path})
                groups[path] = []
                folders.add(path)
            parent = path
        groups[parent].append({"name": row["name"], "seq": sequence(row.get("sequence")), "id": row["id"]})
    keys = list(groups)
    sorted_groups = parser("parse", [{"kind": "sortLists", "value": list(groups.values())}], cancel_event=cancel_event)[0]
    groups = dict(zip(keys, sorted_groups, strict=True))
    rows = {row["id"]: row for row in imported["requests"]}
    ordered = []
    def visit(folder):
        for node in groups[folder]:
            if "folder" in node:
                visit(node["folder"])
            else:
                ordered.append(rows[node["id"]])
    visit("")
    imported["requests"] = ordered


class SourceJobs:
    def __init__(self, workspace_service=None):
        self.workspace_service = workspace_service
        self._lock = threading.RLock()
        self._jobs = {}
        self._pool = ThreadPoolExecutor(max_workers=LIMITS["workers"], thread_name_prefix="namazu-bruno-import")

    def close(self):
        with self._lock:
            for job in self._jobs.values():
                job["cancel"].set()
        self._pool.shutdown(wait=True, cancel_futures=True)

    def _check(self, job):
        if job["cancel"].is_set():
            raise Cancelled()

    def _new(self, kind, label):
        with self._lock:
            now = time.monotonic()
            for key, job in list(self._jobs.items()):
                if ((now - job["created"] > LIMITS["job_lifetime_seconds"] and job["public"]["status"] not in {"discovering", "parsing", "importing"})
                        or (len(self._jobs) >= LIMITS["jobs"] and job["public"]["status"] in {"cancelled", "completed"})):
                    del self._jobs[key]
            if len(self._jobs) >= LIMITS["jobs"]:
                raise ValueError("At most eight source reviews can remain open. Cancel a review or restart after preserving your workspace.")
            identifier = uuid.uuid4().hex
            job = {"created": now, "cancel": threading.Event(), "files": {}, "groups": {}, "prepared": [],
                   "public": {"id": identifier, "source_kind": kind, "label": label, "status": "discovering",
                    "progress": {"files_seen": 0, "definitions": 0, "collections": 0, "parsed_collections": 0, "total_files": None, "skipped": 0},
                    "timings": {"discovery_ms": None, "parsing_ms": None, "import_ms": None},
                    "collections": [], "workspace_environments": [], "workspace_environment": "", "warnings": [], "errors": [],
                    "review_id": None, "result": None, "limits": dict(LIMITS), "requests_sent": 0}}
            self._jobs[identifier] = job
            return job

    def _job(self, identifier):
        with self._lock:
            if identifier not in self._jobs:
                raise ValueError("Source review not found or expired; select the source again.")
            return self._jobs[identifier]

    def get(self, identifier):
        job = self._job(identifier)
        with self._lock:
            return copy.deepcopy(job["public"])

    def cancel(self, identifier):
        job = self._job(identifier)
        with self._lock:
            if job["public"]["status"] == "completed":
                return self.get(identifier)
            job["cancel"].set()
            job["public"]["status"] = "cancelled"
            job["public"]["review_id"] = None
            job["prepared"] = []
            job["files"] = {}
            job["groups"] = {}
            job["global_files"] = {}
        return self.get(identifier)

    def _run(self, job, stage, work):
        start = time.perf_counter()
        job["stage_started"] = start
        try:
            self._check(job)
            work()
        except Cancelled:
            with self._lock:
                job["public"]["status"] = "cancelled"
        except Exception as error:
            with self._lock:
                job["public"]["status"] = "failed"
                # OSError/parser source can contain local paths or secret text.
                job["public"]["errors"] = [str(error) if isinstance(error, ValueError) else "Source processing failed. Check local permissions, archive integrity and available disk space."]
        finally:
            with self._lock:
                job["public"]["timings"][stage + "_ms"] = round((time.perf_counter() - start) * 1000, 2)
                if job["cancel"].is_set():
                    job["files"], job["prepared"] = {}, []
                    job["groups"] = {}
                    job["public"]["status"] = "cancelled"

    def create(self, body):
        if not isinstance(body, dict) or set(body) - {"files", "zip_base64", "filename"}:
            raise ValueError("Supply explicit source files or ZIP bytes; filesystem paths require the native folder picker.")
        if ("files" in body) == ("zip_base64" in body):
            raise ValueError("Choose exactly one source: files or a ZIP archive.")
        if "zip_base64" in body:
            encoded = body["zip_base64"]
            if not isinstance(encoded, str) or len(encoded) > (LIMITS["zip_bytes"] * 4 // 3 + 4):
                raise ValueError("Workspace ZIP uploads are limited to 16 MiB compressed.")
            try:
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                raise ValueError("Supply a valid base64 ZIP archive.") from None
            if len(content) > LIMITS["zip_bytes"]:
                raise ValueError("Workspace ZIP uploads are limited to 16 MiB compressed.")
            job = self._new("zip", "Uploaded workspace ZIP")
            job["namespace"] = "zip:" + hashlib.sha256(content).hexdigest()
            self._pool.submit(self._run, job, "discovery", lambda: self._zip(job, content))
        else:
            files = copy.deepcopy(body["files"])
            if not isinstance(files, list) or not 1 <= len(files) <= LIMITS["entries"]:
                raise ValueError("Select 1–10000 source files.")
            if sum(len(item.get("content", "").encode()) for item in files if isinstance(item, dict) and isinstance(item.get("content"), str)) > LIMITS["source_bytes"]:
                raise ValueError("Selected source files exceed 32 MiB.")
            job = self._new("files", "Selected source files")
            job["namespace"] = "files"
            self._pool.submit(self._run, job, "discovery", lambda: self._uploaded(job, files))
        return self.get(job["public"]["id"])

    def native(self, root):
        if not isinstance(root, str) or not root or not Path(root).is_absolute():
            raise ValueError("Select one absolute source folder using the native picker.")
        chosen = Path(root)
        try:
            for path in [chosen, *chosen.parents]:
                if _linked(path.lstat()):
                    raise ValueError("Select a regular local folder; linked or reparse-point roots are not read.")
            if not chosen.is_dir():
                raise ValueError("Select an existing source folder.")
            chosen = chosen.resolve()
        except OSError:
            raise ValueError("The selected source folder is not accessible.") from None
        job = self._new("native-folder", "Selected local folder")
        job["namespace"] = "native:" + hashlib.sha256(str(chosen).encode()).hexdigest()
        self._pool.submit(self._run, job, "discovery", lambda: self._directory(job, chosen))
        return self.get(job["public"]["id"])

    def _seen(self, job):
        self._check(job)
        with self._lock:
            progress = job["public"]["progress"]
            progress["files_seen"] += 1
            if progress["files_seen"] > LIMITS["entries"]:
                raise ValueError("Source discovery exceeded 10000 entries; select a narrower folder.")

    def _add(self, job, name, raw):
        name = relative_path(name)
        if any(part.casefold() in SKIP for part in name.split("/")) or not relevant(name):
            job["public"]["progress"]["skipped"] += 1
            return
        if name.casefold() in job.setdefault("paths", set()):
            raise ValueError("Source contains duplicate or case-colliding relative paths.")
        job["paths"].add(name.casefold())
        if len(raw) > LIMITS["file_bytes"]:
            raise ValueError("A Bruno definition or metadata file exceeds 256 KiB.")
        job["bytes"] = job.get("bytes", 0) + len(raw)
        if job["bytes"] > LIMITS["source_bytes"]:
            raise ValueError("Source definitions exceed the 32 MiB total limit.")
        try:
            job["files"][name] = raw.decode("utf-8-sig")
        except UnicodeError:
            raise ValueError("A selected Bruno definition is not UTF-8 text.") from None
        job["public"]["progress"]["definitions"] += 1

    def _uploaded(self, job, files):
        for item in files:
            self._seen(job)
            if not isinstance(item, dict) or not isinstance(item.get("content"), str):
                raise ValueError("Each source file needs a relative path and UTF-8 content.")
            self._add(job, item.get("path"), item["content"].encode())
        self._discover(job)

    def _directory(self, job, root):
        pending = [root]
        while pending:
            self._check(job)
            folder = pending.pop()
            _safe_native_path(root, folder)
            with os.scandir(folder) as entries:
                for entry in entries:
                    self._seen(job)
                    info = entry.stat(follow_symlinks=False)
                    if _linked(info) or entry.name.casefold() in SKIP:
                        job["public"]["progress"]["skipped"] += 1
                        continue
                    path = Path(entry.path)
                    name = relative_path(path.relative_to(root).as_posix())
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode) and relevant(name):
                        _safe_native_path(root, path)
                        # Windows DirEntry.stat deliberately returns zero file
                        # IDs; lstat obtains the handle-independent comparison.
                        info = path.lstat()
                        if info.st_size > LIMITS["file_bytes"]:
                            raise ValueError("A Bruno definition or metadata file exceeds 256 KiB.")
                        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                        with os.fdopen(os.open(path, flags), "rb") as stream:
                            current = os.fstat(stream.fileno())
                            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(current.st_mode):
                                raise ValueError("Source changed during discovery; select the folder again.")
                            _safe_native_path(root, path)
                            self._add(job, name, stream.read(LIMITS["file_bytes"] + 1))
                    else:
                        job["public"]["progress"]["skipped"] += 1
        self._discover(job)

    def _zip(self, job, content):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > LIMITS["entries"] or sum(item.file_size for item in members) > LIMITS["source_bytes"]:
                raise ValueError("ZIP exceeds 10000 entries or 32 MiB expanded size.")
            seen = set()
            for item in members:
                self._seen(job)
                name = relative_path(item.orig_filename.rstrip("/"))
                if name.casefold() in seen:
                    raise ValueError("ZIP contains duplicate or case-colliding paths.")
                seen.add(name.casefold())
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode) or (mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                    raise ValueError("ZIP links and special file entries are not supported.")
                if item.flag_bits & 1:
                    raise ValueError("Encrypted ZIP entries are not supported.")
                if item.file_size > max(1024 * 1024, item.compress_size * LIMITS["zip_ratio"]):
                    raise ValueError("ZIP entry exceeds the maximum expansion ratio.")
                if item.is_dir() or any(part.casefold() in SKIP for part in name.split("/")) or not relevant(name):
                    job["public"]["progress"]["skipped"] += 1
                    continue
                with archive.open(item) as stream:
                    self._add(job, name, stream.read(LIMITS["file_bytes"] + 1))
        self._discover(job)

    def _discover(self, job):
        self._check(job)
        files = job["files"]
        roots = sorted({str(PurePosixPath(name).parent) for name in files if PurePosixPath(name).name in MANIFESTS})
        workspace_files = [name for name in files if PurePosixPath(name).name in {"workspace.yml", "workspace.yaml"}]
        workspace_names, global_files = {}, {}
        for filename in workspace_files:
            doc = metadata(files[filename])
            if doc.get("opencollection") != "1.0.0" or (doc.get("info") or {}).get("type") != "workspace":
                raise ValueError("Only workspace.yml OpenCollection 1.0.0 metadata verified with Bruno 4.2.1 is supported.")
            base = PurePosixPath(filename).parent
            for entry in doc.get("collections") or []:
                try:
                    target = relative_path(entry["path"].replace("\\", "/"))
                    target = str(base / target)
                except (ValueError, KeyError, TypeError, AttributeError):
                    job["public"]["warnings"].append("Workspace references an external or invalid collection path; it was not followed.")
                    continue
                workspace_names[target] = str(entry.get("name") or target)
                if target not in roots:
                    job["public"]["warnings"].append("A workspace collection reference is not present inside the selected source; no remote repository or external path was opened.")
            env_prefix = (str(base) + "/" if str(base) != "." else "") + "environments/"
            for name in files:
                if name.startswith(env_prefix) and name.endswith((".bru", ".yml", ".yaml")):
                    key = str(PurePosixPath(name[len(env_prefix):]).with_suffix(""))
                    if key in global_files:
                        raise ValueError("Multiple workspace environments have the same name; select one workspace root.")
                    global_files[key] = (name, files[name])
        job["global_files"] = global_files
        job["public"]["workspace_environments"] = sorted(global_files)
        if not roots:
            # A deliberately selected request/folder remains usable without
            # inventing a collection manifest or opening parent directories.
            if any(name.endswith((".bru", ".yml", ".yaml")) and not name.startswith("environments/") for name in files):
                roots = ["."]
            else:
                raise ValueError("No Bruno collection or request definitions were found in the selected source.")
        if len(roots) > LIMITS["collections"]:
            raise ValueError("Select at most 100 collections in one source review.")
        ordered = [root for root in workspace_names if root in roots] + [root for root in roots if root not in workspace_names]
        summaries = []
        for root in ordered:
            prefix = root + "/" if root != "." else ""
            members = {}
            for name, content in files.items():
                if not name.startswith(prefix) or PurePosixPath(name).name.startswith("workspace."):
                    continue
                owner = max((candidate for candidate in roots if candidate == "." or name.startswith(candidate + "/")), key=len)
                if owner != root or any(name == entry[0] for entry in global_files.values()):
                    continue
                members[name[len(prefix):]] = content
            source_id = hashlib.sha256((job["namespace"] + "\0" + root).encode()).hexdigest()
            errors, name = [], workspace_names.get(root) or (PurePosixPath(root).name if root != "." else "Selected Bruno requests")
            try:
                if "bruno.json" in members:
                    conf = json.loads(members["bruno.json"])
                    if not isinstance(conf, dict) or str(conf.get("version")) != "1" or conf.get("type") != "collection":
                        raise ValueError()
                    name = conf.get("name") or name
                elif "opencollection.yml" in members or "opencollection.yaml" in members:
                    conf = metadata(members.get("opencollection.yml") or members["opencollection.yaml"])
                    if conf.get("opencollection") != "1.0.0":
                        raise ValueError()
                    name = (conf.get("info") or {}).get("name") or name
            except (ValueError, TypeError):
                errors.append("Invalid or unsupported collection manifest; siblings remain available.")
            requests = [path for path in members if path.endswith((".bru", ".yml", ".yaml")) and not path.startswith("environments/")
                        and PurePosixPath(path).name not in {"folder.bru", "collection.bru", "folder.yml", "folder.yaml", "opencollection.yml", "opencollection.yaml"}]
            envs = sorted(str(PurePosixPath(path[len("environments/"):]).with_suffix("")) for path in members if path.startswith("environments/"))
            if len(requests) > LIMITS["requests_per_collection"] or len(members) > 2200:
                errors.append("Collection exceeds 2000 requests or 2200 definition/metadata files; select a smaller source.")
            row = {"source_id": source_id, "title": str(name), "root": root, "format": "yaml" if any(PurePosixPath(p).name.startswith("opencollection.") for p in members) else "bru",
                   "environments": envs, "environment": None if envs else "", "selected": not errors and bool(requests), "request_count": len(requests),
                   "requests": [{"id": path, "name": PurePosixPath(path).stem, "folder": str(PurePosixPath(path).parent) if "/" in path else ""} for path in requests],
                   "warnings": [], "errors": errors}
            job["groups"][source_id] = {"files": members, "summary": row}
            summaries.append(row)
        with self._lock:
            self._check(job)
            job["public"]["collections"] = summaries
            job["public"]["progress"].update(collections=len(summaries), total_files=job["public"]["progress"]["files_seen"])
            job["public"]["timings"]["discovery_ms"] = round((time.perf_counter() - job["stage_started"]) * 1000, 2)
            job["public"]["status"] = "discovered"

    def review(self, identifier, body):
        job = self._job(identifier)
        selections = body.get("selections")
        if not isinstance(selections, list) or not 1 <= len(selections) <= LIMITS["collections"]:
            raise ValueError("Select at least one collection to review.")
        selected = set()
        for selection in selections:
            source_id = selection.get("source_id") if isinstance(selection, dict) else None
            if source_id not in job["groups"] or source_id in selected:
                raise ValueError("Selected collection is absent or duplicated.")
            selected.add(source_id)
            env = selection.get("environment")
            available = job["groups"][source_id]["summary"]["environments"]
            if (env is None and available) or (env not in (None, "") and env not in available):
                raise ValueError("Explicitly choose an available environment or No environment for each selected collection.")
            ids = selection.get("request_ids")
            if ids is not None and (not isinstance(ids, list) or not ids or any(not isinstance(key, str) for key in ids) or len(ids) != len(set(ids))):
                raise ValueError("Select distinct request source IDs, or select the entire collection.")
        global_env = body.get("workspace_environment", "")
        if not isinstance(global_env, str) or (global_env and global_env not in job.get("global_files", {})):
            raise ValueError("Select an available workspace environment.")
        with self._lock:
            if job["public"]["status"] not in {"discovered", "reviewed", "failed"} or job["cancel"].is_set():
                raise ValueError("Wait for discovery to finish, or select the cancelled source again.")
            job["public"].update(status="parsing", review_id=None, errors=[], workspace_environment=global_env)
            job["prepared"] = []
            job["public"]["progress"]["parsed_collections"] = 0
            for row in job["public"]["collections"]:
                row["selected"] = row["source_id"] in selected
        self._pool.submit(self._run, job, "parsing", lambda: self._parse(job, copy.deepcopy(selections), global_env))
        return self.get(identifier)

    def _parse(self, job, selections, global_env):
        globals_ = []
        if global_env:
            from .bruno_yaml import definition
            environments = []
            for name, (path, content) in job["global_files"].items():
                self._check(job)
                kind = "environment" if path.endswith(".bru") else "yamlEnvironment"
                value = parser("parse", [{"kind": kind, "value": content}], cancel_event=job["cancel"])[0]
                if kind == "yamlEnvironment":
                    value = definition(value, kind)
                environments.append({**value, "name": name, "uid": name})
            target = next(env for env in environments if env["name"] == global_env)
            resolved = parser("parse", [{"kind": "resolveEnvironment", "value": {"environments": environments, "targetEnvironment": target, "merge": True}}], cancel_event=job["cancel"])[0]
            if resolved.get("missingInheritedEnvironmentName") or resolved.get("cyclicInheritancePath") or resolved.get("externalSecrets") or resolved.get("unsupportedTypedVariables"):
                raise ValueError("Workspace environment inheritance or external/typed secrets require explicit local review.")
            globals_ = resolved.get("variables") or []
        prepared, failed = [], False
        for selection in selections:
            self._check(job)
            group = job["groups"][selection["source_id"]]
            summary = group["summary"]
            summary["environment"] = selection.get("environment") or ""
            summary["request_ids"] = selection.get("request_ids")
            try:
                imported = import_collection([{"path": name, "content": content} for name, content in group["files"].items()],
                                             environment=summary["environment"], global_variables=globals_, cancel_event=job["cancel"])
                if imported.get("requires_environment"):
                    raise ValueError("Select an explicit environment before importing.")
                order_requests(imported, job["cancel"])
                ids = selection.get("request_ids")
                all_requests = imported["requests"]
                if ids is not None:
                    if set(ids) - {row["id"] for row in imported["requests"]}:
                        raise ValueError("A selected request no longer exists in this immutable source snapshot.")
                    imported["requests"] = [row for row in imported["requests"] if row["id"] in ids]
                imported["provenance"] = {"source_id": summary["source_id"], "root": summary["root"], "format": summary["format"],
                                          "workspace_environment": global_env, "bruno_version": "4.2.1", "filestore_version": "0.13.0"}
                created = collection(imported)
                prepared.append(created)
                with self._lock:
                    summary.update(requests=all_requests, warnings=imported["warnings"], errors=[], request_count=len(all_requests),
                                   selected_request_count=len(imported["requests"]))
            except ValueError as error:
                summary["errors"] = [str(error)]
                failed = True
            with self._lock:
                self._check(job)
                job["public"]["progress"]["parsed_collections"] += 1
        with self._lock:
            self._check(job)
            if failed:
                job["public"]["status"] = "failed"
                job["public"]["errors"] = ["A selected collection failed review; no collections were imported. Deselect it or choose a corrected source."]
            else:
                job["prepared"] = prepared
                job["public"]["timings"]["parsing_ms"] = round((time.perf_counter() - job["stage_started"]) * 1000, 2)
                job["public"].update(status="reviewed", review_id=uuid.uuid4().hex)

    def import_reviewed(self, identifier, body):
        job = self._job(identifier)
        with self._lock:
            if job["public"]["status"] != "reviewed" or body.get("review_id") != job["public"]["review_id"] or job["cancel"].is_set():
                raise ValueError("Review the selected collections before importing; this review is stale or incomplete.")
            workspace_id = body.get("workspace_id")
            if not isinstance(workspace_id, str):
                raise ValueError("Select the existing Namazu workspace receiving these collections.")
            job["public"]["status"] = "importing"
        self._pool.submit(self._run, job, "import", lambda: self._commit(job, workspace_id))
        return self.get(identifier)

    def _commit(self, job, workspace_id):
        from . import workspaces
        service = self.workspace_service or workspaces.service()
        self._check(job)
        with service._lock:
            workspace = service._load(workspace_id)
            collections = workspace.setdefault("request_collections", [])
            identifiers, duplicates, additions = [], [], []
            for created in job["prepared"]:
                self._check(job)
                existing = next((row for row in collections if row.get("source_hash") == created.get("source_hash") and row.get("hash") == created.get("hash")), None)
                if existing:
                    identifiers.append(existing["id"])
                    duplicates.append(existing["id"])
                else:
                    identifiers.append(created["id"])
                    additions.append(copy.deepcopy(created))
            if len(collections) + len(additions) > 100:
                raise ValueError("The selected import would exceed 100 request collections in this workspace.")
            # Cancellation and commit share a lock. A successful commit is the
            # boundary after which Cancel cannot falsely claim a rollback.
            with self._lock:
                self._check(job)
                if additions:
                    collections.extend(additions)
                    service._invalidate(workspace, "Reviewed Bruno collections were added; existing controls remain unchanged")
                    service._save(workspace)
                job["public"]["result"] = {"workspace": service.get(workspace_id), "collection_ids": identifiers,
                                           "duplicates": duplicates, "requests_sent": 0}
                job["public"]["timings"]["import_ms"] = round((time.perf_counter() - job["stage_started"]) * 1000, 2)
                job["public"]["status"] = "completed"
                job["files"], job["prepared"] = {}, []
                job["groups"] = {}
                job["global_files"] = {}

    def active_count(self):
        with self._lock:
            return sum(job["public"]["status"] in {"discovering", "parsing", "importing"} for job in self._jobs.values())

    def stop_all(self):
        for identifier in list(self._jobs):
            if self.get(identifier)["status"] in {"discovering", "discovered", "parsing", "reviewed", "importing"}:
                self.cancel(identifier)


_service = None


def service():
    global _service
    if _service is None:
        _service = SourceJobs()
    return _service
