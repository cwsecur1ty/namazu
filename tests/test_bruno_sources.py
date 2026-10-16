"""Multi-source definition imports remain local, bounded and atomic."""
from __future__ import annotations

import base64
import copy
import io
import json
import socket
import stat
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from namazu import bruno_sources, desktop_runtime, workspaces
from namazu.bruno_collections import import_collection, parser
from namazu.bruno_source_routes import router
from namazu.request_collections import collection, restore

FIXTURE = Path(__file__).parent / "fixtures/bruno/workspace"


@pytest.fixture
def jobs(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Source discovery/import must never send network requests")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    workspace_service = workspaces.WorkspaceService(tmp_path / "workspaces.db")
    manager = bruno_sources.SourceJobs(workspace_service)
    yield manager, workspace_service
    manager.close()
    workspace_service.close()


def wait(manager, job, expected=None):
    identifier = job["id"] if isinstance(job, dict) else job
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        value = manager.get(identifier)
        if value["status"] not in {"discovering", "parsing", "importing"}:
            if expected:
                assert value["status"] == expected, value.get("errors") or value
            return value
        time.sleep(0.01)
    raise AssertionError("Offline import job did not finish")


def archive_body():
    return {"zip_base64": base64.b64encode((FIXTURE / "workspace.zip").read_bytes()).decode(), "filename": "workspace.zip"}


def selections(job, **changes):
    return {"workspace_environment": "Global", "selections": [
        {"source_id": row["source_id"], "environment": "Local", **changes} for row in job["collections"]]}


def basic_files(root="one", *, broken=False):
    request = ("not valid bru fixture" if broken else
               "meta {\n name: Example\n type: http\n seq: 1\n}\nget {\n url: http://127.0.0.1:9/example\n body: none\n auth: none\n}\n")
    return [{"path": root + "/bruno.json", "content": json.dumps({"version": "1", "type": "collection", "name": "Identical name"})},
            {"path": root + "/Example.bru", "content": request}]


def test_official_serializer_zip_preserves_boundaries_order_globals_inheritance_and_no_requests(jobs):
    manager, service = jobs
    original = service.create("Existing workspace")
    service.set_profile(original["id"], {"id": "keep", "token": "never-import-this-secret"})
    before = service.get(original["id"])
    job = wait(manager, manager.create(archive_body()), "discovered")
    assert job["workspace_environments"] == ["Global"]
    assert [row["format"] for row in job["collections"]] == ["yaml", "bru"]
    assert [row["request_count"] for row in job["collections"]] == [4, 4]
    assert len({row["source_id"] for row in job["collections"]}) == 2
    reviewed = wait(manager, manager.review(job["id"], selections(job)), "reviewed")
    assert service.get(original["id"]) == before
    for row in reviewed["collections"]:
        assert row["requests"][0]["name"] == "No auth"
        assert [item["name"] for item in row["requests"]] == ["No auth", "Same request", "Same request", "Inert script"]
        assert [item["request"]["body"] for item in row["requests"][:3]] == ["null", "false", "0"]
        assert all("global=from-workspace" in item["request"]["url"] for item in row["requests"])
        assert all("layer=request" in item["request"]["url"] for item in row["requests"])
        assert row["requests"][-1]["can_prepare"] is False
    done = wait(manager, manager.import_reviewed(job["id"], {"workspace_id": original["id"], "review_id": reviewed["review_id"]}), "completed")
    result = done["result"]["workspace"]
    assert result["profiles"] == before["profiles"]
    assert result["contracts"] == before["contracts"]
    assert len(result["request_collections"]) == 2
    assert len({operation["id"] for row in result["request_collections"] for operation in row["operations"]}) == 8
    assert all(row["provenance"]["workspace_environment"] == "Global" for row in result["request_collections"])
    assert done["requests_sent"] == done["result"]["requests_sent"] == 0
    assert all(done["timings"][key] is not None for key in ("discovery_ms", "parsing_ms", "import_ms"))
    restored = service.restore(service.export(original["id"]))
    assert [row["provenance"] for row in restored["request_collections"]] == [row["provenance"] for row in result["request_collections"]]


def test_duplicate_contents_at_distinct_roots_remain_separate_and_reimport_is_idempotent(jobs):
    manager, service = jobs
    workspace = service.create()
    body = {"files": basic_files("one") + basic_files("two")}
    def import_again():
        job = wait(manager, manager.create(body), "discovered")
        review = wait(manager, manager.review(job["id"], {"selections": [{"source_id": row["source_id"], "environment": ""} for row in job["collections"]]}), "reviewed")
        return wait(manager, manager.import_reviewed(job["id"], {"workspace_id": workspace["id"], "review_id": review["review_id"]}), "completed")["result"]
    first, second = import_again(), import_again()
    assert len(set(first["collection_ids"])) == 2
    assert second["collection_ids"] == first["collection_ids"]
    assert second["duplicates"] == first["collection_ids"]
    assert len(second["workspace"]["request_collections"]) == 2


def test_subset_review_keeps_full_preview_and_ancestor_configuration(jobs):
    manager, _service = jobs
    job = wait(manager, manager.create(archive_body()), "discovered")
    row = job["collections"][0]
    selected_id = "Same folder/First.yml"
    review = wait(manager, manager.review(job["id"], {"workspace_environment": "Global", "selections": [
        {"source_id": row["source_id"], "environment": "Local", "request_ids": [selected_id]}]}), "reviewed")
    preview = next(item for item in review["collections"] if item["source_id"] == row["source_id"])
    assert preview["request_count"] == len(preview["requests"]) == 4
    assert preview["selected_request_count"] == 1
    operation = manager._job(job["id"])["prepared"][0]["operations"][0]
    assert operation["local_id"] == selected_id
    assert operation["request_definition"]["request"]["headers"]["X-Inherited"] == "collection"


def test_failed_sibling_never_commits_and_can_be_deselected(jobs):
    manager, service = jobs
    workspace = service.create()
    job = wait(manager, manager.create({"files": basic_files("good") + basic_files("bad", broken=True)}), "discovered")
    failed = wait(manager, manager.review(job["id"], {"selections": [{"source_id": row["source_id"], "environment": ""} for row in job["collections"]]}), "failed")
    assert not service.get(workspace["id"]).get("request_collections")
    assert any(row["errors"] for row in failed["collections"])
    selected = next(row for row in failed["collections"] if row["root"] == "good")
    reviewed = wait(manager, manager.review(job["id"], {"selections": [{"source_id": selected["source_id"], "environment": ""}]}), "reviewed")
    done = wait(manager, manager.import_reviewed(job["id"], {"workspace_id": workspace["id"], "review_id": reviewed["review_id"]}), "completed")
    assert len(done["result"]["collection_ids"]) == 1


def zip_body(entries):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for key, content in entries:
            archive.writestr(key, content)
    raw = data.getvalue()
    # ZipInfo normalizes the host separator on Windows; explicitly construct
    # the adversarial archive bytes for the backslash-path regression.
    for key, _content in entries:
        if isinstance(key, str) and "\\" in key:
            raw = raw.replace(key.replace("\\", "/").encode(), key.encode())
    return {"zip_base64": base64.b64encode(raw).decode()}


@pytest.mark.parametrize("path", ["../outside.bru", "/absolute.bru", "C:/file.bru", "root\\file.bru", "root/file.bru:stream", "a//file.bru"])
def test_zip_traversal_and_ambiguous_paths_are_rejected_without_extraction(jobs, path):
    manager, _service = jobs
    job = wait(manager, manager.create(zip_body([(path, "secret fixture text")])), "failed")
    assert "secret fixture text" not in json.dumps(job)


def test_zip_links_duplicates_and_bombs_are_rejected(jobs):
    manager, _service = jobs
    symlink = zipfile.ZipInfo("linked.bru")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    bodies = [zip_body([(symlink, "/outside/file")]), zip_body([("A.bru", "x"), ("a.bru", "x")]),
              zip_body([("bomb.bru", "X" * (2 * 1024 * 1024))])]
    for body in bodies:
        assert wait(manager, manager.create(body), "failed")["errors"]


def test_native_discovery_skips_dependencies_and_never_follows_workspace_external_refs(jobs, tmp_path):
    manager, _service = jobs
    root = tmp_path / "source"
    for file in basic_files("collection"):
        target = root / file["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file["content"])
    (root / "node_modules" / "nested").mkdir(parents=True)
    (root / "node_modules" / "nested" / "broken.bru").write_text("not parsed")
    (root / "workspace.yml").write_text("opencollection: 1.0.0\ninfo:\n  name: Local\n  type: workspace\ncollections:\n  - name: Outside\n    path: ../never-read\n")
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    job = wait(manager, manager.native(str(root.resolve())), "discovered")
    assert len(job["collections"]) == 1 and job["progress"]["skipped"] >= 1
    assert any("external" in warning for warning in job["warnings"])
    assert {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
    assert str(root) not in json.dumps(job)


def test_reparse_and_symlink_flags_are_rejected():
    assert bruno_sources._linked(SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400))
    assert bruno_sources._linked(SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0))
    assert not bruno_sources._linked(SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0))


def test_cancel_during_parse_keeps_workspace_unchanged(jobs, monkeypatch):
    manager, service = jobs
    workspace = service.create()
    job = wait(manager, manager.create({"files": basic_files()}), "discovered")
    entered, release = threading.Event(), threading.Event()
    original = bruno_sources.import_collection
    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(bruno_sources, "import_collection", paused)
    manager.review(job["id"], {"selections": [{"source_id": job["collections"][0]["source_id"], "environment": ""}]})
    assert entered.wait(5)
    assert manager.cancel(job["id"])["status"] == "cancelled"
    release.set()
    assert not service.get(workspace["id"]).get("request_collections")
    with pytest.raises(ValueError, match="stale or incomplete"):
        manager.import_reviewed(job["id"], {"workspace_id": workspace["id"], "review_id": None})


def test_failed_atomic_save_keeps_original_workspace(jobs, monkeypatch):
    manager, service = jobs
    workspace = service.create()
    before = service.get(workspace["id"])
    job = wait(manager, manager.create({"files": basic_files()}), "discovered")
    review = wait(manager, manager.review(job["id"], {"selections": [{"source_id": job["collections"][0]["source_id"], "environment": ""}]}), "reviewed")
    def disk_full(_workspace):
        raise OSError("private-root secret should not appear")
    monkeypatch.setattr(service, "_save", disk_full)
    failed = wait(manager, manager.import_reviewed(job["id"], {"workspace_id": workspace["id"], "review_id": review["review_id"]}), "failed")
    assert "private-root" not in json.dumps(failed)
    assert service.get(workspace["id"]) == before


def test_native_route_requires_distinct_native_capability_not_browser_session(jobs, monkeypatch):
    manager, _service = jobs
    monkeypatch.setattr(bruno_sources, "service", lambda: manager)
    monkeypatch.setattr(desktop_runtime, "_native_secret", "n" * 64)
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        body = {"root": str((FIXTURE / "source").resolve())}
        assert client.post("/api/bruno/sources/native", json=body).status_code == 403
        assert client.post("/api/bruno/sources/native", json=body, headers={"X-Namazu-Session": "s" * 64}).status_code == 403
        response = client.post("/api/bruno/sources/native", json=body, headers={"X-Namazu-Native": "n" * 64})
        assert response.status_code == 200
        wait(manager, response.json(), "discovered")


def test_browser_source_body_rejects_filesystem_paths(jobs):
    manager, _service = jobs
    with pytest.raises(ValueError, match="filesystem paths"):
        manager.create({"root": str(FIXTURE)})


def test_environment_cycles_remain_blocked_and_yaml_is_deterministic():
    files = [{"path": path.relative_to(FIXTURE / "source/collections/YAML").as_posix(), "content": path.read_text()}
             for path in (FIXTURE / "source/collections/YAML").rglob("*") if path.is_file()]
    one = import_collection(files, environment="Local", global_variables=[{"name": "global_value", "value": "test", "enabled": True}])
    two = import_collection(files, environment="Local", global_variables=[{"name": "global_value", "value": "test", "enabled": True}])
    assert one == two
    cycle = copy.deepcopy(files)
    next(row for row in cycle if row["path"] == "environments/Base.yml")["content"] += "\nextends: Local\n"
    blocked = import_collection(cycle, environment="Local")
    assert all(not row["can_prepare"] for row in blocked["requests"])


def test_oauth_client_credentials_mapping_never_materializes_secret():
    source = """meta {
 name: OAuth
 type: http
 seq: 1
}
get {
 url: http://127.0.0.1:9/item
 body: none
 auth: oauth2
}
auth:oauth2 {
 grant_type: client_credentials
 access_token_url: http://127.0.0.1:9/token
 client_id: fixture-client
 client_secret: fixture-private-secret
 scope: read
 credentials_placement: body
 token_placement: header
 token_header_prefix: Bearer
}
"""
    row = import_collection([{"path": "OAuth.bru", "content": source}], environment="")["requests"][0]
    mapping = row["oauth_client_credentials"]
    assert mapping["grant"] == "client_credentials" and mapping["client_id"] == "fixture-client"
    assert "fixture-private-secret" not in json.dumps(row)
    assert mapping["secret_reference"] == "local client secret required"
    bad = source.replace("token_placement: header", "token_placement: url")
    assert import_collection([{"path": "OAuth.bru", "content": bad}], environment="")["requests"][0]["oauth_client_credentials"] is None


def test_official_order_function_handles_equal_sequence_without_merging():
    ordered = parser("parse", [{"kind": "sortLists", "value": [[{"name": "Z", "seq": 1}, {"name": "A", "seq": 1}, {"name": "B"}]]}])[0][0]
    assert [row["name"] for row in ordered] == ["A", "Z", "B"]


def test_parser_subprocess_is_terminated_promptly_on_cancel(tmp_path, monkeypatch):
    from namazu import bruno_collections
    delayed = tmp_path / "delayed.cjs"
    delayed.write_text("setTimeout(() => process.exit(0), 30000);")
    monkeypatch.setattr(bruno_collections, "BRIDGE", delayed)
    cancel = threading.Event()
    timer = threading.Timer(0.15, cancel.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(ValueError, match="cancelled"):
            parser("parse", [], cancel_event=cancel)
    finally:
        timer.cancel()
    assert time.monotonic() - started < 3


def test_unknown_yaml_features_are_not_silently_lost():
    content = "info:\n  name: Unknown\n  type: http\nhttp:\n  method: GET\n  url: http://127.0.0.1:9/local\nfutureExecutableHook: do-not-run\n"
    row = import_collection([{"path": "unknown.yml", "content": content}], environment="")["requests"][0]
    assert not row["can_prepare"]
    assert row["definition"]["unsupported_yaml_features"] == ["futureExecutableHook"]


def test_forged_restored_oauth_mapping_cannot_clear_unsupported_flow():
    content = """info:
  name: OAuth
  type: http
http:
  method: GET
  url: http://127.0.0.1:9/local
  auth:
    type: oauth2
    flow: client_credentials
    accessTokenUrl: http://127.0.0.1:9/token
    credentials:
      clientId: fixture-client
      clientSecret: fixture-secret
      placement: body
    tokenConfig:
      placement:
        query: access_token
"""
    parsed = import_collection([{"path": "oauth.yml", "content": content}], environment="")
    row = parsed["requests"][0]
    assert row["authentication_mode"] == "oauth2" and row["oauth_client_credentials"] is None
    row["oauth_client_credentials"] = {"grant": "client_credentials", "endpoint": "http://127.0.0.1:9/token", "client_id": "fixture-client", "scope": "", "credential_placement": "post"}
    imported = collection(parsed)
    saved = imported["material"]["requests"][0]
    assert saved["oauth_client_credentials"] is None and not saved["can_prepare"]
    restored = restore(imported)
    assert restored["operations"][0]["request_definition"]["oauth_client_credentials"] is None
