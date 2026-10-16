"""Desktop persistence tests use temporary paths and inert data only."""
from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from namazu import desktop_state
from namazu.audit.run_store import RunStore, default_db_path
from namazu.credential_store import CredentialStore, CredentialStoreError, DPAPIProvider
from namazu.desktop_state import (
    STATE_FORMAT,
    DesktopPaths,
    StateConflict,
    StateStorageError,
    StateStore,
    StateVersionError,
    data_paths,
    initialize_data,
    sanitise_browser_preferences,
)
from namazu.workspaces import WorkspaceService


class FakeProvider:
    """Reversible fake for storage tests, never a production encryption option."""
    name = "test-only"

    def protect(self, data, context):
        return hashlib.sha256(context).digest() + data[::-1]

    def unprotect(self, data, context):
        if data[:32] != hashlib.sha256(context).digest():
            raise ValueError("Bad test binding")
        return data[32:][::-1]


def payload(revision=0, **state):
    return {"version": 1, "revision": revision, "state": state}


def test_paths_are_per_user_and_environment_override_is_respected(tmp_path):
    paths = data_paths(environ={"LOCALAPPDATA": str(tmp_path / "local")}, platform="win32", home=tmp_path)
    assert paths.root == tmp_path / "local" / "Namazu"
    assert paths.ui_state == paths.root / "config" / "desktop-state.json"
    assert paths.runs_db == paths.root / "evidence" / "runs.db"
    assert paths.workspaces_db == paths.root / "workspaces" / "workspaces.db"
    custom = data_paths(environ={"NAMAZU_STATE_DIR": str(tmp_path / "custom")}, platform="win32")
    assert custom.root == tmp_path / "custom"


def test_data_directory_failure_is_reported_without_touching_legacy(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    original = legacy / "runs.db"
    original.write_bytes(b"retained original")
    def fail(_):
        raise OSError(errno.ENOSPC, "disk full")
    monkeypatch.setattr(DesktopPaths, "ensure", fail)
    with pytest.raises(StateStorageError, match="original databases"):
        initialize_data(data_paths(tmp_path / "desktop"), legacy_dir=legacy)
    assert original.read_bytes() == b"retained original"
    assert not (tmp_path / "desktop").exists()


def test_default_database_layout_changes_only_for_desktop(tmp_path, monkeypatch):
    monkeypatch.setenv("NAMAZU_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("NAMAZU_DESKTOP", raising=False)
    assert default_db_path() == tmp_path / "runs.db"
    monkeypatch.setenv("NAMAZU_DESKTOP", "1")
    assert default_db_path() == tmp_path / "evidence" / "runs.db"


def test_browser_preferences_are_allowlisted_validated_and_roundtrip_as_strings():
    data = {"namazu-theme": "dark", "namazu-layout": "rows", "namazu-panel-w": "320", "namazu-req-basis": "50",
            "namazu-wrap": "1", "namazu-group-mode": "path", "namazu-history-limit": "100",
            "namazu-examples:Old API:http://localhost/v1": json.dumps({"GET /widgets": {
                "example": {"url": "http://localhost/v1/widgets", "headers": {"Authorization": "Bearer imported-secret"},
                            "body": {"password": "imported-password", "count": 2}}, "expectation": {"status": 200}}}),
            "namazu-access:workspace:contract:hash:target:profile:1:default:tab:http://localhost/v1": json.dumps({
                "matrix": [{"method": "GET", "identity": "primary", "url": "http://localhost/v1/widgets", "expect": "deny"}],
                "sequence": [{"headers": {"X-Api-Key": "sequence-secret"}, "body": '{"client_secret":"body-secret","count":3}'}]})}
    result = sanitise_browser_preferences({"preferences": data})
    assert result["format"] == "namazu-browser-preferences" and result["version"] == 1
    assert set(result["preferences"]) == set(data)
    assert all(isinstance(value, str) for value in result["preferences"].values())
    text = json.dumps(result)
    for secret in ("imported-secret", "imported-password", "sequence-secret", "body-secret"):
        assert secret not in text
    example = json.loads(result["preferences"]["namazu-examples:Old API:http://localhost/v1"])["GET /widgets"]
    assert example["expectation"]["status"] == 200
    assert example["example"]["body"]["count"] == 2
    assert sanitise_browser_preferences(result) == result


@pytest.mark.parametrize("key,value", [
    ("namazu-auth", "secret"), ("namazu-oauth", "secret"), ("namazu-proxy", "http://user:password@localhost"),
    ("namazu-settings", "{}"), ("../../preferences.json", "{}"), ("namazu-tools-after-audit", "1"),
    ("namazu-theme", "<script>"), ("namazu-history-limit", "999999"), ("namazu-panel-w", "nan"),
    ("namazu-req-basis", "1000"), ("namazu-access:api", "[]"), ("namazu-access:api", '{"script":"danger"}'),
    ("namazu-examples:api", '{"__proto__":{"polluted":true}}'), ("namazu-examples:api", "broken"),
    ("namazu-examples:http://token:secret@localhost", "{}"),
])
def test_browser_preferences_reject_unsupported_keys_and_values(key, value):
    with pytest.raises(ValueError):
        sanitise_browser_preferences({"preferences": {key: value}})


def test_browser_preference_migration_masks_available_profile_echoes_without_assigning_or_running(tmp_path):
    vault = CredentialStore(tmp_path / "vault", provider=FakeProvider())
    service = WorkspaceService(tmp_path / "workspaces.db", credential_store=vault)
    workspace = service.create("local")
    service.set_profile(workspace["id"], {"id": "shared", "token": "current-fixture-secret", "persistence": "windows"})
    # A fresh service must recognize an existing encrypted local value too.
    restored = WorkspaceService(service.path, credential_store=CredentialStore(tmp_path / "vault", provider=FakeProvider()))
    before = restored.get(workspace["id"])
    result = sanitise_browser_preferences({"preferences": {"namazu-examples:local:http://localhost": json.dumps({
        "GET /widgets": {"example": {"headers": {"X-Legacy-Credential": "current-fixture-secret"},
                                     "body": {"echo": "current-fixture-secret", "text": "<script>never executed</script>"}},
                         "identity_ref": "shared", "snapshot_hash": "original-hash"}})}}, redact=restored.sanitise_local_data)
    assert "current-fixture-secret" not in json.dumps(result)
    parsed = json.loads(next(iter(result["preferences"].values())))
    assert parsed["GET /widgets"]["identity_ref"] == "shared"
    assert parsed["GET /widgets"]["snapshot_hash"] == "original-hash"
    assert parsed["GET /widgets"]["example"]["body"]["text"] == "<script>never executed</script>"
    assert restored.get(workspace["id"]) == before
    assert not before["contracts"] and not before["runs"]
    restored._conn.close()
    service._conn.close()


def test_versioned_state_keeps_workspace_drafts_and_rejects_stale_window(tmp_path):
    first, second = StateStore(tmp_path), StateStore(tmp_path)
    assert first.get()["revision"] == 0
    draft = {"workspaces": {"w1": {"tabs": [{"id": "tab1", "contract_id": "c1", "snapshot_hash": "abc"}],
                                  "drafts": {"tab1": {"body": {"ordinary": 2}}}}},
             "preferences": {"theme": "dark"}}
    saved = first.put(payload(**draft))
    assert saved["revision"] == 1
    assert second.get()["state"] == draft
    with pytest.raises(StateConflict) as conflict:
        second.put(payload(preferences={"theme": "light"}))
    assert conflict.value.current["revision"] == 1
    assert first.get()["state"] == draft
    assert json.loads(first.path.read_text())["format"] == STATE_FORMAT


def test_concurrent_state_writers_cannot_both_commit_same_revision(tmp_path):
    def write(label):
        try:
            return StateStore(tmp_path).put(payload(preferences={"label": label}))["revision"]
        except StateConflict:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(write, ["one", "two"]))
    assert sorted(map(str, results)) == ["1", "conflict"]


def test_state_masks_draft_headers_environment_values_and_raw_text_preserving_refs(tmp_path):
    store = StateStore(tmp_path)
    state = {"workspaces": {"w": {"drafts": {"t": {
        "headers": {"Authorization": "Bearer local-bearer-value", "Accept": "application/json"},
        "body": {"password": "local-password-value", "ordinary": "keep", "count": 200},
        "raw": "GET / HTTP/1.1\r\nAuthorization: Bearer local-header-value\r\n\r\n",
        "pasted": '{"access_token":"local-json-value","allowed":true}',
        "identityRef": "profile-alpha", "secret_ref": "opaque-secret-reference",
        "snapshot_hash": "hash-original", "classification": "request-sent", "status": "permission-denied",
    }}}}, "environments": [{"key": "ACCESS_TOKEN", "value": "local-env-value"},
                            {"name": "REGION", "value": "local"}]}
    saved = store.put(payload(**state))["state"]
    text = store.path.read_text()
    for secret in ("local-bearer-value", "local-password-value", "local-header-value", "local-json-value", "local-env-value"):
        assert secret not in text
    draft = saved["workspaces"]["w"]["drafts"]["t"]
    assert draft["identityRef"] == "profile-alpha"
    assert draft["secret_ref"] == "opaque-secret-reference"
    assert draft["classification"] == "request-sent"
    assert draft["status"] == "permission-denied"
    assert draft["snapshot_hash"] == "hash-original"
    assert draft["body"]["count"] == 200
    assert saved["environments"][1]["value"] == "local"


def test_state_preserves_context_ids_with_short_auth_secret_and_masks_auth_value(tmp_path):
    store = StateStore(tmp_path)
    value = store.put(payload(activeWorkspaceId="workspace-alpha", tabs=[{
                                    "id": "tab-alpha", "workspaceId": "workspace-alpha", "contractId": "contract-alpha",
                                    "snapshotHash": "hash-alpha", "localOperationId": "GET /alpha", "operationKey": "operation-alpha",
                                    "key": '["workspace-alpha", "operation-alpha"]',
                                    "draft": {"auth": {"type": "bearer", "value": "a", "credential_ref": "ref-alpha"},
                                              "bearer": "long-fixture-token"}}]))["state"]
    tab = value["tabs"][0]
    assert tab["id"] == "tab-alpha"
    assert tab["contractId"] == "contract-alpha"
    assert tab["snapshotHash"] == "hash-alpha"
    assert value["activeWorkspaceId"] == "workspace-alpha"
    assert tab["localOperationId"] == "GET /alpha"
    assert tab["key"] == '["workspace-alpha", "operation-alpha"]'
    assert tab["draft"]["auth"]["credential_ref"] == "ref-alpha"
    assert tab["draft"]["auth"]["value"] == "<credential>"
    assert tab["draft"]["bearer"] == "<credential>"


def test_corrupt_state_recovers_backup_and_retains_corrupt_original(tmp_path):
    store = StateStore(tmp_path)
    store.put(payload(preferences={"theme": "dark"}))
    store.put(payload(1, preferences={"theme": "light"}))
    store.path.write_bytes(b"broken{state")
    recovered = store.get()
    assert recovered["revision"] == 1
    assert recovered["state"]["preferences"]["theme"] == "dark"
    assert recovered["recovery"]["source"] == "backup"
    assert (store.path.parent / recovered["recovery"]["corrupt_copy"]).read_bytes() == b"broken{state"


def test_unrecoverable_state_keeps_bytes_and_explains_default_recovery(tmp_path):
    store = StateStore(tmp_path)
    store.path.parent.mkdir(parents=True)
    store.path.write_bytes(b"broken")
    recovered = store.get()
    assert recovered["revision"] == 0
    assert recovered["recovery"]["source"] == "defaults"
    assert (store.path.parent / recovered["recovery"]["corrupt_copy"]).read_bytes() == b"broken"


def test_newer_state_version_is_never_replaced(tmp_path):
    store = StateStore(tmp_path)
    store.path.parent.mkdir(parents=True)
    future = json.dumps({"format": STATE_FORMAT, "version": 77, "revision": 1, "state": {}}).encode()
    store.path.write_bytes(future)
    with pytest.raises(StateVersionError):
        store.get()
    assert store.path.read_bytes() == future


@pytest.mark.parametrize("failure", ["disk-full", "replace-denied"])
def test_failed_state_write_retains_original_and_revision(tmp_path, monkeypatch, failure):
    store = StateStore(tmp_path)
    store.put(payload(preferences={"retained": True}))
    original = store.path.read_bytes()
    if failure == "disk-full":
        def fail(*args, **kwargs):
            raise OSError(errno.ENOSPC, "Fixture disk full")
        monkeypatch.setattr(desktop_state, "_stage_bytes", fail)
    else:
        original_replace = os.replace
        def fail(source, destination):
            if Path(destination) == store.path:
                raise PermissionError("Fixture permission failure")
            return original_replace(source, destination)
        monkeypatch.setattr(desktop_state.os, "replace", fail)
    with pytest.raises(StateStorageError, match="previous state"):
        store.put(payload(1, preferences={"lost": True}))
    assert store.path.read_bytes() == original
    assert store.get()["revision"] == 1


def make_legacy(path, label):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE retained(value TEXT)")
    db.execute("INSERT INTO retained VALUES(?)", (label,))
    db.commit()
    return db


def test_legacy_sqlite_migration_captures_wal_preserves_sources_and_is_idempotent(tmp_path):
    legacy, paths = tmp_path / "legacy", DesktopPaths(tmp_path / "desktop")
    run_db = make_legacy(legacy / "runs.db", "committed-in-wal")
    workspace_db = make_legacy(legacy / "workspaces.db", "workspace")
    try:
        assert (legacy / "runs.db-wal").exists()
        result = initialize_data(paths, legacy_dir=legacy)
        assert len(result["manifest"]["entries"]) == 2
        for entry in result["manifest"]["entries"]:
            assert Path(entry["source"]).exists()
            assert Path(entry["backup"]).exists()
            assert hashlib.sha256(Path(entry["backup"]).read_bytes()).hexdigest() == entry["sha256"]
        with sqlite3.connect(paths.runs_db) as db:
            assert db.execute("SELECT value FROM retained").fetchone()[0] == "committed-in-wal"
            db.execute("INSERT INTO retained VALUES('new-desktop-row')")
        repeat = initialize_data(paths, legacy_dir=legacy)
        assert len(repeat["manifest"]["entries"]) == 2
        with sqlite3.connect(paths.runs_db) as db:
            assert db.execute("SELECT COUNT(*) FROM retained").fetchone()[0] == 2
        assert run_db.execute("SELECT COUNT(*) FROM retained").fetchone()[0] == 1
    finally:
        run_db.close()
        workspace_db.close()


def test_migration_prioritises_explicit_old_state_root_and_never_overwrites_destination(tmp_path):
    paths, legacy = DesktopPaths(tmp_path / "desktop"), tmp_path / "legacy"
    source = make_legacy(paths.root / "runs.db", "explicit-root")
    other = make_legacy(legacy / "runs.db", "old-home")
    try:
        initialize_data(paths, legacy_dir=legacy)
        with sqlite3.connect(paths.runs_db) as db:
            assert db.execute("SELECT value FROM retained").fetchone()[0] == "explicit-root"
        assert (legacy / "runs.db").exists()
    finally:
        source.close()
        other.close()


def test_migration_failure_keeps_original_database(tmp_path, monkeypatch):
    paths, legacy = DesktopPaths(tmp_path / "desktop"), tmp_path / "legacy"
    db = make_legacy(legacy / "runs.db", "retain")
    try:
        def fail(*args, **kwargs):
            raise OSError(errno.ENOSPC, "Fixture disk full")
        monkeypatch.setattr(desktop_state, "atomic_write", fail)
        with pytest.raises(StateStorageError, match="original databases"):
            initialize_data(paths, legacy_dir=legacy)
        assert not paths.runs_db.exists()
        assert db.execute("SELECT value FROM retained").fetchone()[0] == "retain"
    finally:
        db.close()


def test_corrupt_legacy_database_is_not_silently_replaced(tmp_path):
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "runs.db").write_bytes(b"corrupt legacy")
    paths = DesktopPaths(tmp_path / "desktop")
    with pytest.raises(StateStorageError):
        initialize_data(paths, legacy_dir=legacy)
    assert (legacy / "runs.db").read_bytes() == b"corrupt legacy"
    assert not paths.runs_db.exists()


def test_session_credentials_create_no_disk_file_and_disappear_in_new_process_store(tmp_path):
    vault = CredentialStore(tmp_path, provider=FakeProvider())
    vault.put("profile-one", "fixture-secret", mode="session")
    assert vault.get("profile-one") == "fixture-secret"
    assert not vault.path.exists()
    assert CredentialStore(tmp_path, provider=FakeProvider()).get("profile-one") is None


def test_opt_in_credentials_are_encrypted_bound_to_reference_and_removable(tmp_path):
    vault = CredentialStore(tmp_path, provider=FakeProvider())
    vault.put("profile-one", "fixture-secret", mode="windows")
    assert "fixture-secret" not in vault.path.read_text()
    reopened = CredentialStore(tmp_path, provider=FakeProvider())
    assert reopened.get("profile-one") == "fixture-secret"
    envelope = json.loads(vault.path.read_text())
    envelope["entries"]["profile-two"] = copy.deepcopy(envelope["entries"]["profile-one"])
    vault.path.write_text(json.dumps(envelope))
    with pytest.raises(CredentialStoreError):
        reopened.get("profile-two")
    vault.delete("profile-one")
    assert reopened.get("profile-one") is None


def test_switching_to_session_only_removes_saved_encrypted_credential(tmp_path):
    vault = CredentialStore(tmp_path, provider=FakeProvider())
    vault.put("identity", "fixture-secret", mode="windows")
    vault.put("identity", "fixture-secret", mode="session")
    assert vault.get("identity") == "fixture-secret"
    assert CredentialStore(tmp_path, provider=FakeProvider()).get("identity") is None
    assert not (tmp_path / "credentials.json.bak").exists()


def test_credential_store_failure_has_no_plaintext_fallback(tmp_path, monkeypatch):
    vault = CredentialStore(tmp_path, provider=FakeProvider())
    vault.put("identity", "old-fixture", mode="windows")
    before = vault.path.read_bytes()
    def fail(*args, **kwargs):
        raise OSError(errno.ENOSPC, "Fixture disk full")
    monkeypatch.setattr("namazu.credential_store.atomic_write", fail)
    with pytest.raises(CredentialStoreError):
        vault.put("identity", "new-fixture", mode="windows")
    assert vault.path.read_bytes() == before
    assert vault.get("identity") == "old-fixture"


@pytest.mark.skipif(os.name != "nt", reason="DPAPI is supplied by Windows")
def test_real_windows_dpapi_roundtrip_and_context_binding():
    provider = DPAPIProvider()
    encrypted = provider.protect(b"local-fixture-value", b"local-fixture-reference")
    assert b"local-fixture-value" not in encrypted
    assert provider.unprotect(encrypted, b"local-fixture-reference") == b"local-fixture-value"
    with pytest.raises(CredentialStoreError):
        provider.unprotect(encrypted, b"other-reference")


def test_workspace_opt_in_secret_survives_restart_but_never_export_restore(tmp_path):
    directory, db = tmp_path / "secrets", tmp_path / "workspaces.db"
    vault = CredentialStore(directory, provider=FakeProvider())
    service = WorkspaceService(db, credential_store=vault)
    workspace = service.create()
    raw = {"openapi": "3.0.3", "info": {"title": "Local", "version": "1"}, "servers": [{"url": "http://127.0.0.1:9138/api"}],
           "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}}}
    workspace = service.import_contracts(workspace["id"], [{"raw_spec": raw}])
    contract = workspace["contracts"][0]
    workspace = service.set_profile(workspace["id"], {"name": "Saved", "token": "fixture-workspace-secret", "persistence": "windows"})
    profile = workspace["profiles"][0]
    service.assign_identity(workspace["id"], contract["id"], {"profile_id": profile["id"], "allowed_scopes": [contract["target"]]})
    exported = service.export(workspace["id"])
    assert "fixture-workspace-secret" not in json.dumps(exported)
    assert b"fixture-workspace-secret" not in db.read_bytes()
    service.close()
    reopened = WorkspaceService(db, credential_store=CredentialStore(directory, provider=FakeProvider()))
    try:
        assert reopened.get(workspace["id"])["profiles"][0]["credential_available"]
        args = (workspace["id"], contract["id"], contract["hash"], contract["operations"][0]["id"])
        assert reopened.request_context(*args, require_credential=False)["identities"] == {}
        assert reopened.request_context(*args)["identities"]["primary"]["headers"]["Authorization"] == "Bearer fixture-workspace-secret"
        restored = reopened.restore(exported)
        assert not restored["profiles"][0]["credential_available"]
        assert "credential_ref" not in restored["profiles"][0]
    finally:
        reopened.close()


@pytest.mark.parametrize("kind", ["runs", "workspaces"])
def test_sqlite_schema_zero_upgrade_preserves_existing_rows(tmp_path, kind):
    path = tmp_path / (kind + ".db")
    factory = RunStore if kind == "runs" else WorkspaceService
    store = factory(path)
    store.close()
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE retained_fixture(value TEXT)")
    db.execute("INSERT INTO retained_fixture VALUES('unchanged-evidence')")
    db.execute("PRAGMA user_version=0")
    db.commit()
    db.close()
    migrated = factory(path)
    migrated.close()
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT value FROM retained_fixture").fetchone()[0] == "unchanged-evidence"
    finally:
        db.close()


@pytest.mark.parametrize("kind", ["runs", "workspaces"])
def test_future_sqlite_schema_is_refused_without_modification(tmp_path, kind):
    path = tmp_path / (kind + ".db")
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE future(value TEXT)")
    db.execute("INSERT INTO future VALUES('retain')")
    db.execute("PRAGMA user_version=77")
    db.commit()
    db.close()
    original = path.read_bytes()
    factory = RunStore if kind == "runs" else WorkspaceService
    with pytest.raises(ValueError, match="unsupported schema version"):
        factory(path)
    assert path.read_bytes() == original
