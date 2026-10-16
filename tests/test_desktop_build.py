"""Release identity checks use local staged fixtures; they do not open a GUI."""
from __future__ import annotations

import hashlib
import json
import sys
from types import SimpleNamespace

import pytest

from desktop import release_manifest
from namazu import desktop_build


@pytest.fixture
def package(tmp_path, monkeypatch):
    root = tmp_path / "source"
    static = root / "namazu/static"
    static.mkdir(parents=True)
    page = ('<!doctype html><html><head><meta name="namazu-build-id" content="source">'
            '<link rel="stylesheet" href="/static/style.css">'
            '<script src="/static/app.js"></script></head><body></body></html>')
    (static / "index.html").write_text(page)
    (static / "app.js").write_text("window.fixtureReady = true;")
    (static / "style.css").write_text("body {color:black}")
    source_hashes = {p.relative_to(root).as_posix(): release_manifest.digest(p) for p in static.iterdir()}
    inputs = {"source_sha256": source_hashes, "build_id": release_manifest.build_id(source_hashes)}
    output = tmp_path / "installed"
    manifest = release_manifest.stage_identity(output, inputs, root=root)
    identity = {"build_id": inputs["build_id"], "packaged": True,
                "asset_manifest_sha256": desktop_build.asset_map_hash(manifest["assets"])}
    monkeypatch.setattr(desktop_build, "_verified", None)
    return SimpleNamespace(root=root, output=output, inputs=inputs, manifest=manifest, identity=identity, page=page)


def save_manifest(package):
    (package.output / "build-identity.json").write_text(json.dumps(package.manifest))


def trust_updated_assets(package):
    """Model a builder-produced trusted map, to exercise checks beyond hashing."""
    package.manifest["assets"] = {"static/" + p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in (package.output / "static").iterdir()}
    package.identity["asset_manifest_sha256"] = desktop_build.asset_map_hash(package.manifest["assets"])
    save_manifest(package)


def test_staged_package_binds_backend_frontend_and_expected_native_identity(package, monkeypatch):
    assert (package.root / "namazu/static/index.html").read_text() == package.page
    generated = {}
    exec((package.output / "_namazu_build_identity.py").read_text(), {}, generated)
    assert generated["BUILD_ID"] == package.identity["build_id"]
    assert generated["ASSET_MANIFEST_SHA256"] == package.identity["asset_manifest_sha256"]
    monkeypatch.setattr(desktop_build, "compiled_identity", lambda: package.identity)
    assert desktop_build.public_identity()["resources_verified"] is False
    status = desktop_build.preflight(package.identity["build_id"], package_root=package.output)
    assert status == {"build_id": package.identity["build_id"], "frontend_build_id": package.identity["build_id"],
                      "packaged": True, "resources_verified": True}
    assert desktop_build.public_identity() == status


def test_build_id_is_content_order_independent_and_changes_with_source():
    assert release_manifest.build_id({"a": "1", "b": "2"}) == release_manifest.build_id({"b": "2", "a": "1"})
    assert release_manifest.build_id({"a": "1"}) != release_manifest.build_id({"a": "2"})


def test_builder_rejects_stale_inputs_and_ambiguous_page(package, tmp_path):
    stale = {**package.inputs, "build_id": "namazu-" + "0" * 24}
    with pytest.raises(ValueError, match="source inputs"):
        release_manifest.stage_identity(tmp_path / "stale", stale, root=package.root)
    index = package.root / "namazu/static/index.html"
    index.write_text(package.page + '<meta name="namazu-build-id" content="source">')
    with pytest.raises(ValueError, match="exactly one"):
        release_manifest.stage_identity(tmp_path / "ambiguous", package.inputs, root=package.root)


def assert_error(package, code, **kwargs):
    with pytest.raises(desktop_build.DesktopBuildError) as error:
        desktop_build.preflight(package_root=package.output, compiled=package.identity, **kwargs)
    assert error.value.code == code
    assert str(package.output) not in str(error.value)
    assert "fixture-secret" not in str(error.value)


def test_native_mismatch_is_checked_before_resources(package):
    (package.output / "build-identity.json").unlink()
    assert_error(package, "native-backend-build-mismatch", expected_build_id="source")


@pytest.mark.parametrize("asset", ["index.html", "app.js", "style.css"])
def test_missing_resource_cannot_produce_ready(package, asset):
    (package.output / "static" / asset).unlink()
    assert_error(package, "frontend-asset-missing")


def test_changed_resource_cannot_produce_ready(package):
    (package.output / "static/app.js").write_text("fixture-secret")
    assert_error(package, "frontend-asset-mismatch")


@pytest.mark.parametrize("content", [None, "not json fixture-secret", "[]"])
def test_missing_or_invalid_manifest_has_safe_fixed_error(package, content):
    path = package.output / "build-identity.json"
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    assert_error(package, "frontend-manifest-invalid" if content == "[]" else "frontend-manifest-missing")


def test_mixed_frontend_manifest_rejected(package):
    package.manifest["build_id"] = "namazu-" + "f" * 24
    save_manifest(package)
    assert_error(package, "backend-frontend-build-mismatch")


def test_modified_asset_inventory_cannot_rebind_frozen_backend(package):
    package.manifest["assets"]["static/app.js"] = "0" * 64
    save_manifest(package)
    assert_error(package, "frontend-manifest-mismatch")


def test_page_identity_is_checked_independently_of_trusted_asset_hashes(package):
    index = package.output / "static/index.html"
    index.write_text(index.read_text().replace(package.identity["build_id"], "source"))
    trust_updated_assets(package)
    assert_error(package, "frontend-page-build-mismatch")


@pytest.mark.parametrize("name", ["static/../secret", "static//app.js", "/static/app.js", "static\\app.js", "C:/secret"])
def test_resource_manifest_cannot_escape_its_static_root(package, name):
    package.manifest["assets"][name] = "0" * 64
    package.identity["asset_manifest_sha256"] = desktop_build.asset_map_hash(package.manifest["assets"])
    save_manifest(package)
    assert_error(package, "frontend-manifest-invalid")


@pytest.mark.parametrize("reference,code", [
    ("/static/missing.js", "frontend-asset-missing"),
    ("https://fixture.invalid/script.js", "frontend-asset-reference-invalid"),
    ("//fixture.invalid/script.js", "frontend-asset-reference-invalid"),
    ("/other/app.js", "frontend-asset-reference-invalid"),
])
def test_bad_frontend_references_cannot_produce_ready(package, reference, code):
    index = package.output / "static/index.html"
    index.write_text(index.read_text().replace("/static/app.js", reference))
    trust_updated_assets(package)
    assert_error(package, code)


def test_source_resources_are_checked_without_a_packaged_identity():
    status = desktop_build.preflight("source", compiled={"build_id": "source", "packaged": False})
    assert status["resources_verified"] and status["build_id"] == "source"


def test_frozen_backend_requires_compiled_identity(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    def missing(_name):
        raise ModuleNotFoundError()
    monkeypatch.setattr(desktop_build.importlib, "import_module", missing)
    with pytest.raises(desktop_build.DesktopBuildError, match="no build identity") as error:
        desktop_build.compiled_identity()
    assert error.value.code == "backend-build-identity-missing"


def test_bad_compiled_identity_is_rejected(monkeypatch):
    monkeypatch.setattr(desktop_build.importlib, "import_module", lambda _: SimpleNamespace(BUILD_ID="fixture-secret"))
    with pytest.raises(desktop_build.DesktopBuildError) as error:
        desktop_build.compiled_identity()
    assert error.value.code == "backend-build-identity-invalid"
    assert "fixture-secret" not in str(error.value)


def test_public_status_never_reuses_previous_build_verification(monkeypatch):
    monkeypatch.setattr(desktop_build, "compiled_identity", lambda: {"build_id": "source", "packaged": False})
    monkeypatch.setattr(desktop_build, "_verified", {"build_id": "old", "frontend_build_id": "old"})
    status = desktop_build.public_identity()
    assert status["resources_verified"] is False and status["frontend_build_id"] is None
