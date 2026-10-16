"""Nonsecret package identity and fail-closed frontend resource preflight.

This detects incomplete or mixed local releases. It is not code signing or a
defence against software that can replace the entire executable and package.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

FORMAT = "namazu-desktop-build"
VERSION = 1
BUILD_PATTERN = re.compile(r"namazu-[0-9a-f]{24}")
_verified = None


class DesktopBuildError(RuntimeError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def asset_map_hash(assets):
    return hashlib.sha256(json.dumps(assets, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compiled_identity():
    try:
        identity = importlib.import_module("_namazu_build_identity")
    except ModuleNotFoundError:
        if getattr(sys, "frozen", False):
            raise DesktopBuildError("backend-build-identity-missing", "The packaged backend has no build identity. Extract a complete current Namazu release into a new folder.") from None
        return {"build_id": "source", "packaged": False, "asset_manifest_sha256": None}
    build_id, fingerprint = getattr(identity, "BUILD_ID", None), getattr(identity, "ASSET_MANIFEST_SHA256", None)
    if not isinstance(build_id, str) or not BUILD_PATTERN.fullmatch(build_id) or not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise DesktopBuildError("backend-build-identity-invalid", "The packaged backend build identity is invalid. Extract the complete application again.")
    return {"build_id": build_id, "packaged": True, "asset_manifest_sha256": fingerprint}


class _Frontend(HTMLParser):
    def __init__(self):
        super().__init__()
        self.build_ids, self.assets = [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "namazu-build-id":
            self.build_ids.append(attrs.get("content"))
        if tag == "script" and attrs.get("src"):
            self.assets.append(attrs["src"])
        if tag == "link" and "stylesheet" in (attrs.get("rel") or "").split() and attrs.get("href"):
            self.assets.append(attrs["href"])


def _asset_path(root, name):
    if not isinstance(name, str) or "\\" in name or ":" in name or name.startswith("/"):
        raise DesktopBuildError("frontend-manifest-invalid", "The frontend resource manifest contains an invalid asset path.")
    path = PurePosixPath(name)
    if not path.parts or path.parts[0] != "static" or any(part in {"", ".", ".."} for part in name.split("/")):
        raise DesktopBuildError("frontend-manifest-invalid", "The frontend resource manifest contains an invalid asset path.")
    resolved = (root / name).resolve()
    if not resolved.is_relative_to(root):
        raise DesktopBuildError("frontend-manifest-invalid", "A frontend resource resolves outside the installed application.")
    return resolved


def preflight(expected_build_id=None, *, package_root=None, compiled=None):
    """Check local resources before state migration or a listening HTTP socket."""
    identity = compiled_identity() if compiled is None else compiled
    build_id = identity["build_id"]
    if expected_build_id is not None and expected_build_id != build_id:
        raise DesktopBuildError("native-backend-build-mismatch", "The native window and backend are from different builds. Extract the complete Namazu ZIP into a new folder.")
    root = (Path(package_root) if package_root is not None else Path(__file__).parent).resolve()
    assets = None
    if identity["packaged"]:
        try:
            path = root / "build-identity.json"
            if path.stat().st_size > 1_048_576:
                raise ValueError()
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            raise DesktopBuildError("frontend-manifest-missing", "The packaged frontend manifest is missing or unreadable. Extract the complete Namazu ZIP into a new folder.") from None
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or manifest.get("version") != VERSION:
            raise DesktopBuildError("frontend-manifest-invalid", "The packaged frontend manifest has an unsupported format. Use matching application files.")
        if manifest.get("build_id") != build_id:
            raise DesktopBuildError("backend-frontend-build-mismatch", "The backend and frontend resources are from different builds. Extract the complete Namazu ZIP into a new folder.")
        assets = manifest.get("assets")
        if not isinstance(assets, dict) or not 1 <= len(assets) <= 4096 or "static/index.html" not in assets:
            raise DesktopBuildError("frontend-manifest-invalid", "The packaged frontend resource inventory is incomplete.")
        if asset_map_hash(assets) != identity["asset_manifest_sha256"]:
            raise DesktopBuildError("frontend-manifest-mismatch", "The frontend resource inventory does not match the packaged backend. Extract the complete application again.")
        for name, expected in assets.items():
            asset = _asset_path(root, name)
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise DesktopBuildError("frontend-manifest-invalid", "The frontend resource manifest contains an invalid checksum.")
            try:
                actual = hashlib.sha256(asset.read_bytes()).hexdigest()
            except OSError:
                raise DesktopBuildError("frontend-asset-missing", "A required frontend resource is missing or unreadable. Extract the complete Namazu ZIP into a new folder.") from None
            if actual != expected:
                raise DesktopBuildError("frontend-asset-mismatch", "A frontend resource differs from this build. Extract the complete Namazu ZIP into a new folder.")
    try:
        page = _Frontend()
        page.feed((root / "static/index.html").read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        raise DesktopBuildError("frontend-index-missing", "Namazu's frontend entry page is missing or unreadable. Restore the complete application files.") from None
    if identity["packaged"] and page.build_ids != [build_id]:
        raise DesktopBuildError("frontend-page-build-mismatch", "The frontend entry page does not identify the same build as the backend.")
    for reference in page.assets:
        parts = urlsplit(reference)
        if parts.scheme or parts.netloc or not parts.path.startswith("/static/"):
            raise DesktopBuildError("frontend-asset-reference-invalid", "The frontend entry page contains an unsupported resource reference.")
        name = parts.path.lstrip("/")
        if not _asset_path(root, name).is_file() or (assets is not None and name not in assets):
            raise DesktopBuildError("frontend-asset-missing", "The frontend entry page references a missing resource. Restore the complete application files.")
    verified = {"build_id": build_id, "frontend_build_id": build_id, "packaged": identity["packaged"], "resources_verified": True}
    global _verified
    _verified = verified
    return dict(verified)


def public_identity():
    identity = compiled_identity()
    verified = _verified if _verified and _verified["build_id"] == identity["build_id"] else None
    return {"build_id": identity["build_id"], "packaged": identity["packaged"],
            "frontend_build_id": (verified or {}).get("frontend_build_id"),
            "resources_verified": bool(verified)}
