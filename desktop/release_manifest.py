"""Verify pinned build inputs and record exactly what a desktop artifact contains."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_id(source_hashes):
    fingerprint = hashlib.sha256(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return "namazu-" + fingerprint[:24]


def stage_identity(output: Path, inputs: dict, *, root=ROOT):
    """Create build-only resources without rewriting the checked-in frontend."""
    identity = inputs["build_id"]
    if identity != build_id(inputs["source_sha256"]):
        raise ValueError("Build identity does not match source inputs")
    if output.exists():
        raise ValueError("Build identity staging directory already exists; use a fresh build")
    output.mkdir(parents=True)
    shutil.copytree(root / "namazu/static", output / "static")
    index = output / "static/index.html"
    page = index.read_text(encoding="utf-8")
    marker = '<meta name="namazu-build-id" content="source">'
    if page.count(marker) != 1 or len(re.findall(r'name=[\"\']namazu-build-id[\"\']', page)) != 1:
        raise ValueError("Frontend entry page must contain exactly one source build identity")
    index.write_text(page.replace(marker, '<meta name="namazu-build-id" content="' + identity + '">', 1), encoding="utf-8")
    assets = {"static/" + path.relative_to(output / "static").as_posix(): digest(path)
              for path in sorted((output / "static").rglob("*")) if path.is_file()}
    fingerprint = hashlib.sha256(json.dumps(assets, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    manifest = {"format": "namazu-desktop-build", "version": 1, "build_id": identity, "assets": assets}
    (output / "build-identity.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (output / "_namazu_build_identity.py").write_text(
        '"""Generated nonsecret identity for this frozen backend."""\n'
        + "BUILD_ID = " + repr(identity) + "\nASSET_MANIFEST_SHA256 = " + repr(fingerprint) + "\n", encoding="utf-8")
    return manifest


def sources() -> dict[str, str]:
    paths = list((ROOT / "namazu").rglob("*.py"))
    for name in ("static", "bruno_node"):
        paths.extend(path for path in (ROOT / "namazu" / name).rglob("*") if path.is_file())
    paths.extend(path for path in (ROOT / "desktop").glob("*") if path.is_file())
    paths.extend(path for path in (ROOT / "desktop/Namazu.Desktop").glob("*") if path.is_file())
    paths.append(ROOT / "scripts/build-desktop.ps1")
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(set(paths))}


def verify_environment() -> None:
    if sys.version_info[:2] != (3, 14) or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit("The desktop build requires Python 3.14 x64.")
    for line in (ROOT / "desktop/requirements-build.lock.txt").read_text().splitlines():
        if "==" not in line:
            continue
        name, version = line.split("==", 1)
        actual = importlib.metadata.version(name)
        if actual != version:
            raise SystemExit(f"Pinned dependency mismatch: {name} needs {version}; found {actual}. Use -InstallDependencies.")


def main() -> None:
    mode, destination = sys.argv[1:3]
    output = Path(destination)
    if mode == "inputs":
        verify_environment()
        source_hashes = sources()
        output.write_text(json.dumps({"python": sys.version, "source_sha256": source_hashes, "build_id": build_id(source_hashes)}, indent=2), encoding="utf-8")
    elif mode == "stage":
        stage_identity(output, json.loads(Path(sys.argv[3]).read_text(encoding="utf-8")))
    elif mode == "artifact":
        inputs = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
        if inputs["source_sha256"] != sources():
            raise SystemExit("Build inputs changed while packaging. Build a fresh release from the final source state.")
        inputs["artifact_sha256"] = {
            path.relative_to(output).as_posix(): digest(path)
            for path in sorted(output.rglob("*")) if path.is_file()
        }
        (output / "content-manifest.json").write_text(json.dumps(inputs, indent=2), encoding="utf-8")
    else:
        raise SystemExit("Expected inputs, stage or artifact.")


if __name__ == "__main__":
    main()
