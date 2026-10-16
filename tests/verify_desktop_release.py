"""Read-only source, package and ZIP verification for a finished local build."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def verify(folder, source):
    manifest_path = folder / "content-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for key, root in (("source_sha256", source), ("artifact_sha256", folder)):
        for relative, expected in manifest[key].items():
            path = (root / relative).resolve()
            assert path.is_relative_to(root), f"Manifest path escapes root: {relative}"
            assert path.is_file(), f"Missing {key} file: {relative}"
            assert sha256(path.read_bytes()) == expected, f"Changed {key} file: {relative}"
    actual = {path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file()}
    expected = set(manifest["artifact_sha256"]) | {"content-manifest.json"}
    assert actual == expected, f"Artifact file inventory mismatch: {actual ^ expected}"
    archive_path = Path(str(folder) + ".zip")
    with zipfile.ZipFile(archive_path) as archive:
        prefix = folder.name + "/"
        entries = {info.filename.replace("\\", "/"): info for info in archive.infolist() if not info.is_dir()}
        assert set(entries) == {prefix + item for item in expected}, "ZIP file inventory differs from folder"
        for relative in expected:
            assert sha256(archive.read(entries[prefix + relative])) == sha256((folder / relative).read_bytes()), f"ZIP content differs: {relative}"
    return {"verified": True, "source_files": len(manifest["source_sha256"]),
            "artifact_files": len(actual), "archive_bytes": archive_path.stat().st_size,
            "archive_sha256": sha256(archive_path.read_bytes()),
            "executable": str(folder / "Namazu.exe"), "archive": str(archive_path)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.folder.resolve(), Path(__file__).resolve().parents[1])
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
