"""Regenerate local official-serializer workspace fixtures without network I/O."""
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "tests/fixtures/bruno/workspace"


def main():
    result = subprocess.run(["node", str(ROOT / "tests/bruno_workspace_fixture.cjs")], capture_output=True, text=True, check=True, timeout=30)
    generated = json.loads(result.stdout)
    DEST.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(DEST / "workspace.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in generated["files"]:
            file = DEST / "source" / item["path"]
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(item["content"], encoding="utf-8")
            if not any(part in {"node_modules", ".git"} for part in file.parts):
                info = zipfile.ZipInfo(item["path"], date_time=(2026, 10, 15, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, item["content"].encode())
    provenance = {**generated["provenance"], "sha256": {item["path"]: hashlib.sha256(item["content"].encode()).hexdigest() for item in generated["files"]},
                  "archive_sha256": hashlib.sha256((DEST / "workspace.zip").read_bytes()).hexdigest(),
                  "sources": ["https://github.com/usebruno/bruno/blob/v4.2.1/packages/bruno-electron/src/ipc/workspace.js",
                              "https://github.com/usebruno/bruno/blob/v4.2.1/packages/bruno-electron/src/utils/workspace-config.js",
                              "https://docs.usebruno.com/v3/get-started/import-export-data/import-export-workspace"]}
    (DEST / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(json.dumps({"files": len(generated["files"]), "archive_bytes": (DEST / "workspace.zip").stat().st_size, "requests_sent": 0}))


if __name__ == "__main__":
    main()
