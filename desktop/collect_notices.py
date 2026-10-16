"""Copy installed dependency license/notice texts into the release artifact."""
from __future__ import annotations

import importlib.metadata
import json
import shutil
import sys
from pathlib import Path


def main():
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    lock = Path(__file__).with_name("requirements-build.lock.txt")
    packages = [line.split("==", 1)[0] for line in lock.read_text().splitlines() if "==" in line]
    inventory = []
    for name in packages:
        distribution = importlib.metadata.distribution(name)
        metadata = distribution.metadata
        entry = {"name": metadata["Name"], "version": distribution.version,
                 "license": metadata.get("License-Expression") or metadata.get("License") or "See included notices",
                 "homepage": metadata.get("Home-page") or "", "notice_files": []}
        destination = target / name
        destination.mkdir(exist_ok=True)
        for item in distribution.files or []:
            if any(part.lower().startswith(("license", "copying", "notice")) for part in item.parts):
                source = Path(distribution.locate_file(item))
                if source.is_file():
                    output = destination / source.name
                    shutil.copyfile(source, output)
                    entry["notice_files"].append(str(output.relative_to(target)))
        inventory.append(entry)
    (target / "python-dependencies.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
