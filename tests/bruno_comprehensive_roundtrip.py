"""Execute exported safe definitions with the pinned real CLI on owned loopback only."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from namazu.bruno import import_report
from namazu.bruno_collections import export_collection, import_collection
from tests.bruno_comprehensive_fixture import BASE, Fixture
from tests.test_bruno_comprehensive import files


def run(cli, output):
    cli, output = Path(cli).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output(["node", str(cli), "--version"], text=True, timeout=120).strip()
    assert version == "4.2.1"
    server = Fixture()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        original = import_collection(files(), environment="Local")
        by_id = {row["id"]: row for row in original["requests"]}
        names = ["02-no-auth.bru", "03-json-object.bru", "04-json-null.bru", "05-json-false.bru", "06-json-zero.bru", "07-json-string.bru",
                 "08-text.bru", "09-xml.bru", "10-form.bru", "11-no-body.bru", "22-json-escapes.bru", "25-empty-text.bru", "26-duplicate-query.bru", "27-custom-content-type.bru"]
        requests = [{**by_id[name]["request"], "url": by_id[name]["request"]["url"].replace(BASE, server.base)} for name in names]
        exported = export_collection(requests)
        restored = import_collection(exported["files"], environment="Local")
        assert len(restored["requests"]) == len(names)
        assert server.attempts == [], "Definition parsing/export must remain offline"
        with tempfile.TemporaryDirectory(prefix="namazu-real-bruno-roundtrip-") as temporary:
            root = Path(temporary)
            for item in exported["files"]:
                path = root / item["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(item["content"], encoding="utf-8")
            report = root / "report.json"
            command = ["node", str(cli), "run", "--env", "Local", "--noproxy", "--reporter-json", str(report)]
            result = subprocess.run(command, cwd=root, capture_output=True, encoding="utf-8", timeout=120)
            assert result.returncode == 0, result.stdout + result.stderr
            report_data = json.loads(report.read_text(encoding="utf-8"))
            evidence = import_report(report_data)
            assert evidence["bruno"]["recorded_executions"] == len(names)
            assert evidence["bruno"]["observed_responses"] == len(names)
        assert len(server.attempts) == len(names)
        checks = []
        for name, request, receipt in zip(names, requests, server.attempts, strict=True):
            url = urlsplit(request["url"])
            actual = urlsplit(receipt["path"])
            assert receipt["method"] == request["method"], name
            assert actual.path == url.path, name
            assert parse_qs(actual.query, keep_blank_values=True) == parse_qs(url.query, keep_blank_values=True), name
            media = next((value for key, value in request["headers"].items() if key.lower() == "content-type"), None)
            if media:
                assert receipt["headers"]["content-type"] == media, name
            if request["body"] is None:
                assert receipt["body_bytes"] == 0, name
            elif media and "json" in media:
                assert json.loads(receipt["body"]) == json.loads(request["body"]), name
            else:
                assert receipt["body"] == request["body"], name
            assert "authorization" not in receipt["headers"], "Definitions do not carry imported credentials into exports"
            checks.append({"source_definition": name, "method": receipt["method"], "path": receipt["path"], "body_bytes": receipt["body_bytes"], "content_type": receipt["headers"].get("content-type"), "passed": True})
        summary = {"status": "passed", "cli": "@usebruno/cli@4.2.1", "target": "owned ephemeral loopback mock", "definition_count": len(names),
                   "requests_during_import_export": 0, "explicit_cli_mock_attempts": len(server.attempts), "observed_responses": evidence["bruno"]["observed_responses"],
                   "checks": checks, "limitations": ["JSON compares values because Bruno reserializes it.", "No API security coverage is established."]}
        (output / "report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2), flush=True)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--cli", required=True)
    arguments.add_argument("--output", type=Path, default=Path(".local-reports/bruno-comprehensive-roundtrip"))
    options = arguments.parse_args()
    run(options.cli, options.output)
