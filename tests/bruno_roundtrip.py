"""Execute exported GET/POST definitions only against an in-process loopback mock.

Usage: python -m tests.bruno_roundtrip --cli path/to/@usebruno/cli/bin/bru.js
Requires the pinned CLI; this is deliberately separate from offline unit tests.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import threading
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from namazu.bruno import import_report
from namazu.bruno_collections import export_collection, import_collection


def run(cli):
    cli = Path(cli).resolve()
    assert subprocess.check_output(["node", str(cli), "--version"], text=True).strip() == "4.2.1"
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            seen.append({"method": self.command, "path": self.path, "body": body, "mode": self.headers.get("X-Mode")})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":"local-widget","owner":"fixture-user"}')

        do_POST = do_GET

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server, ExitStack() as cleanup:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cleanup.callback(server.shutdown)
        base = f"http://127.0.0.1:{server.server_port}"
        requests = [{"method": "GET", "url": base + "/ok?q=space%20value", "headers": {"X-Mode": "read"}, "body": None}, {"method": "POST", "url": base + "/ok", "headers": {"Content-Type": "application/json", "X-Mode": "write"}, "body": '{"id":"local-widget","enabled":true}'}]
        converted = export_collection(requests)
        imported = import_collection(converted["files"], environment="Local")
        assert [r["request"]["method"] for r in imported["requests"]] == ["GET", "POST"]
        assert seen == [], "Import/export must never send target requests"
        with tempfile.TemporaryDirectory(prefix="namazu-bruno-roundtrip-") as directory:
            root = Path(directory)
            for file in converted["files"]:
                target = root / file["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(file["content"], encoding="utf-8")
            report = root / "report.json"
            result = subprocess.run(["node", str(cli), "run", "--env", "Local", "--noproxy", "--reporter-json", str(report)], cwd=root, capture_output=True, encoding="utf-8", timeout=60)
            assert result.returncode == 0, result.stdout + result.stderr
            evidence = import_report(json.loads(report.read_text(encoding="utf-8")))
            assert evidence["bruno"]["observed_responses"] == 2
            assert len(seen) == 2
            assert seen[0] == {"method": "GET", "path": "/ok?q=space+value", "body": "", "mode": "read"}
            assert {k: v for k, v in seen[1].items() if k != "body"} == {"method": "POST", "path": "/ok", "mode": "write"}
            # The CLI serializes JSON with spaces. Compare values, not wire bytes.
            assert json.loads(seen[1]["body"]) == json.loads(requests[1]["body"])
    print("Bruno CLI 4.2.1: GET + POST roundtrip passed; import/export sent zero requests.")


if __name__ == "__main__":
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--cli", required=True)
    run(arguments.parse_args().cli)
