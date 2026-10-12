"""Regenerate Bruno 4.2.1 reports against loopback only; never uses a remote API."""
from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures" / "bruno"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        status, body = 200, '{"id":"local-widget","owner":"fixture-user"}'
        headers = {"Content-Type": "application/json", "X-Frame-Options": "DENY"}
        if path.startswith("/uniform"):
            status, body = 403, '{"detail":"Not entitled to this resource"}'
        elif path == "/validation":
            status, body = 400, '{"errors":{"count":"must be a positive integer"}}'
        elif path == "/edge":
            status, body = 403, '<html>Incapsula incident ID: local <iframe src="/_Incapsula_Resource"></iframe></html>'
            headers["Content-Type"] = "text/html"
        elif path == "/timeout":
            time.sleep(0.7)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.do_GET()


def collection(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    (root / "bruno.json").write_text(json.dumps({"version": "1", "name": "Namazu local interoperability", "type": "collection", "ignore": ["node_modules", ".git"]}), encoding="utf-8")
    (root / "environments").mkdir(exist_ok=True)
    (root / "environments" / "Local.bru").write_text("vars {\n  baseUrl: http://127.0.0.1:9876\n}\n", encoding="utf-8")
    for index, path in enumerate(("ok", "failed", "uniform", "uniform-again", "validation", "edge", "timeout"), 1):
        expected = 201 if path == "failed" else 403 if path.startswith("uniform") or path == "edge" else 400 if path == "validation" else 200
        text = f"meta {{\n  name: {path}\n  type: http\n  seq: {index}\n}}\n\nget {{\n  url: {{{{baseUrl}}}}/{path}\n  body: none\n  auth: none\n}}\n\nassert {{\n  res.status: eq {expected}\n}}\n"
        if path == "ok":
            text += '\ntests {\n  test("resource content", function () { expect(res.body.id).to.equal("local-widget"); });\n}\n'
        text += '\nsettings {\n  timeout: 200\n}\n'
        (root / f"{index:02d}-{path}.bru").write_text(text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, help="Path to @usebruno/cli 4.2.1 bin/bru.js")
    parser.add_argument("--serve", action="store_true", help="Serve the README walkthrough on 127.0.0.1:9876")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 9876 if args.serve else 0), Handler)
    if args.serve:
        print("Local fixture: http://127.0.0.1:9876", flush=True)
        server.serve_forever()
        return
    if not args.cli:
        parser.error("Provide --cli or --serve")
    cli = args.cli.resolve()
    version = subprocess.check_output(["node", str(cli), "--version"], text=True).strip()
    if version != "4.2.1":
        parser.error(f"Expected Bruno CLI 4.2.1, found {version}")
    collection(ROOT / "collection")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    common = ["node", str(cli), "run", "--env", "Local", "--env-var", f"baseUrl={base}", "--iteration-count", "2", "--sandbox", "developer", "--noproxy"]
    try:
        for filename, extra in (("report.json", []), ("omitted.json", ["--reporter-skip-all-headers", "--reporter-skip-body"])):
            command = [*common, "--reporter-json", str(ROOT / filename), *extra]
            result = subprocess.run(command, cwd=ROOT / "collection", capture_output=True, encoding="utf-8", timeout=90)
            if result.returncode not in (0, 1) or not (ROOT / filename).exists():
                raise RuntimeError(result.stdout + result.stderr)
            document = json.loads((ROOT / filename).read_text(encoding="utf-8"))
            def scrub(value):
                if isinstance(value, dict):
                    return {k: scrub(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [scrub(v) for v in value]
                if isinstance(value, str):
                    return value.replace(str(ROOT / "collection"), "fixture/collection").replace(base, "http://127.0.0.1:9876").replace(f"127.0.0.1:{server.server_port}", "127.0.0.1:9876")
                return value
            (ROOT / filename).write_text(json.dumps(scrub(document), indent=2) + "\n", encoding="utf-8")
        (ROOT / "provenance.json").write_text(json.dumps({"cli": "@usebruno/cli@4.2.1", "parser": "@usebruno/lang@0.40.0", "command": "bru run --env Local --iteration-count 2 --sandbox developer --noproxy --reporter-json report.json", "generator": "tests/bruno_fixture.py", "target": "loopback ThreadingHTTPServer only", "sanitization": "Ephemeral loopback port replaced with 9876 and absolute collection path replaced with fixture/collection; synthetic data only. CLI timings retained; report has no execution timestamp.", "expected_exit_code": 1}, indent=2) + "\n", encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
