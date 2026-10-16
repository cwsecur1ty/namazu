"""Generate actual pinned Bruno reports and loopback receipts for interoperability.

Run explicitly: python tests/bruno_comprehensive_fixture.py --cli PATH/bru.js
The generated report is produced by @usebruno/cli 4.2.1, never fabricated.
Malformed/unsupported input files are separately labelled and never executed.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parent / "fixtures/bruno/comprehensive"
BASE = "http://127.0.0.1:9876"
CLI_VERSION = "4.2.1"
PARSER_VERSION = "0.40.0"


class Fixture(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server_port}"
        self.attempts = []
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        parsed = urlsplit(self.path)
        record = {"method": self.command, "path": self.path,
                  "headers": {name.lower(): value for name, value in self.headers.items()},
                  "body": raw.decode("utf-8", errors="replace"), "body_bytes": len(raw)}
        with self.server.lock:
            self.server.attempts.append(record)
        status, content_type = 200, "application/json; charset=utf-8"
        body = {"id": "local-widget", "owner": "fixture-user", "method": self.command,
                "path": unquote(parsed.path), "query": parse_qs(parsed.query, keep_blank_values=True),
                "body": record["body"], "headers": record["headers"]}
        if parsed.path.startswith("/denied"):
            status, body = 403, {"detail": "Not entitled to this resource"}
        elif parsed.path == "/validation":
            status, body = 400, {"errors": {"count": "must be a positive integer"}}
        elif parsed.path == "/edge":
            status, content_type = 403, "text/html"
            body = '<html>Incapsula incident ID: local <iframe src="/_Incapsula_Resource"></iframe></html>'
        elif parsed.path == "/timeout":
            time.sleep(0.7)
        elif parsed.path == "/empty":
            status, body = 204, ""
        elif parsed.path == "/scalar-false":
            body = False
        elif parsed.path == "/scalar-zero":
            body = 0
        elif parsed.path == "/scalar-null":
            body = None
        encoded = (json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Fixture", "Namazu local Bruno interoperability")
        self.end_headers()
        if self.command != "HEAD":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.wfile.write(encoded)

    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_HEAD = do_GET


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def request(name, url, *, method="get", mode="none", auth="inherit", seq=1, extra="", body=None, expected=200):
    value = f"meta {{\n  name: {name}\n  type: http\n  seq: {seq}\n}}\n\n{method} {{\n  url: {url}\n  body: {mode}\n  auth: {auth}\n}}\n"
    if body is not None:
        value += f"\nbody:{mode} {{\n{body}\n}}\n"
    return value + extra + f"\nassert {{\n  res.status: eq {expected}\n}}\n\nsettings {{\n  timeout: 200\n}}\n"


def build_collection(root):
    write(root, "bruno.json", json.dumps({"version": "1", "name": "Namazu comprehensive local Bruno fixture", "type": "collection", "ignore": ["node_modules", ".git"]}, indent=2))
    write(root, "collection.bru", """vars:pre-request {
  baseUrl: http://127.0.0.1:9876
  layer: collection
  sharedToken: fixture-shared-token
  disabledFallback: collection-value
}

headers {
  X-Collection: inherited
  X-Override: collection
}

auth {
  mode: bearer
}

auth:bearer {
  token: {{sharedToken}}
}
""")
    for environment, layer in [("Local", "environment"), ("Alternate", "alternate")]:
        write(root, f"environments/{environment}.bru", f"vars {{\n  baseUrl: {BASE}\n  layer: {layer}\n  environmentName: {environment}\n  message: caf\u00e9 \u96ea\n}}\n")
    write(root, "Nested folder/folder.bru", """meta {
  name: Nested folder
  seq: 1
}

vars:pre-request {
  layer: folder
  folderToken: fixture-folder-token
}

headers {
  X-Folder: inherited
  x-override: folder
}

auth {
  mode: bearer
}

auth:bearer {
  token: {{folderToken}}
}
""")
    write(root, "Other folder/folder.bru", "meta {\n  name: Other folder\n  seq: 2\n}\n\nauth {\n  mode: none\n}\n")
    entries = [
        ("Nested folder/Same request.bru", request("Same request", "{{baseUrl}}/echo?layer={{layer}}&message={{message}}", extra="\nheaders {\n  X-Override: request\n}\n\nvars:pre-request {\n  layer: request\n}\n")),
        ("Nested folder/Child with spaces/Same request.bru", request("Same request", "{{baseUrl}}/space path/caf\u00e9?layer={{layer}}", seq=2)),
        ("Other folder/Same request.bru", request("Same request", "{{baseUrl}}/echo?layer={{layer}}", seq=1)),
        ("01-request-auth-override.bru", request("Request bearer override", "{{baseUrl}}/echo?case=override", auth="bearer", seq=3, extra="\nauth:bearer {\n  token: fixture-request-token\n}\n")),
        ("02-no-auth.bru", request("Explicit no auth", "{{baseUrl}}/echo?case=no-auth", auth="none", seq=4)),
        ("03-json-object.bru", request("JSON object and Unicode", "{{baseUrl}}/echo", method="post", mode="json", body='  {"name":"{{message}}","enabled":true,"count":0,"items":[null,false,"space value"]}', seq=5)),
        ("04-json-null.bru", request("JSON null", "{{baseUrl}}/echo?case=null", method="post", mode="json", body="  null", seq=6)),
        ("05-json-false.bru", request("JSON false", "{{baseUrl}}/echo?case=false", method="post", mode="json", body="  false", seq=7)),
        ("06-json-zero.bru", request("JSON zero", "{{baseUrl}}/echo?case=zero", method="post", mode="json", body="  0", seq=8)),
        ("07-json-string.bru", request("JSON string", "{{baseUrl}}/echo?case=string", method="post", mode="json", body='  "caf\u00e9 \u96ea"', seq=9)),
        ("08-text.bru", request("Text body", "{{baseUrl}}/echo?case=text", method="put", mode="text", body="  line one\n  caf\u00e9 \u96ea", seq=10)),
        ("09-xml.bru", request("XML body", "{{baseUrl}}/echo?case=xml", method="post", mode="xml", body='  <entry label="caf\u00e9"><value>space value</value></entry>', seq=11)),
        ("10-form.bru", request("Form body", "{{baseUrl}}/echo?case=form", method="post", mode="form-urlencoded", body="  name: caf\u00e9 \u96ea\n  label: space value\n  ~disabled: omitted", seq=12)),
        ("11-no-body.bru", request("POST without body", "{{baseUrl}}/echo?case=absent", method="post", seq=13)),
        ("12-empty-response.bru", request("Empty response", "{{baseUrl}}/empty", seq=14, expected=204)),
        ("13-successful-tests.bru", request("Successful assertions and script tests", "{{baseUrl}}/ok", seq=15, extra='\ntests {\n  test("resource content", function () { expect(res.body.id).to.equal("local-widget"); });\n}\n')),
        ("14-failed-tests.bru", request("Failed assertion and script test", "{{baseUrl}}/ok", seq=16, expected=201, extra='\ntests {\n  test("deliberate failure", function () { expect(res.body.id).to.equal("different-widget"); });\n}\n')),
        ("15-denial.bru", request("Application denial", "{{baseUrl}}/denied", seq=17, expected=403)),
        ("16-validation.bru", request("Field validation", "{{baseUrl}}/validation", seq=18, expected=400)),
        ("17-edge.bru", request("Edge block", "{{baseUrl}}/edge", seq=19, expected=403)),
        ("18-timeout.bru", request("Timeout", "{{baseUrl}}/timeout", seq=20)),
        ("19-unresolved-query.bru", request("Unresolved static input", "{{baseUrl}}/echo?unresolved={{missingValue}}", seq=21)),
        ("20-inert-script.bru", request("Script-dependent request", "{{baseUrl}}/echo?case=script", seq=22, extra='\nscript:pre-request {\n  req.setHeader("X-Script", "fixture-script-ran");\n}\n')),
        ("21-graphql.bru", request("Unsupported GraphQL conversion", "{{baseUrl}}/echo?case=graphql", method="post", mode="graphql", seq=23, extra='\nbody:graphql {\n  query { localWidget { id } }\n}\n\nbody:graphql:vars {\n  {}\n}\n')),
        ("22-json-escapes.bru", request("Escaped JSON strings", "{{baseUrl}}/echo?case=escapes", method="post", mode="json", seq=24,
                                             body="  " + json.dumps({"quote": 'a "quoted" value', "path": "C:\\fixture\\path", "line": "one\ntwo", "unicode": "caf\u00e9 \u96ea"}, ensure_ascii=False))),
        ("23-disabled-variable.bru", request("Disabled override keeps lower scope", "{{baseUrl}}/echo?disabled={{disabledFallback}}", seq=25,
                                                extra="\nvars:pre-request {\n  ~disabledFallback: must-not-use\n}\n")),
        ("24-opaque-auth-reference.bru", request("Opaque auth reference", "{{baseUrl}}/echo?case=opaque-auth", auth="bearer", seq=26,
                                                  extra="\nvars:pre-request {\n  opaque: fixture-opaque-auth-value\n}\n\nauth:bearer {\n  token: {{opaque}}\n}\n")),
        ("25-empty-text.bru", request("Empty text block parser boundary", "{{baseUrl}}/echo?case=empty-text-block", method="post", mode="text", body="", seq=27)),
        ("26-duplicate-query.bru", request("Repeated and empty query values", "{{baseUrl}}/echo?tag=one&tag=two&empty=", seq=28,
                                             extra="\nparams:query {\n  tag: one\n  tag: two\n  empty: \n}\n")),
        ("27-custom-content-type.bru", request("Explicit content type casing", "{{baseUrl}}/echo?case=content-type", method="post", mode="json", body='  {"label":"one"}', seq=29,
                                                  extra="\nheaders {\n  content-type: application/problem+json\n}\n")),
        ("28-owned-file.bru", request("Owned fixture file upload", "{{baseUrl}}/echo?case=file", method="post", mode="file", seq=30,
                                        body="  file: @file(assets/local payload.txt) @contentType(text/plain)")),
        ("29-owned-multipart.bru", request("Owned fixture multipart", "{{baseUrl}}/echo?case=multipart", method="post", mode="multipart-form", seq=31,
                                             body="  title: caf\u00e9 \u96ea\n  upload: @file(assets/local payload.txt) @contentType(text/plain)")),
        ("30-response-false.bru", request("False response value", "{{baseUrl}}/scalar-false", seq=32)),
        ("31-response-zero.bru", request("Zero response value", "{{baseUrl}}/scalar-zero", seq=33)),
        ("32-response-null.bru", request("Null response value", "{{baseUrl}}/scalar-null", seq=34)),
        ("33-empty-text-mode.bru", request("Empty text mode without a block", "{{baseUrl}}/echo?case=empty-text", method="post", mode="text", seq=35)),
    ]
    for name, text in entries:
        write(root, name, text)
    write(root, "assets/local payload.txt", "Owned synthetic local upload. caf\u00e9 \u96ea\n")
    return len(entries)


def scrub(value, *, base, collection):
    if isinstance(value, dict):
        return {name: scrub(item, base=base, collection=collection) for name, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, base=base, collection=collection) for item in value]
    if isinstance(value, str):
        return value.replace(str(collection), "fixture/comprehensive/collection").replace(base, BASE).replace(base.removeprefix("http://"), BASE.removeprefix("http://"))
    return value


def generate(cli, output=ROOT):
    cli, output = Path(cli).resolve(), Path(output).resolve()
    version = subprocess.check_output(["node", str(cli), "--version"], text=True, timeout=120).strip()
    if version != CLI_VERSION:
        raise ValueError(f"Expected Bruno CLI {CLI_VERSION}, found {version}")
    package = cli.parent.parent / "package.json"
    collection = output / "collection"
    count = build_collection(collection)
    write(output, "negative/malformed.bru", "meta {\n name: incomplete\n\nget {\n url: {{baseUrl}}/never\n")
    write(output, "negative/malformed-report.json", '{"results": [')
    write(output, "negative/unsupported-report.json", json.dumps({"format": "unrecognized-tool", "requests": [], "schema": 9000}))
    server = Fixture()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    runs = []
    common = ["node", str(cli), "run", "--env", "Local", "--env-var", f"baseUrl={server.base}", "--iteration-count", "2", "--sandbox", "developer", "--noproxy"]
    try:
        for filename, flags in [("report.json", []), ("omitted.json", ["--reporter-skip-all-headers", "--reporter-skip-body"])]:
            report = output / filename
            before = len(server.attempts)
            command = [*common, "--reporter-json", str(report), *flags]
            result = subprocess.run(command, cwd=collection, capture_output=True, encoding="utf-8", timeout=180)
            if result.returncode not in (0, 1) or not report.exists():
                raise RuntimeError(result.stdout + result.stderr)
            raw_bytes = report.read_bytes()
            data = json.loads(raw_bytes)
            safe = scrub(data, base=server.base, collection=collection)
            report.write_text(json.dumps(safe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            attempts = scrub(server.attempts[before:], base=server.base, collection=collection)
            write(output, filename.replace(".json", "-receipts.json"), json.dumps(attempts, indent=2, ensure_ascii=False) + "\n")
            executions = [entry for iteration in data for entry in iteration.get("results", [])]
            runs.append({"report": filename, "exit_code": result.returncode,
                         "command": "node @usebruno/cli/bin/bru.js run --env Local --env-var baseUrl=<owned-loopback> --iteration-count 2 --sandbox developer --noproxy --reporter-json " + filename + " " + " ".join(flags),
                         "original_cli_output_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                         "normalized_output_sha256": hashlib.sha256(report.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
                         "logical_executions": len(executions), "mock_network_attempts": len(attempts),
                         "observed_responses": sum(isinstance((entry.get("response") or {}).get("status"), int) for entry in executions),
                         "no_response_executions": sum(not isinstance((entry.get("response") or {}).get("status"), int) for entry in executions)})
            print(json.dumps(runs[-1]), flush=True)
        provenance = {"cli": f"@usebruno/cli@{version}", "parser": f"@usebruno/lang@{PARSER_VERSION}",
                      "cli_package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                      "generator": "tests/bruno_comprehensive_fixture.py", "target": "owned ephemeral loopback ThreadingHTTPServer only",
                      "collection_requests": count, "iterations": 2, "runs": runs,
                      "normalization": "Only ephemeral loopback base/port and absolute collection path are replaced. Actual CLI timings, generated UIDs and HTTP dates remain; fixture credentials are synthetic.",
                      "negative_inputs": "Hand-authored malformed and unsupported-format examples; not represented as CLI-generated reports and never executed.",
                      "parser_boundary": "25-empty-text.bru intentionally records official parser handling of an empty text block followed by assertions; it becomes nonempty literal text. 33-empty-text-mode.bru is the genuine zero-byte text-mode request.",
                      "coverage_boundary": "Interoperability and accounting regressions only; not API security coverage."}
        write(output, "provenance.json", json.dumps(provenance, indent=2) + "\n")
    finally:
        server.shutdown()
        server.server_close()
    return provenance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT)
    options = parser.parse_args()
    generate(options.cli, options.output)
