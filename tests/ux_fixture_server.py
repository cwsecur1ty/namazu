"""Opt-in loopback fixtures for manual UX journeys. Never used by production routes.

Run: python -m tests.ux_fixture_server --port 9137
Only inert local credentials and resources are accepted. /stats counts API
attempts, so report import and offline review can be checked for accidental IO.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from namazu import __version__
from namazu.audit import contract, readiness
from namazu.spec import parse_spec

DENIAL = {"title": "Forbidden", "status": 403,
          "detail": "The caller does not hold the role required to use this endpoint, or is not entitled to the report this request targets."}
EDGE = '<html><body>Request unsuccessful. Incapsula incident ID: local-test<iframe src="/_Incapsula_Resource"></iframe></body></html>'
BODY = {"documentUri": "doc-local", "personaId": "persona-reader", "focusTopic": "markets",
        "maxBulletsAmount": 3, "strictMode": True, "regenerate": False}
ASSERTIONS = [{"purpose": "resource", "pointer": "/documentUri", "operator": "equals", "expected": "doc-local"},
              {"purpose": "content", "pointer": "/summary", "operator": "contains", "expected": "Local fixture summary"}]


def api_document(base):
    schema = {"type": "object", "required": ["documentUri", "personaId", "maxBulletsAmount", "strictMode"],
              "properties": {
                  "documentUri": {"type": "string", "minLength": 1, "description": "Document the local identity may summarise.", "example": "string"},
                  "personaId": {"type": "string", "minLength": 1, "description": "A persona supplied by the API owner.", "example": "string"},
                  "focusTopic": {"type": "string", "maxLength": 80, "description": "Optional focus for the summary.", "example": "markets"},
                  "maxBulletsAmount": {"type": "integer", "minimum": 1, "maximum": 8, "description": "Number of summary bullets.", "example": 3},
                  "strictMode": {"type": "boolean", "description": "Keep the output within the requested topic.", "example": True},
                  "regenerate": {"type": "boolean", "description": "Generate a fresh result; may incur generation costs.", "example": False}}}
    response = {"description": "Local summary", "content": {"application/json": {"schema": {"type": "object"}}}}
    return {"openapi": "3.0.3", "info": {"title": "Namazu local UX fixture", "version": "1"},
            "servers": [{"url": base + "/uniform", "description": "Uniform application denials"},
                        {"url": base + "/success", "description": "Successful business requests"}],
            "security": [{"fixtureBearer": []}],
            "components": {"securitySchemes": {"fixtureBearer": {"type": "http", "scheme": "bearer"}}},
            "paths": {"/summaries": {"post": {"summary": "Create a local summary", "requestBody": {"required": True,
                "content": {"application/json": {"schema": schema}}},
                "responses": {"200": response, "400": {"description": "Field validation rejected this input"},
                              "401": {"description": "Identity was not accepted"}, "403": {"description": "Request denied"}}}},
                "/identity": {"get": {"summary": "Read the local identity", "responses": {"200": response, "401": {"description": "Identity was not accepted"}}}}}}


def known_good(base, identity="primary"):
    return {"method": "POST", "url": base + "/success/summaries",
            "headers": {"Authorization": "Bearer local-" + identity, "Content-Type": "application/json"},
            "body": json.dumps(BODY, separators=(",", ":"))}


def receipt(base, identity="primary"):
    request = known_good(base, identity)
    return {"label": "baseline", "endpoint": "POST /summaries", "method": "POST", "url": request["url"],
            "request_headers": request["headers"], "request_body": request["body"], "identity_ref": identity,
            "identity": identity, "status": 200, "response_headers": {"content-type": "application/json"},
            "response_body": json.dumps({"documentUri": "doc-local", "summary": "Local fixture summary for doc-local",
                                         "personaId": "persona-reader", "focusTopic": "markets"}),
            "truncated": False, "error": "", "seqGlobal": 1}


def prepared_input(base, identity="primary"):
    return {"request": known_good(base, identity), "identity_ref": identity, "expectation": {"status": "200"},
            "assertions": copy.deepcopy(ASSERTIONS), "recorded_response": receipt(base, identity),
            "operation": "POST /summaries"}


def permission_matrix(base):
    # This deliberately allows the shared resource. Cross-user access is not
    # inherently forbidden; the owner-supplied expectations define the test.
    return [{"kind": "entitlement", "identity_ref": "secondary", "expect": "allow",
             "assertions": copy.deepcopy(ASSERTIONS), "identity_control": prepared_input(base, "secondary")}]


def successful_report(base, two_identities=False):
    parsed = parse_spec(api_document(base))
    captured = receipt(base)
    safe = readiness.prepare(prepared_input(base))
    snapshot = contract.snapshot(parsed, next(op for op in parsed["operations"] if op["id"] == "POST /summaries"),
                                 request_url=captured["url"])
    return {"application": "Namazu", "export": "security-audit", "tool_version": __version__,
            "started_at": "2026-10-09T08:20:43Z", "findings": [],
            "api": {"title": "Local successful baseline fixture", "base_url": base + "/success", "version": "1"},
            "run": {"status": "completed", "environment": "local fixture"},
            "provenance": {"kind": "imported-historical-run", "requests_sent_during_current_action": 0,
                           "source_run": {"target": base + "/success", "environment": "local fixture",
                                          "started_at": "2026-10-09T08:20:43Z", "tool_version": __version__, "status": "completed"}},
            "scope": {"profile": "writes", "requests_sent": 1, "endpoints_audited": 1, "endpoints_in_scope": 1,
                      "second_identity": two_identities},
            "requests": [{**captured, "request_headers": {"Authorization": "<credential>", "Content-Type": "application/json"}}],
            "contract_snapshots": {"POST /summaries": snapshot},
            "coverage": {"baselines": [{"endpoint": "POST /summaries", "status": 200, "outcome": "success",
                                         "positive_control": True, "exchange": safe["recorded_response"]}],
                         "checks": [], "probes": []},
            "readiness": {"prepared": safe, "configuration": {"permission_matrix":
                          readiness.prepare({**prepared_input(base), "configuration": {"permission_matrix": permission_matrix(base)}})["configuration"]["permission_matrix"] if two_identities else []}}}


def old_mixed_report():
    fixture = json.loads((Path(__file__).parent / "fixtures/response_classification_export.json").read_text(encoding="utf-8"))
    coverage = fixture["notes_audit"]["coverage"]
    coverage["baselines"] = [{"endpoint": "POST /mock", "status": 403, "positive_control": False,
                              "outcome": "denied", "exchange": fixture["baseline"]}]
    return {"application": "Namazu", "export": "security-audit", "started_at": "2026-10-09T08:20:43Z",
            "api": {"title": "Sanitised historical mixed outcomes", "base_url": "http://127.0.0.1", "version": "1"},
            "scope": {"profile": "writes", "requests_sent": 141, "endpoints_audited": 1, "endpoints_in_scope": 1,
                      "second_identity": False}, "findings": [], "requests": fixture["requests"],
            "coverage": coverage, "notes": fixture["notes_audit"].get("notes", [])}


def reports_page(base):
    examples = [("known-good", "Known-good request JSON", known_good(base)),
                ("assertions", "Business success assertions", ASSERTIONS),
                ("recorded-response", "Recorded successful baseline response", receipt(base)),
                ("permission-matrix", "Two-identity permission expectations", permission_matrix(base)),
                ("old-export", "Old mixed audit without contract snapshot", old_mixed_report()),
                ("successful-export", "Successful baseline with one identity", successful_report(base)),
                ("two-identity-export", "Successful baseline with two identities", successful_report(base, True))]
    chunks = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">',
              '<title>Namazu local UX fixtures</title><h1>Local UX fixtures</h1>',
              '<p>Only inert localhost data. Copy an example into Namazu. Importing evidence should not change /stats API attempt counts.</p>']
    for key, label, value in examples:
        chunks.append(f'<p><label for="{key}">{html.escape(label)}</label><br><textarea id="{key}" rows="10" cols="100" spellcheck="false">'
                      + html.escape(json.dumps(value, indent=2)) + '</textarea></p>')
    return ''.join(chunks) + '</html>'


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0, *, timeout_delay=1.5):
        super().__init__(("127.0.0.1", port), FixtureHandler)
        self.timeout_delay = max(0.05, min(float(timeout_delay), 10))
        self.attempts = []
        self.attempt_lock = threading.Lock()
        # Reliability knobs, all off by default so existing journeys are
        # unchanged. ``throttle_after`` turns every counted attempt beyond that
        # number into an HTTP 429, so a run-wide rate-limit stop can be observed
        # crossing operation boundaries. ``commits`` counts the writes the
        # fixture actually accepted (a successful POST /summaries), so a test can
        # prove a write happened and was neither undone by a stop nor replayed.
        self.throttle_after = None
        self.commits = 0

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server_port}"


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value, *, media="application/json", headers=None):
        raw = (json.dumps(value) if media == "application/json" else value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.wfile.write(raw)

    def identity(self):
        return {"Bearer local-primary": "primary", "Bearer local-secondary": "secondary"}.get(self.headers.get("Authorization"))

    def record_attempt(self):
        with self.server.attempt_lock:
            self.server.attempts.append({"method": self.command, "path": urlsplit(self.path).path,
                                         "identity": self.identity() or "unaccepted"})

    def throttled(self):
        """Once the configured number of attempts is exceeded, every further
        request is a 429. Returns True (and replies) when it fired."""
        after = self.server.throttle_after
        if after is None:
            return False
        with self.server.attempt_lock:
            over = len(self.server.attempts) > after
        if over:
            self.reply(429, {"error": "rate_limited", "detail": "Local fixture rate limit reached"},
                       headers={"Retry-After": "1"})
            return True
        return False

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/docs":
            return self.reply(200, '<html><a href="/openapi.json">Download OpenAPI specification</a></html>', media="text/html")
        if path == "/openapi.json":
            return self.reply(200, api_document(self.server.base))
        if path == "/reports":
            return self.reply(200, reports_page(self.server.base), media="text/html")
        if path == "/stats":
            with self.server.attempt_lock:
                return self.reply(200, {"api_request_attempts": len(self.server.attempts),
                                        "commits": self.server.commits, "attempts": list(self.server.attempts)})
        self.record_attempt()
        if self.throttled():
            return None
        if path.endswith("/identity"):
            return self.reply(200, {"identity": self.identity(), "authenticated": True}) if self.identity() else self.reply(401, {"error": "invalid_token"})
        return self.reply(404, {"detail": "Local fixture route not found"})

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 1024 * 1024:
            return self.reply(413, {"error": "Local fixture request too large"})
        raw = self.rfile.read(size)
        path = urlsplit(self.path).path
        self.record_attempt()
        if self.throttled():
            return None
        if path == "/oauth/token":
            return self.reply(400, {"error": "invalid_client", "error_description": "Local fixture token acquisition failed"})
        if not path.endswith("/summaries"):
            return self.reply(404, {"detail": "Local fixture route not found"})
        if not self.identity():
            return self.reply(401, {"error": "invalid_token", "detail": "The local credential is missing or expired"})
        if path.startswith("/slow/") or path.startswith("/timeout/"):
            time.sleep(self.server.timeout_delay)
        if path.startswith("/uniform/"):
            return self.reply(403, DENIAL, headers={"fm-correlation-id": "local-" + str(len(self.server.attempts)), "x-iinfo": "local diagnostic"})
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {"errors": {"body": ["Expected a JSON object"]}})
        if not isinstance(body, dict):
            return self.reply(400, {"errors": {"body": ["Expected an object"]}})
        if path.startswith("/mixed/") and not isinstance(body.get("strictMode"), bool):
            return self.reply(403, EDGE, media="text/html")
        if path.startswith("/mixed/") and body.get("focusTopic") == "timeout":
            time.sleep(self.server.timeout_delay)
        errors = {}
        for name in ("documentUri", "personaId"):
            if not isinstance(body.get(name), str) or not body[name]:
                errors[name] = ["A nonempty string is required"]
        count = body.get("maxBulletsAmount")
        if type(count) is not int or not 1 <= count <= 8:
            errors["maxBulletsAmount"] = ["An integer between 1 and 8 is required"]
        if not isinstance(body.get("strictMode"), bool):
            errors["strictMode"] = ["A boolean is required"]
        if errors:
            return self.reply(400, {"title": "Validation rejected this input", "errors": errors})
        if path.startswith("/mixed/") or body["documentUri"] == "string" or body["personaId"] == "string":
            return self.reply(403, DENIAL)
        if self.identity() == "secondary" and body["documentUri"] == "doc-private":
            return self.reply(403, DENIAL)
        # An accepted write. Counting it here (not at attempt time) lets a test
        # prove the write actually committed, and that a stop never undid it and
        # a restart never replayed it.
        with self.server.attempt_lock:
            self.server.commits += 1
        return self.reply(200, {"documentUri": body["documentUri"], "summary": "Local fixture summary for " + body["documentUri"],
                                "personaId": body["personaId"], "focusTopic": body.get("focusTopic", "")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9137)
    parser.add_argument("--timeout-delay", type=float, default=1.5)
    args = parser.parse_args()
    with FixtureServer(args.port, timeout_delay=args.timeout_delay) as server:
        print(f"Local UX fixture: {server.base}/docs ; examples: {server.base}/reports", flush=True)
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()


if __name__ == "__main__":
    main()
