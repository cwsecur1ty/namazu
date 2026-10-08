"""A local API with known behaviour, for tests and for a demonstration run.

Nothing here contacts an external host. :func:`handler` returns an httpx mock
handler for unit tests, and :func:`serve` runs the same application on a
loopback socket for the cases that need a real server, which is anything
driving an external tool as a subprocess.

The behaviour is chosen to cover the states an audit has to tell apart:

``/reports/{id}``   requires a bearer token, and returns 403 for a report the
                    caller is not entitled to. Two tenants each own one report,
                    so a legitimate cross-tenant denial and a real cross-tenant
                    read are both reachable. Each report carries a marker
                    naming its owner, so a read can be verified by content
                    rather than by status code.
``/orders/{id}``    the broken one. Any valid-looking token gets any order.
``/search``         needs no credential and documents nothing about 403.
``/problems``       answers 403 with application/problem+json, which its own
                    contract does not document for that status.
``/sessions``       a POST that returns an id, for the sequence runner to
                    extract and substitute.
"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx

BASE = "https://api.fixture.test"

TOKENS = {
    "tenant-a-token-000000000000": "tenant-a",
    "tenant-b-token-000000000000": "tenant-b",
}
REPORTS = {
    "r-100": {"id": "r-100", "owner": "tenant-a", "marker": "MARKER-TENANT-A-R100",
              "title": "Tenant A quarterly"},
    "r-200": {"id": "r-200", "owner": "tenant-b", "marker": "MARKER-TENANT-B-R200",
              "title": "Tenant B quarterly"},
}
ORDERS = {"o-1": {"id": "o-1", "owner": "tenant-a", "marker": "MARKER-ORDER-O1", "total": 42.5}}

SPEC: dict = {
    "openapi": "3.0.3",
    "info": {"title": "Fixture reports API", "version": "1.0"},
    "servers": [{"url": BASE}],
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Report": {
                "type": "object",
                "required": ["id", "owner", "marker"],
                "properties": {"id": {"type": "string"}, "owner": {"type": "string"},
                               "marker": {"type": "string"}, "title": {"type": "string"}},
            },
            "Session": {"type": "object", "required": ["session_id"],
                        "properties": {"session_id": {"type": "string"}}},
        },
    },
    "security": [{"bearer": []}],
    "paths": {
        "/reports/{reportId}": {
            "get": {
                "operationId": "getReport",
                "parameters": [{"name": "reportId", "in": "path", "required": True,
                                "schema": {"type": "string"}, "example": "r-100"}],
                "responses": {
                    "200": {"description": "A report", "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Report"}}}},
                    "401": {"description": "Unauthenticated"},
                    "403": {"description": "Not entitled"},
                },
            },
        },
        "/orders/{orderId}": {
            "get": {
                "operationId": "getOrder",
                "parameters": [{"name": "orderId", "in": "path", "required": True,
                                "schema": {"type": "string"}, "example": "o-1"}],
                "responses": {"200": {"description": "An order", "content": {
                    "application/json": {"schema": {"type": "object"}}}}},
            },
        },
        "/search": {
            "get": {
                "operationId": "search",
                "security": [],
                "parameters": [{"name": "q", "in": "query",
                                "schema": {"type": "string"}, "example": "quarterly"}],
                "responses": {"200": {"description": "Hits", "content": {
                    "application/json": {"schema": {"type": "object"}}}}},
            },
        },
        "/problems": {
            "get": {
                "operationId": "problem",
                # 403 documents application/json only, and the handler answers
                # with application/problem+json. That is the contract defect.
                "responses": {
                    "200": {"description": "Fine", "content": {
                        "application/json": {"schema": {"type": "object"}}}},
                    "403": {"description": "Denied", "content": {
                        "application/json": {"schema": {
                            "type": "object", "required": ["title", "status"],
                            "properties": {"title": {"type": "string"},
                                           "status": {"type": "integer"}}}}}},
                },
            },
        },
        "/sessions": {
            "post": {
                "operationId": "createSession",
                "requestBody": {"required": True, "content": {"application/json": {
                    "schema": {"type": "object", "required": ["label"],
                               "properties": {"label": {"type": "string"}}}}}},
                "responses": {"201": {"description": "Created", "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/Session"}}}}},
            },
        },
    },
}

# What an id looks like here. A request carrying a placeholder the example
# generator produced, such as the literal "string", is answered as invalid
# input rather than as a permission decision, which is the distinction a
# baseline classifier has to be able to see.
PLACEHOLDERS = {"string", "0", "", "null", "none", "123e4567-e89b-12d3-a456-426614174000"}
_ID = re.compile(r"^[a-z]-\d+$")


def _tenant(authorization: str) -> str | None:
    text = (authorization or "").strip()
    if not text.lower().startswith("bearer "):
        return None
    return TOKENS.get(text.split(" ", 1)[1].strip())


def route(method: str, path: str, query: str, headers: dict, body: str) -> tuple:
    """(status, headers, body) for one request. The whole application logic."""
    lowered = {str(name).lower(): value for name, value in (headers or {}).items()}
    authorization = lowered.get("authorization", "")
    tenant = _tenant(authorization)
    params = parse_qs(query or "")

    if path == "/openapi.json":
        return 200, {"Content-Type": "application/json"}, json.dumps(SPEC)

    if path == "/search":
        term = (params.get("q") or [""])[0]
        return 200, {"Content-Type": "application/json"}, json.dumps({"hits": 0, "q": term})

    if path == "/problems":
        # Denies everyone, in a media type its own 403 does not document.
        return 403, {"Content-Type": "application/problem+json"}, json.dumps(
            {"title": "Not entitled to this resource", "status": 403})

    if path == "/sessions":
        if method != "POST":
            return 405, {"Content-Type": "application/json"}, json.dumps({"detail": "method"})
        if not tenant:
            return 401, {"Content-Type": "application/json"}, json.dumps({"detail": "unauthenticated"})
        try:
            label = (json.loads(body or "{}") or {}).get("label")
        except ValueError:
            label = None
        if not isinstance(label, str) or not label or label in PLACEHOLDERS:
            return 422, {"Content-Type": "application/json"}, json.dumps(
                {"detail": "label must be a non-empty label"})
        return 201, {"Content-Type": "application/json"}, json.dumps(
            {"session_id": f"sess-{tenant}-{abs(hash(label)) % 10000}"})

    if path.startswith("/reports/"):
        report_id = path.split("/reports/", 1)[1]
        if not tenant:
            return 401, {"Content-Type": "application/json", "WWW-Authenticate": "Bearer"}, \
                json.dumps({"detail": "unauthenticated"})
        if report_id in PLACEHOLDERS or not _ID.match(report_id):
            # Not a permission decision. The identifier is not one of ours.
            return 422, {"Content-Type": "application/json"}, json.dumps(
                {"detail": f"reportId {report_id!r} is not a report identifier"})
        report = REPORTS.get(report_id)
        if report is None:
            return 404, {"Content-Type": "application/json"}, json.dumps({"detail": "no such report"})
        if report["owner"] != tenant:
            # Correct behaviour: a real authorization boundary, enforced.
            return 403, {"Content-Type": "application/json"}, json.dumps(
                {"detail": "caller is not entitled to this report"})
        return 200, {"Content-Type": "application/json"}, json.dumps(report)

    if path.startswith("/orders/"):
        order_id = path.split("/orders/", 1)[1]
        if not tenant:
            return 401, {"Content-Type": "application/json"}, json.dumps({"detail": "unauthenticated"})
        if order_id in PLACEHOLDERS:
            return 422, {"Content-Type": "application/json"}, json.dumps({"detail": "bad id"})
        order = ORDERS.get(order_id)
        if order is None:
            return 404, {"Content-Type": "application/json"}, json.dumps({"detail": "no such order"})
        # The broken one: authenticated is treated as authorized.
        return 200, {"Content-Type": "application/json"}, json.dumps(order)

    return 404, {"Content-Type": "application/json"}, json.dumps({"detail": "not found"})


def handler(record: list | None = None):
    """An httpx mock transport handler over :func:`route`."""

    def respond(request: httpx.Request) -> httpx.Response:
        parts = urlsplit(str(request.url))
        body = request.content.decode("utf-8", "replace") if request.content else ""
        status, headers, text = route(request.method, parts.path, parts.query,
                                      dict(request.headers), body)
        if record is not None:
            record.append({"method": request.method, "path": parts.path, "query": parts.query,
                           "authorization": request.headers.get("authorization", ""),
                           "status": status})
        return httpx.Response(status, headers=headers, content=text.encode("utf-8"))

    return respond


def client(record: list | None = None) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler(record)), base_url=BASE)


# ── a real socket, for subprocess tools ──────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _serve(self):
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        status, headers, text = route(self.command, parts.path, parts.query,
                                      dict(self.headers), body)
        payload = text.encode("utf-8")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = _serve


def serve(port: int = 0) -> tuple:
    """Start the fixture on loopback. Returns (base_url, shutdown)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def shutdown():
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    return base, shutdown


if __name__ == "__main__":
    import sys

    base, _stop = serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8111)
    print(f"fixture on {base}", flush=True)
    threading.Event().wait()
