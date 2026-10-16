"""Opt-in loopback-only multi-contract fixture; no real credentials or data.

python -m tests.workspace_fixture_server --port 9138
"""
from __future__ import annotations

import argparse
import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def document(base: str, name: str) -> dict:
    bases = {"accounts": "/v1/accounts", "orders": "/v2/orders", "public": "/public"}
    return {
        "openapi": "3.0.3", "info": {"title": name.title() + " local API", "version": "2" if name == "orders" else "1"},
        "servers": [{"url": base + bases[name]}],
        "paths": {"/widgets/{id}": {"get": {
            "operationId": "getWidget", "summary": "Read a local " + name + " widget",
            "parameters": [{"name": "id", "in": "path", "required": True,
                            "schema": {"type": "integer", "minimum": 1, "maximum": 3}, "example": 1}],
            "responses": {"200": {"description": "Local widget", "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Widget"}}}},
                "401": {"description": "No accepted fixture identity"},
                "400": {"description": "Local input rejected"}}}}},
        "components": {"schemas": {"Widget": {"type": "object", "required": ["id", name],
            "properties": {"id": {"type": "integer"}, name: {"type": "string"}}}}},
    }


class WorkspaceFixture(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0):
        super().__init__(("127.0.0.1", port), WorkspaceHandler)
        self.attempts = []
        self.lock = threading.Lock()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server_port}"


class WorkspaceHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value, *, media="application/json", headers=None):
        raw = (json.dumps(value) if media == "application/json" else value).encode()
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/stats":
            with self.server.lock:
                return self.reply(200, {"attempts": list(self.server.attempts)})
        auth = self.headers.get("Authorization", "")
        identity = {"Bearer local-shared": "shared", "Bearer local-override": "override"}.get(auth, "anonymous")
        with self.server.lock:
            self.server.attempts.append({"method": self.command, "path": path,
                                         "identity": identity, "credential_present": bool(auth)})
        for name in ("accounts", "orders", "public"):
            if path == f"/docs/{name}":
                return self.reply(200, f'<html><a href="/specs/{name}/openapi.json">OpenAPI</a></html>', media="text/html")
            if path == f"/specs/{name}/openapi.json":
                return self.reply(200, document(self.server.base, name))
        if path.endswith("/redirect"):
            return self.reply(302, {}, headers={"Location": self.server.base + "/outside"})
        for name, prefix in (("accounts", "/v1/accounts"), ("orders", "/v2/orders"), ("public", "/public")):
            if path.startswith(prefix + "/widgets/"):
                if name != "public" and identity == "anonymous":
                    return self.reply(401, {"error": "fixture identity required"})
                value = path.rsplit("/", 1)[-1]
                if value not in ("1", "2", "3"):
                    return self.reply(400, {"errors": {"id": "Use a local id from 1 to 3"}})
                return self.reply(200, {"id": int(value), name: "local " + name + " fixture"})
        return self.reply(404, {"error": "fixture route not found"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9138)
    args = parser.parse_args()
    with WorkspaceFixture(args.port) as server:
        print(f"Local contracts: {server.base}/docs/accounts and {server.base}/docs/orders", flush=True)
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()


if __name__ == "__main__":
    main()
