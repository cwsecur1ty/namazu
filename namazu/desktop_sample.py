"""Explicitly opened local sample. No external hosts, credentials or startup traffic."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .workspaces import service

_server = None
_lock = threading.Lock()


class SampleHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path.split("?", 1)[0] not in {"/sample/accounts/widgets/17", "/sample/orders/widgets/17"}:
            status, body = 404, {"error": "Local sample only knows the documented widget 17"}
        else:
            status, body = 200, {"id": 17, "name": "Local sample widget", "sample": True}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Namazu-Local-Sample", "true")
        self.end_headers()
        self.wfile.write(data)


def sample_origin():
    global _server
    with _lock:
        if _server is None:
            _server = ThreadingHTTPServer(("127.0.0.1", 0), SampleHandler)
            _server.daemon_threads = True
            threading.Thread(target=_server.serve_forever, daemon=True, name="namazu-local-sample").start()
        return f"http://127.0.0.1:{_server.server_port}"


def create_sample():
    origin = sample_origin()
    workspace = service().create("Local sample")
    items = []
    for name in ("accounts", "orders"):
        spec = {"openapi": "3.0.3", "info": {"title": f"Local sample {name}", "version": "1.0"},
                "servers": [{"url": origin + "/sample/" + name}],
                "paths": {"/widgets/{id}": {"get": {"operationId": "getWidget", "tags": ["Widgets"],
                    "summary": "Read documented sample widget", "description": "Local mock data only. No API security coverage is established.",
                    "parameters": [{"name": "id", "in": "path", "required": True, "example": 17, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Local sample", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Widget"}}}},
                                  "404": {"description": "Unknown sample widget"}}}}},
                "components": {"schemas": {"Widget": {"type": "object", "required": ["id", "name", "sample"],
                    "properties": {"id": {"type": "integer"}, "name": {"type": "string"}, "sample": {"type": "boolean"}}}}}}
        items.append({"filename": f"local-sample-{name}.json", "raw_spec": json.dumps(spec)})
    service().import_contracts(workspace["id"], items)
    return service().get(workspace["id"])
