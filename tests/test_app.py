"""Standalone API and loopback end-to-end tests; no K9 database or external target."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread

from fastapi.testclient import TestClient
import pytest

from namazu.app import app


@pytest.fixture
def app_client():
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client


def test_import_raw_contract_exposes_schema_and_operations(app_client, api_document):
    response = app_client.post("/api/import", json={"raw_spec": json.dumps(api_document)})

    assert response.status_code == 200, response.text
    imported = response.json()
    assert imported["title"] == "Widget test API"
    assert imported["document"]["openapi"] == "3.0.3"
    assert imported["schemas"]
    assert len(imported["operations"]) == 2


def test_prepare_preserves_edited_nested_post_body(app_client, api_document, widget_body):
    response = app_client.post("/api/prepare", json={
        "spec": api_document, "operation_id": "POST /widgets", "body": widget_body,
        "headers": {"X-Request-ID": "namazu-test"},
    })

    assert response.status_code == 200, response.text
    prepared = response.json()
    assert prepared["method"] == "POST"
    assert prepared["url"] == "https://api.example.test/widgets"
    assert prepared["body"] == widget_body
    assert prepared["headers"]["X-Request-ID"] == "namazu-test"
    assert prepared["request_validation"]["valid"] is True


def test_prepare_reports_nested_request_error_without_network(app_client, api_document, widget_body):
    widget_body["items"][0]["quantity"] = 0
    response = app_client.post("/api/prepare", json={
        "spec": api_document, "operation_id": "POST /widgets", "body": widget_body,
    })

    assert response.status_code == 200, response.text
    validation = response.json()["request_validation"]
    assert validation["valid"] is False
    assert "quantity" in json.dumps(validation["errors"])


def test_run_rejects_post_without_opt_in(app_client, api_document, widget_body):
    response = app_client.post("/api/run", json={
        "spec": api_document, "operation_id": "POST /widgets", "body": widget_body,
    })

    assert response.status_code in (400, 403, 422)
    assert any(word in response.text.lower() for word in ("mutating", "allow_mutating", "confirm"))


def test_import_rejects_invalid_document(app_client):
    response = app_client.post("/api/import", json={"raw_spec": '{"message":"not an API contract"}'})

    assert response.status_code in (400, 422)
    assert "detail" in response.json()


def test_rejects_cross_origin_execution(app_client, api_document):
    response = app_client.post("/api/prepare", headers={"Origin": "https://unrelated.example"},
                               json={"spec": api_document, "operation_id": "POST /widgets"})
    assert response.status_code == 403


def test_rejects_foreign_host_before_proxy_access(app_client):
    response = app_client.get("/api/health", headers={"Host": "attacker.example"})
    assert response.status_code == 400


def test_accepts_same_origin_prepare(app_client, api_document):
    response = app_client.post("/api/prepare", headers={"Origin": "http://127.0.0.1"},
                               json={"spec": api_document, "operation_id": "POST /widgets"})
    assert response.status_code == 200


def test_documentation_url_to_post_run_over_loopback(app_client, api_document, widget_body, widget_response):
    document = deepcopy(api_document)
    received = []

    class TargetHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _respond(self, status, body, content_type):
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            if self.path == "/docs":
                self._respond(200, '<html><script>SwaggerUIBundle({url:"/openapi.json"})</script></html>', "text/html")
            elif self.path == "/openapi.json":
                self._respond(200, json.dumps(document), "application/json")
            else:
                self._respond(404, "{}", "application/json")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append({"path": self.path, "body": json.loads(self.rfile.read(length)),
                             "content_type": self.headers.get("Content-Type")})
            self._respond(201, json.dumps(widget_response), "application/json")

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    origin = f"http://127.0.0.1:{target.server_port}"
    document["servers"] = [{"url": origin}]
    thread = Thread(target=target.serve_forever, daemon=True)
    thread.start()
    try:
        imported_response = app_client.post("/api/import", json={"url": origin + "/docs"})
        assert imported_response.status_code == 200, imported_response.text
        imported = imported_response.json()
        assert imported["base_url"] == origin
        prepared = app_client.post("/api/prepare", json={
            "spec": imported["document"], "operation_id": "POST /widgets", "body": widget_body,
        })
        assert prepared.status_code == 200, prepared.text
        executed = app_client.post("/api/run", json={
            "spec": imported["document"], "operation_id": "POST /widgets",
            "body": prepared.json()["body"], "allow_mutating": True,
        })
        assert executed.status_code == 200, executed.text
        result = executed.json()
        assert result["response"]["status"] == 201
        assert result["validation"]["valid"] is True
        assert received == [{"path": "/widgets", "body": widget_body, "content_type": "application/json"}]
    finally:
        target.shutdown()
        target.server_close()
        thread.join(timeout=2)
