"""Namazu must not announce itself as python-httpx.

A WAF in front of the target refuses an unfamiliar client, and httpx's default
User-Agent is exactly that. When it does, the operator sees a block page from
the security service rather than a token, and nothing in the tool explains why.
So every path that opens a socket carries an identity, and the operator can
replace it when an engagement needs a different one.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from namazu import __version__, oauth
from namazu.audit import audit_operation
from namazu.audit.transport import Budget, Executor, build_client
from namazu.discovery import DEFAULT_USER_AGENT, client_headers, fetch_document
from namazu.spec import parse_spec


@pytest.fixture
def server():
    """A server that records the User-Agent of everything it is sent."""
    seen: list = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def _record(self):
            with lock:
                seen.append(self.headers.get("User-Agent"))

        def _reply(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._record()
            if "well-known" in self.path:
                return self._reply({"issuer": "https://id.test",
                                    "token_endpoint": "https://id.test/token",
                                    "authorization_endpoint": "https://id.test/authorize"})
            self._reply({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._record()
            self._reply({"access_token": "at", "token_type": "Bearer", "expires_in": 600})

    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{instance.server_address[1]}", seen
    instance.shutdown()


def test_the_default_names_namazu_and_its_version():
    assert DEFAULT_USER_AGENT.startswith(f"Namazu/{__version__}")
    assert "httpx" not in DEFAULT_USER_AGENT
    assert client_headers(None) == {"User-Agent": DEFAULT_USER_AGENT}
    assert client_headers("   ") == {"User-Agent": DEFAULT_USER_AGENT}


def test_an_operator_can_replace_it():
    assert client_headers("Engagement/1") == {"User-Agent": "Engagement/1"}


def test_a_user_agent_cannot_smuggle_a_header():
    with pytest.raises(ValueError, match="line breaks"):
        client_headers("Engagement/1\r\nX-Injected: yes")


def test_oauth_discovery_identifies_itself(server):
    base, seen = server
    oauth.discover(f"{base}/.well-known/openid-configuration")
    assert seen, "discovery sent no request"
    assert all(agent == DEFAULT_USER_AGENT for agent in seen), seen


def test_the_token_exchange_identifies_itself(server):
    base, seen = server
    oauth.request_token(f"{base}/token", {"grant_type": "client_credentials"}, client_id="c")
    assert seen == [DEFAULT_USER_AGENT]


def test_the_token_exchange_honours_an_override(server):
    """The case that unblocks a WAF: the operator sets what the client claims."""
    base, seen = server
    oauth.request_token(f"{base}/token", {"grant_type": "client_credentials"}, client_id="c",
                        user_agent="Engagement/7")
    assert seen == ["Engagement/7"]


def test_contract_import_identifies_itself(server):
    base, seen = server
    fetch_document(f"{base}/openapi.json", user_agent="Engagement/7")
    assert seen
    assert all(agent == "Engagement/7" for agent in seen), seen


def test_the_audit_client_identifies_itself(server):
    base, seen = server
    with build_client(user_agent="Engagement/7") as client:
        client.get(f"{base}/probe")
    assert seen == ["Engagement/7"]


def test_a_probe_header_still_wins_over_the_client_default(server):
    """An operator who sets User-Agent on the Headers tab keeps it."""
    base, seen = server
    with build_client(user_agent="Engagement/7") as client:
        executor = Executor(client, Budget(4))
        executor.send("GET", f"{base}/probe", label="probe",
                      headers={"User-Agent": "Set-On-The-Headers-Tab/1"})
    assert seen == ["Set-On-The-Headers-Tab/1"]


def test_an_audit_run_carries_the_user_agent(server):
    base, seen = server
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": base}],
        "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok", "content": {
            "application/json": {"schema": {"type": "object"}}}}}}}},
    }, base)
    audit_operation(spec, "GET /ping", base_url=base, profile="readonly",
                    user_agent="Engagement/7")
    assert seen, "the audit sent no request"
    assert set(seen) == {"Engagement/7"}, set(seen)


def test_nothing_in_the_tool_still_sends_the_httpx_default(server):
    """The regression that matters: a new client built without the helper."""
    base, seen = server
    with httpx.Client() as bare:
        bare.get(f"{base}/probe")
    assert seen == [f"python-httpx/{httpx.__version__}"], (
        "this test documents what the default looks like, so a client built "
        "without client_headers() is recognisable in the other tests")
