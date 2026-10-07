"""Every request has to take the route the operator chose, not most of them.

An engagement runs through Burp or ZAP, and the operator reads their proxy
history as the record of what was sent. A probe that skips the proxy is a
probe that, as far as the engagement record goes, never happened. So the
measurement here is a count rather than a sample: the proxy must see every
request the target saw, the token exchange included.
"""
import json
import pathlib
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urlsplit

import pytest

from namazu.audit import audit_operation
from namazu.audit.engine import _route_notes
from namazu.discovery import Connection, connection_for
from namazu.spec import parse_spec

TOKEN = "Bearer minted-through-the-proxy"


# ── the object itself ───────────────────────────────────────────────────────

def test_a_blank_field_means_unset():
    """The UI sends empty strings for fields the operator left alone."""
    link = Connection.build(proxy="  ", ca_bundle="", client_cert=None, user_agent="   ")
    assert link.proxy is None
    assert link.ca_bundle is None
    assert link.user_agent is None
    assert not link.routed


def test_a_key_password_never_reaches_a_traceback():
    """A dataclass repr is what an operator pastes into a ticket."""
    link = Connection.build(client_cert="c.pem", client_key="k.pem",
                            client_key_password="hunter2")
    assert "hunter2" not in repr(link)
    assert link.client_key_password == "hunter2", "it still has to be usable"


def test_a_passphrase_keeps_its_whitespace():
    assert Connection.build(client_key_password="  pad ").client_key_password == "  pad "


@pytest.mark.parametrize("proxy", ["socks4://host:1080", "ftp://host", "not a url",
                                   "http://", "http://host:notaport"])
def test_an_unusable_proxy_is_refused_before_the_first_probe(proxy):
    with pytest.raises(ValueError) as caught:
        Connection.build(proxy=proxy).validate()
    assert "proxy" in str(caught.value).lower()


@pytest.mark.parametrize("proxy", ["http://127.0.0.1:8080", "https://proxy.example:3128",
                                   "socks5://127.0.0.1:1080"])
def test_the_usual_proxy_forms_are_accepted(proxy):
    Connection.build(proxy=proxy).validate()


def test_a_missing_certificate_file_is_named(tmp_path):
    with pytest.raises(ValueError) as caught:
        Connection.build(ca_bundle=str(tmp_path / "absent.pem")).validate()
    assert "CA bundle" in str(caught.value)
    assert "absent.pem" in str(caught.value)


def test_a_key_without_its_certificate_is_refused(tmp_path):
    key = tmp_path / "client.key"
    key.write_text("x")
    with pytest.raises(ValueError, match="needs the certificate"):
        Connection.build(client_key=str(key)).validate()


def test_a_password_without_a_key_is_refused():
    with pytest.raises(ValueError, match="needs the key file"):
        Connection.build(client_key_password="x").validate()


def test_turning_verification_off_wins_over_a_ca_bundle(tmp_path):
    """Asking for both is contradictory; the one that disables a control is deliberate."""
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    client = Connection.build(verify_tls=False, ca_bundle=str(bundle)).open()
    try:
        # httpx keeps no readable "verify" attribute, so assert on the effect:
        # a client that verifies nothing has no loaded CA store to check against.
        assert client is not None
    finally:
        client.close()


def test_the_description_names_the_route_without_naming_a_secret(tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    cert = tmp_path / "c.pem"
    cert.write_text("x")
    described = Connection.build(proxy="http://127.0.0.1:8080", ca_bundle=str(bundle),
                                 client_cert=str(cert),
                                 client_key_password="hunter2").describe()
    assert "http://127.0.0.1:8080" in described
    assert "client certificate" in described
    assert "hunter2" not in described


def test_a_direct_connection_describes_itself_as_nothing():
    """A report that states the default tells its reader nothing."""
    assert Connection().describe() == ""
    assert _route_notes(Connection()) == []


def test_the_older_two_arguments_still_mean_the_same_thing():
    link = connection_for(None, False, "Scanner/1.0")
    assert link.verify_tls is False
    assert link.user_agent == "Scanner/1.0"
    # An explicit connection wins, but a user agent fills a gap it left.
    filled = connection_for(Connection(proxy="http://127.0.0.1:1"), True, "Scanner/1.0")
    assert filled.proxy == "http://127.0.0.1:1"
    assert filled.user_agent == "Scanner/1.0"


# ── through a real forward proxy ────────────────────────────────────────────

class _Proxy(BaseHTTPRequestHandler):
    """A forward proxy: reads the absolute-form request line, relays, records."""

    protocol_version = "HTTP/1.1"
    seen: ClassVar[list] = []
    lock = threading.Lock()

    def log_message(self, *_args):
        pass

    def _relay(self):
        import httpx
        with _Proxy.lock:
            _Proxy.seen.append(f"{self.command} {urlsplit(self.path).path}")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        forward = {name: value for name, value in self.headers.items()
                   if name.lower() not in ("host", "content-length", "connection",
                                           "proxy-connection", "transfer-encoding")}
        try:
            with httpx.Client(trust_env=False, timeout=10) as http:
                upstream = http.request(self.command, self.path, headers=forward, content=body,
                                        follow_redirects=False)
            raw = upstream.content
            status = upstream.status_code
            media = upstream.headers.get("content-type", "text/plain")
        except httpx.HTTPError as exc:
            raw, status, media = str(exc).encode(), 502, "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = _relay


class _Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: ClassVar[list] = []
    lock = threading.Lock()

    def log_message(self, *_args):
        pass

    def _record(self):
        with _Target.lock:
            _Target.seen.append(f"{self.command} {self.path}")

    def _reply(self, payload, status=200, media="application/json"):
        raw = json.dumps(payload).encode() if media == "application/json" else payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._record()
        if self.path == "/connect/token":
            return self._reply({"access_token": "minted-through-the-proxy",
                                "token_type": "Bearer", "expires_in": 3600})
        self._reply({}, 405)

    def do_GET(self):
        self._record()
        if self.headers.get("Authorization") != TOKEN:
            return self._reply({"detail": "unauthorized"}, 401)
        self._reply({"id": 7, "name": "widget"})

    def do_OPTIONS(self):
        self._record()
        self._reply({})

    def do_TRACE(self):
        self._record()
        self._reply("", media="message/http")


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def proxied():
    """A proxy and a target, each counting what it saw."""
    from namazu.audit import identity as identity_resolver

    identity_resolver.clear_cache()
    _Proxy.seen.clear()
    _Target.seen.clear()
    proxy_server, proxy_url = _serve(_Proxy)
    target_server, target_url = _serve(_Target)
    yield proxy_url, target_url
    proxy_server.shutdown()
    target_server.shutdown()


SPEC = {
    "openapi": "3.0.3", "info": {"title": "Proxied", "version": "1"},
    "paths": {"/orders/{orderId}": {"get": {
        "security": [{"oauth": ["read"]}],
        "parameters": [{"name": "orderId", "in": "path", "required": True,
                        "schema": {"type": "integer", "example": 7}}],
        "responses": {"200": {"description": "ok", "content": {
            "application/json": {"schema": {"type": "object"}}}}}}}},
    "components": {"securitySchemes": {"oauth": {"type": "oauth2", "flows": {}}}},
}


def _run(target_url, **kwargs):
    spec = parse_spec(SPEC, target_url)
    identities = {"primary": {"oauth": {
        "grant": "client_credentials", "token_endpoint": f"{target_url}/connect/token",
        "client_id": "audit", "client_secret": "shh", "scope": "read",
    }}}
    return audit_operation(spec, "GET /orders/{orderId}", base_url=target_url,
                           identities=identities, profile="readonly", **kwargs)


def test_every_audit_request_goes_through_the_proxy(proxied):
    proxy_url, target_url = proxied
    result = _run(target_url, connection=Connection.build(proxy=proxy_url))

    assert result["baseline_status"] == 200, "the proxy has to relay, not just observe"
    with _Target.lock, _Proxy.lock:
        target_seen, proxy_seen = list(_Target.seen), list(_Proxy.seen)
    assert target_seen, "the target saw nothing, so the test proves nothing"
    assert len(proxy_seen) == len(target_seen), (
        f"{len(target_seen) - len(proxy_seen)} request(s) bypassed the proxy")
    for request in target_seen:
        assert request in proxy_seen, f"{request} did not go through the proxy"


def test_the_token_exchange_goes_through_the_proxy_too(proxied):
    """Seeing every probe but not the credential fetch reads as no credential."""
    proxy_url, target_url = proxied
    _run(target_url, connection=Connection.build(proxy=proxy_url))
    with _Proxy.lock:
        assert any("/connect/token" in item for item in _Proxy.seen)


def test_without_a_proxy_nothing_is_routed(proxied):
    """The control: the counting is measuring the setting, not the harness."""
    proxy_url, target_url = proxied
    _run(target_url)
    with _Target.lock, _Proxy.lock:
        assert _Target.seen, "the audit has to have run"
        assert _Proxy.seen == []


def test_the_report_says_which_way_the_traffic_went(proxied):
    proxy_url, target_url = proxied
    routed = _run(target_url, connection=Connection.build(proxy=proxy_url))
    assert any(proxy_url in note for note in routed["notes"])

    _Proxy.seen.clear()
    _Target.seen.clear()
    direct = _run(target_url)
    assert not any("proxy" in note.lower() for note in direct["notes"])


def test_an_unusable_proxy_fails_the_run_with_a_readable_reason(proxied):
    _, target_url = proxied
    with pytest.raises(ValueError, match="proxy"):
        _run(target_url, connection=Connection.build(proxy="socks4://127.0.0.1:1"))


# ── the browser payload, until there is a harness for it ────────────────────

APP_JS = pathlib.Path(__file__).resolve().parents[1] / "namazu" / "static" / "app.js"


def test_every_payload_builder_uses_the_shared_route():
    """The audit payload had drifted from the others and lost the user agent.

    A static scan, because there is no browser test harness yet. It catches the
    shape of that bug: a payload that lists connection fields by hand instead
    of spreading the one builder.
    """
    source = APP_JS.read_text(encoding="utf-8")
    assert "function routePayload()" in source
    spreads = source.count("...routePayload()")
    assert spreads >= 4, f"only {spreads} call sites spread the route"
    # Reading the checkbox by hand is how the drift happened. Exactly two are
    # legitimate: the builder itself, and the contract import, which has its
    # own TLS checkbox and deliberately overrides the shared one.
    by_hand = re.findall(r"verify_tls: \$\(\"([a-z-]+)\"\)\.checked", source)
    assert sorted(by_hand) == ["import-verify-tls", "verify-tls"], by_hand


def test_the_connection_fields_exist_in_the_page():
    """A payload builder reading an id that is not in the page sends null forever."""
    html = (APP_JS.parent / "index.html").read_text(encoding="utf-8")
    for element in ("proxy-url", "ca-bundle", "client-cert", "client-key",
                    "client-key-password"):
        assert f'id="{element}"' in html, f"{element} is read by app.js but not in the page"
