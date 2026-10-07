"""A security product's block page must be named, not reported as a bad API.

"The token endpoint returned a non-JSON response (HTTP 403)" is true and
useless. It reads as a broken authorization server, so the operator goes
looking at their client secret, when the request never arrived anywhere near
one. The distinction the report has to make is which hop refused it.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from namazu import oauth
from namazu.discovery import describe_block

IMPERVA_BODY = (
    "<html><head><title>Access Denied</title></head><body>"
    "<h2>What happened?</h2>"
    "<p>This request was blocked by our security service</p>"
    "<p>Your support ID is: 8841267799113344556</p></body></html>"
)


def test_an_imperva_block_page_is_named():
    message = describe_block(403, {"X-Iinfo": "7-1234-5678 NNNY CT(1 1 0)"}, IMPERVA_BODY)
    assert "Imperva" in message
    assert "not from the authorization server" in message
    assert "no credential of yours was rejected" in message
    assert "8841267799113344556" in message


def test_a_cloudflare_block_page_is_named():
    message = describe_block(403, {"CF-Ray": "8f2a1b4c-LHR"},
                             "<h1>Attention Required!</h1><p>Ray ID: 8f2a1b4c</p>")
    assert "Cloudflare" in message
    assert "8f2a1b4c" in message


def test_wording_alone_is_enough_when_no_vendor_header_is_present():
    """A WAF behind a reverse proxy may strip its own headers."""
    message = describe_block(403, {"Content-Type": "text/html"},
                             "<p>This request was blocked by our security service</p>")
    assert message
    assert "a security service" in message


def test_a_real_oauth_error_is_left_alone():
    """Never tell someone their credentials were fine when they were not."""
    assert describe_block(400, {"Content-Type": "application/json"},
                          '{"error":"invalid_client"}') == ""
    assert describe_block(401, {"Content-Type": "application/json"},
                          '{"error":"invalid_grant",'
                          '"error_description":"Refresh token expired"}') == ""


def test_a_plain_404_is_left_alone():
    assert describe_block(404, {}, "<html><body>Not Found</body></html>") == ""


@pytest.fixture
def blocking_server():
    """A host whose WAF refuses everything with a block page."""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def _block(self):
            raw = IMPERVA_BODY.encode()
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Iinfo", "7-1234-5678 NNNY CT(1 1 0)")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._block()

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._block()

    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{instance.server_address[1]}"
    instance.shutdown()


def test_the_token_exchange_says_it_was_blocked(blocking_server):
    with pytest.raises(ValueError) as caught:
        oauth.request_token(f"{blocking_server}/token",
                            {"grant_type": "client_credentials"}, client_id="c")
    message = str(caught.value)
    assert "Imperva" in message
    assert "non-JSON" not in message, "the old message hid what had happened"
    assert "support ID" in message


def test_discovery_records_which_candidates_were_blocked(blocking_server):
    """Discovery tries several URLs, so each attempt has to say why it failed."""
    with pytest.raises(ValueError) as caught:
        oauth.discover(f"{blocking_server}/realms/example")
    message = str(caught.value)
    assert "403" in message or "blocked" in message.lower(), message


def test_a_blocked_token_exchange_blames_nothing_on_the_credential(blocking_server):
    """The message must not imply the secret was wrong, nor echo it back."""
    with pytest.raises(ValueError) as caught:
        oauth.request_token(f"{blocking_server}/token",
                            {"grant_type": "refresh_token",
                             "refresh_token": "refresh-token-dRowssaP"},
                            client_id="client-abc", client_secret="secret-hunter2")
    message = str(caught.value)
    assert "no credential of yours was rejected" in message
    assert "invalid" not in message.lower()
    # Nothing secret travels into an error an operator will paste into a ticket.
    assert "hunter2" not in message
    assert "dRowssaP" not in message
