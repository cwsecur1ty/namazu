"""The inventory sweep against hosts that answer every path.

A single page application serves its shell for any route so the client-side
router can handle it. The sweep calibrates against a path that cannot exist and
discards hits that match that response, but a shell whose length moves with the
path, which is what happens when the route is echoed into the page or a nonce
is stamped into it, is no longer within the length tolerance. Every documented
and conventional path then reads as an undocumented endpoint, which is a page
of findings about a host with nothing on it.
"""
import random

import httpx

from namazu.audit import audit_inventory
from namazu.spec import parse_spec

BASE = "https://api.example.test"


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE)


def _empty_spec():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {}}, BASE)


def _ids(result):
    return [finding["id"] for finding in result["findings"]]


SHELL = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    '<title>Example dashboard</title>'
    '<link rel="stylesheet" href="/assets/index-a81b2f.css">'
    '<script type="module" src="/assets/index-7f3c91.js"></script>'
    '</head><body><div id="root"></div></body></html>'
)


def test_a_fixed_length_shell_produces_no_findings():
    """The case already handled: identical shell for every path."""
    with _client(lambda request: httpx.Response(200, html=SHELL)) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    assert result["discovery"]["catch_all"] is True
    assert "inventory.undocumented-endpoint" not in _ids(result)


def test_a_shell_that_echoes_the_route_produces_no_findings():
    """The case the card asked about: length moves with the requested path."""
    def handler(request):
        # A canonical link carrying the route is ordinary in an SPA, and it
        # makes the body length a function of the path.
        shell = SHELL.replace(
            "</head>", f'<link rel="canonical" href="{request.url.path}"></head>')
        return httpx.Response(200, html=shell)

    with _client(handler) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    shadow = [finding for finding in result["findings"]
              if finding["id"] in ("inventory.undocumented-endpoint", "inventory.source-exposed")]
    assert not shadow, [finding["endpoint"] for finding in shadow]


def test_a_shell_carrying_a_nonce_produces_no_findings():
    """A per-response CSP nonce changes the body without changing the page."""
    counter = {"n": 0}

    def handler(request):
        counter["n"] += 1
        nonce = f"nonce-{counter['n']:08d}" * 3
        shell = SHELL.replace("<script", f'<script nonce="{nonce}"', 1)
        return httpx.Response(200, html=shell)

    with _client(handler) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    assert "inventory.undocumented-endpoint" not in _ids(result)


def test_a_shell_carrying_a_variable_length_session_blob_produces_no_findings():
    """The case that actually defeated the length tolerance.

    Before the shell fingerprint this produced eleven findings, including
    /.env, /admin, /internal and /actuator/env, on a host serving nothing but
    its own front end.
    """
    rng = random.Random(7)

    def handler(request):
        blob = "x" * rng.randint(0, 400)
        shell = SHELL.replace(
            "</head>", f'<script>window.__BOOT__={{"session":"{blob}"}}</script></head>')
        return httpx.Response(200, html=shell)

    with _client(handler) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    shadow = [finding["endpoint"] for finding in result["findings"]
              if finding["id"] in ("inventory.undocumented-endpoint", "inventory.source-exposed")]
    assert not shadow, shadow


def test_a_shell_whose_length_swings_with_the_route_produces_no_findings():
    """Sixteen findings before the fingerprint."""
    def handler(request):
        shell = SHELL.replace(
            "</head>", f'<meta name="route" content="{request.url.path * 12}"></head>')
        return httpx.Response(200, html=shell)

    with _client(handler) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    shadow = [finding["endpoint"] for finding in result["findings"]
              if finding["id"] in ("inventory.undocumented-endpoint", "inventory.source-exposed")]
    assert not shadow, shadow


def test_a_page_with_no_build_assets_is_not_treated_as_a_shell():
    """An absent fingerprint must never match another absent one."""
    from namazu.audit.inventory import _shell_signature
    assert _shell_signature("<html><title>x</title></html>", "text/html") is None
    assert _shell_signature(SHELL, "application/json") is None
    assert _shell_signature(SHELL, "text/html; charset=utf-8") is not None


def test_a_genuinely_different_page_is_still_reported():
    """Tightening must not blind the sweep to a real undocumented endpoint."""
    def handler(request):
        if request.url.path == "/actuator/env":
            return httpx.Response(200, json={
                "activeProfiles": ["production"],
                "propertySources": [{"name": "systemEnvironment", "properties": {
                    "DATABASE_URL": {"value": "postgres://app:hunter2@db.internal:5432/app"},
                    "AWS_SECRET_ACCESS_KEY": {"value": "redacted-but-present"}}}]})
        return httpx.Response(200, html=SHELL.replace(
            "</head>", f'<link rel="canonical" href="{request.url.path}"></head>'))

    with _client(handler) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    hit = next((finding for finding in result["findings"]
                if finding["id"] == "inventory.undocumented-endpoint"), None)
    assert hit is not None, "a real operational endpoint was missed"
    assert hit["endpoint"] == "GET /actuator/env"


def test_an_exposed_specification_is_still_reported_on_an_spa_host():
    """The other direction: a real document behind a catch-all host."""
    def handler(request):
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={
                "openapi": "3.0.3", "info": {"title": "Internal", "version": "2"},
                "paths": {"/admin/users": {"get": {"responses": {"200": {"description": "ok"}}}}}})
        return httpx.Response(200, html=SHELL.replace(
            "</head>", f'<link rel="canonical" href="{request.url.path}"></head>'))

    with _client(handler) as client:
        result = audit_inventory(_empty_spec(), base_url=BASE, client=client)
    assert "inventory.docs-exposed" in _ids(result)
