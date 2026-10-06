"""Tests for the second batch of checks and for OAuth 2 support."""
import json

import httpx
import pytest

from namazu.audit import audit_inventory, audit_operation
from namazu.audit.model import Exchange
from namazu.audit.transport import Budget, Executor
from namazu.spec import parse_spec
from namazu import oauth

BASE = "https://api.example.test"
ALICE = {"Authorization": "Bearer alice-token"}


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE)


def _json(payload, status=200, headers=None):
    return httpx.Response(status, json=payload, headers=headers or {})


def _search_spec(extra_params=()):
    params = [{"name": "q", "in": "query", "schema": {"type": "string", "example": "shoes"}}]
    params += list(extra_params)
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "Search", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/search": {"get": {
            "parameters": params,
            "responses": {"200": {"description": "Hits", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"hits": {"type": "integer"}}}}}}}}}},
    }, BASE)


def _ids(result):
    return [f["id"] for f in result["findings"]]


# ── boolean-based SQL injection ─────────────────────────────────────────────

def test_boolean_sql_injection_needs_a_true_and_a_false_response():
    spec = _search_spec([{"name": "id", "in": "query",
                          "schema": {"type": "integer", "example": 5}}])

    def handler(request):
        value = request.url.params.get("id", "")
        # A toy predicate evaluator: "<n> AND a=b" returns rows only when a == b.
        if " AND " in value:
            left, right = value.split(" AND ", 1)
            a, b = right.split("=", 1)
            return _json({"hits": 1, "rows": ["row"]} if a == b else {"hits": 0, "rows": []})
        return _json({"hits": 1, "rows": ["row"]})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.sql-boolean")
    assert hit["severity"] == "critical" and hit["confidence"] == "confirmed"
    assert hit["evidence"]["true_payload"].endswith("AND 1=1")
    assert len(hit["proof"]) == 4  # baseline, true, false, confirmation


def test_boolean_sql_injection_not_reported_when_value_is_inert():
    spec = _search_spec([{"name": "id", "in": "query",
                          "schema": {"type": "integer", "example": 5}}])

    with _client(lambda r: _json({"hits": 1})) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    assert "input.sql-boolean" not in _ids(result)


# ── SSRF ────────────────────────────────────────────────────────────────────

def test_ssrf_confirmed_from_a_server_side_fetch_error():
    spec = _search_spec([{"name": "url", "in": "query",
                          "schema": {"type": "string", "example": "https://cdn.example.test/a.png"}}])

    def handler(request):
        target = request.url.params.get("url", "")
        if "namazu-probe-does-not-resolve.invalid" in target:
            return _json({"error": "getaddrinfo ENOTFOUND namazu-probe-does-not-resolve.invalid"}, 502)
        if "127.0.0.1:9" in target:
            return _json({"error": "connect ECONNREFUSED 127.0.0.1:9"}, 502)
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.ssrf-confirmed")
    assert hit["confidence"] == "confirmed"
    assert hit["evidence"]["reached_loopback"] is True
    assert hit["evidence"]["error_signature"] in ("getaddrinfo", "ENOTFOUND")


def test_ssrf_not_reported_when_the_server_validates_the_url():
    spec = _search_spec([{"name": "url", "in": "query",
                          "schema": {"type": "string", "example": "https://cdn.example.test/a.png"}}])

    def handler(request):
        target = request.url.params.get("url", "")
        if target and not target.startswith("https://cdn.example.test"):
            return _json({"detail": "url not allowed"}, 400)
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    assert "input.ssrf-confirmed" not in _ids(result)


# ── CRLF ────────────────────────────────────────────────────────────────────

def test_crlf_injection_requires_the_header_to_appear_only_with_newlines():
    spec = _search_spec()

    def handler(request):
        value = request.url.params.get("q", "")
        headers = {}
        if "\r\n" in value:
            name, _, injected = value.partition("\r\n")
            key, _, item = injected.partition(": ")
            headers[key] = item
        return _json({"hits": 1}, headers=headers)

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.crlf-injection")
    assert hit["evidence"]["probe_header_value"] == "injected"
    assert hit["evidence"]["control_had_header"] is False


def test_crlf_not_reported_when_newlines_are_stripped():
    def handler(request):
        return _json({"hits": 1, "echo": request.url.params.get("q", "").replace("\r\n", "")})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    assert "input.crlf-injection" not in _ids(result)


# ── forwarding header reflection ────────────────────────────────────────────

def test_forwarded_host_reflected_into_location():
    def handler(request):
        host = request.headers.get("x-forwarded-host")
        if host:
            return httpx.Response(302, headers={"location": f"https://{host}/next"})
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.header-reflection")
    assert hit["evidence"]["reflected_in_location"] is True


def test_forwarded_host_ignored_is_clean():
    with _client(lambda r: _json({"hits": 1})) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    assert "input.header-reflection" not in _ids(result)


# ── parameter pollution ─────────────────────────────────────────────────────

def test_duplicate_parameter_last_value_wins_is_reported():
    def handler(request):
        values = request.url.params.get_list("q")
        return _json({"hits": len(values), "used": values[-1] if values else None})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    assert "input.parameter-pollution" in _ids(result)


# ── posture ─────────────────────────────────────────────────────────────────

def test_trace_enabled_requires_the_probe_header_echoed():
    def handler(request):
        if request.method == "TRACE":
            echoed = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
            return httpx.Response(200, text=f"TRACE /\n{echoed}")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "http.trace-enabled")
    assert hit["scope"] == "host"
    assert "X-Namazu-Probe" in hit["evidence"]["echoed_header"]


def test_trace_rejected_is_clean():
    def handler(request):
        if request.method == "TRACE":
            return httpx.Response(405, text="method not allowed")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    assert "http.trace-enabled" not in _ids(result)


def test_pagination_cap_not_enforced_is_confirmed_by_response_size():
    spec = _search_spec([{"name": "limit", "in": "query",
                          "schema": {"type": "integer", "example": 10}}])

    def handler(request):
        limit = int(request.url.params.get("limit", "10"))
        return _json({"hits": limit, "rows": ["x" * 40] * min(limit, 3000)})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "limits.pagination-not-enforced")
    assert hit["evidence"]["requested"] == 100000
    assert hit["evidence"]["probe_bytes"] > hit["evidence"]["baseline_bytes"]


def test_pagination_cap_enforced_is_clean():
    spec = _search_spec([{"name": "limit", "in": "query",
                          "schema": {"type": "integer", "example": 10}}])

    def handler(request):
        limit = min(int(request.url.params.get("limit", "10")), 100)
        return _json({"hits": limit, "rows": ["x" * 40] * limit})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    assert "limits.pagination-not-enforced" not in _ids(result)


def test_rate_limit_probe_only_runs_in_the_thorough_profile():
    counts = {"n": 0}

    def handler(request):
        counts["n"] += 1
        return _json({"hits": 1})

    with _client(handler) as client:
        audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    without = counts["n"]
    counts["n"] = 0
    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE,
                                 profile="thorough", client=client)
    assert counts["n"] > without
    hit = next(f for f in result["findings"] if f["id"] == "limits.no-rate-limit")
    assert hit["confidence"] == "possible"
    assert "cannot prove the absence" in hit["evidence"]["caveat"]


def test_rate_limit_headers_suppress_the_finding():
    def handler(request):
        return _json({"hits": 1}, headers={"ratelimit-limit": "100", "ratelimit-remaining": "99"})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE,
                                 profile="thorough", client=client)
    assert "limits.no-rate-limit" not in _ids(result)


def test_downgrade_redirect_reported():
    with _client(lambda r: httpx.Response(302, headers={"location": "http://api.example.test/next"})) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "transport.downgrade-redirect")
    assert hit["severity"] == "high"


# ── finding provenance ──────────────────────────────────────────────────────

def test_every_finding_carries_method_cwe_and_references():
    def handler(request):
        return _json({"hits": 1, "password": "x"}, headers={"server": "nginx/1.25.3"})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    assert result["findings"]
    for item in result["findings"]:
        assert item["method"], f"{item['id']} has no method sentence"
        assert item["cwe"], f"{item['id']} has no CWE"
        assert item["references"], f"{item['id']} has no references"
        for reference in item["references"]:
            assert reference["url"].startswith("https://")


def test_catalogue_covers_every_emitted_check():
    """A finding id with no catalogue entry would ship with no CWE or reading."""
    import re
    from pathlib import Path
    from namazu.audit.catalogue import CATALOGUE

    emitted = set()
    for path in Path("namazu/audit").glob("*.py"):
        for match in re.finditer(r'finding\(\s*\n?\s*"([a-z0-9._-]+)"', path.read_text(encoding="utf-8")):
            emitted.add(match.group(1))
    for path in [Path("namazu/oauth.py")]:
        for match in re.finditer(r'finding\(\s*\n?\s*"([a-z0-9._-]+)"', path.read_text(encoding="utf-8")):
            emitted.add(match.group(1))
    missing = sorted(emitted - set(CATALOGUE))
    assert not missing, f"checks with no catalogue entry: {missing}"


# ── OAuth 2 ─────────────────────────────────────────────────────────────────

def test_pkce_pair_is_valid_s256():
    import base64
    import hashlib
    verifier, challenge = oauth.pkce_pair()
    assert 43 <= len(verifier) <= 128
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert challenge == expected


def test_authorization_url_carries_pkce_and_state():
    from urllib.parse import parse_qs, urlsplit
    started = oauth.start_authorization(
        authorization_endpoint="https://id.example.test/authorize",
        token_endpoint="https://id.example.test/token",
        client_id="namazu-client", redirect_uri="http://localhost:8010/oauth/callback",
        scope="openid orders:read",
    )
    query = parse_qs(urlsplit(started["authorize_url"]).query)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [started["state"]]
    assert query["scope"] == ["openid orders:read"]
    assert query["redirect_uri"] == ["http://localhost:8010/oauth/callback"]
    oauth.collect(started["session"])


def test_callback_rejects_an_unknown_state():
    with pytest.raises(ValueError, match="does not match a pending request"):
        oauth.complete_authorization(state="not-a-real-state", code="abc")


def test_authorization_code_exchange_sends_the_verifier(monkeypatch):
    captured = {}

    def fake_request_token(token_url, form, **kwargs):
        captured.update({"url": token_url, "form": form, **kwargs})
        return oauth.summarize_token({"access_token": "at-123", "token_type": "Bearer",
                                      "expires_in": 3600, "scope": "orders:read"})

    monkeypatch.setattr(oauth, "request_token", fake_request_token)
    started = oauth.start_authorization(
        authorization_endpoint="https://id.example.test/authorize",
        token_endpoint="https://id.example.test/token",
        client_id="namazu-client", redirect_uri="http://localhost:8010/oauth/callback",
    )
    result = oauth.complete_authorization(state=started["state"], code="auth-code-1")
    assert result["status"] == "complete"
    assert captured["form"]["grant_type"] == "authorization_code"
    assert captured["form"]["code"] == "auth-code-1"
    assert len(captured["form"]["code_verifier"]) >= 43

    collected = oauth.collect(started["session"])
    assert collected["status"] == "complete"
    assert collected["token"]["header_value"] == "Bearer at-123"
    # The token is handed over exactly once.
    assert oauth.collect(started["session"])["status"] == "unknown"


def test_client_credentials_grant_posts_the_expected_form():
    seen = {}

    def handler(request):
        seen["body"] = request.content.decode()
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"access_token": "cc-1", "token_type": "Bearer",
                                         "expires_in": 600, "scope": "orders:read"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        token = oauth.client_credentials(token_url="https://id.example.test/token",
                                         client_id="svc", client_secret="s3cr3t",
                                         scope="orders:read", client=client)
    assert "grant_type=client_credentials" in seen["body"]
    assert "client_secret=s3cr3t" in seen["body"]
    assert token["header_value"] == "Bearer cc-1"
    assert token["expires_in"] == 600


def test_basic_client_auth_uses_the_authorization_header():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"access_token": "cc-2", "token_type": "Bearer"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        oauth.client_credentials(token_url="https://id.example.test/token", client_id="svc",
                                 client_secret="s3cr3t", auth_style="basic", client=client)
    assert seen["auth"].startswith("Basic ")
    assert "client_secret" not in seen["body"]


def test_token_error_is_surfaced_with_the_server_description():
    def handler(request):
        return httpx.Response(401, json={"error": "invalid_client",
                                         "error_description": "client authentication failed"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="client authentication failed"):
            oauth.client_credentials(token_url="https://id.example.test/token",
                                     client_id="svc", client_secret="bad", client=client)


def test_token_summary_decodes_a_jwt_access_token():
    from namazu.audit import jwtlab
    access = jwtlab.forge_hmac({"sub": "alice", "role": "admin", "exp": 9999999999}, "x" * 40)
    summary = oauth.summarize_token({"access_token": access, "token_type": "Bearer"})
    assert summary["jwt"]["subject"] == "alice"
    assert summary["jwt"]["privilege_claims"] == {"role": "admin"}


def test_discovery_reads_the_metadata_document():
    def handler(request):
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": "https://id.example.test",
                "authorization_endpoint": "https://id.example.test/authorize",
                "token_endpoint": "https://id.example.test/token",
                "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code", "client_credentials"],
            })
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        meta = oauth.discover("https://id.example.test", client=client)
    assert meta["token_endpoint"] == "https://id.example.test/token"
    assert meta["code_challenge_methods_supported"] == ["S256"]


def test_oauth_config_is_read_from_the_contract():
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {},
        "components": {"securitySchemes": {"oauth": {"type": "oauth2", "flows": {
            "authorizationCode": {"authorizationUrl": "https://id.example.test/authorize",
                                  "tokenUrl": "https://id.example.test/token",
                                  "scopes": {"orders:read": "Read orders"}}}}}},
    }, BASE)
    configs = oauth.from_spec(spec)
    assert configs[0]["grant"] == "authorization_code"
    assert configs[0]["token_endpoint"] == "https://id.example.test/token"
    assert configs[0]["scopes"] == ["orders:read"]


# ── authorization server probes ─────────────────────────────────────────────

def test_unregistered_redirect_uri_accepted_is_critical():
    def handler(request):
        target = request.url.params.get("redirect_uri", "")
        return httpx.Response(302, headers={"location": f"{target}?code=abc"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        findings = oauth.probe_authorization_server(
            authorization_endpoint="https://id.example.test/authorize", client_id="namazu",
            redirect_uri="http://localhost:8010/oauth/callback", client=client)
    hit = next(f for f in findings if f.id == "oauth.redirect-not-validated")
    assert hit.severity == "critical" and hit.confidence == "confirmed"
    assert "namazu-probe.invalid" in hit.evidence["location"]


def test_validated_redirect_uri_is_clean():
    def handler(request):
        target = request.url.params.get("redirect_uri", "")
        if "localhost:8010" not in target:
            return httpx.Response(400, json={"error": "invalid_request",
                                             "error_description": "redirect_uri mismatch"})
        if request.url.params.get("response_type") == "token":
            return httpx.Response(302, headers={"location": f"{target}#error=unsupported_response_type"})
        if "code_challenge" not in str(request.url):
            return httpx.Response(302, headers={"location": f"{target}?error=invalid_request"})
        return httpx.Response(302, headers={"location": f"{target}?code=abc"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        findings = oauth.probe_authorization_server(
            authorization_endpoint="https://id.example.test/authorize", client_id="namazu",
            redirect_uri="http://localhost:8010/oauth/callback",
            metadata={"code_challenge_methods_supported": ["S256"]}, client=client)
    assert findings == []


def test_pkce_optional_is_reported_when_metadata_advertises_support():
    def handler(request):
        target = request.url.params.get("redirect_uri", "")
        if "localhost:8010" not in target:
            return httpx.Response(400, json={"error": "invalid_request"})
        if request.url.params.get("response_type") == "token":
            return httpx.Response(302, headers={"location": f"{target}#error=unsupported_response_type"})
        return httpx.Response(302, headers={"location": f"{target}?code=abc"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        findings = oauth.probe_authorization_server(
            authorization_endpoint="https://id.example.test/authorize", client_id="namazu",
            redirect_uri="http://localhost:8010/oauth/callback",
            metadata={"code_challenge_methods_supported": ["S256"]}, client=client)
    hit = next(f for f in findings if f.id == "oauth.pkce-not-enforced")
    assert "S256" in hit.evidence["code_challenge_methods_supported"]


# ── OAuth contract findings ─────────────────────────────────────────────────

def test_implicit_and_password_flows_are_separate_detailed_findings():
    from namazu.audit import specscan
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {},
        "components": {"securitySchemes": {"legacy": {"type": "oauth2", "flows": {
            "implicit": {"authorizationUrl": "https://id.example.test/authorize",
                         "scopes": {"read": "Read"}},
            "password": {"tokenUrl": "https://id.example.test/token", "scopes": {}}}}}},
    }, BASE)
    findings = {f.id: f for f in specscan.review_document(spec)}
    implicit = findings["spec.oauth-implicit-flow"]
    assert implicit.cwe.startswith("CWE-598")
    assert implicit.evidence["json_pointer"].endswith("/flows/implicit")
    assert implicit.evidence["authorization_url"] == "https://id.example.test/authorize"
    assert "code_challenge" in implicit.remediation
    assert "RFC 9700" in " ".join(r["title"] for r in implicit.references)

    password = findings["spec.oauth-password-flow"]
    assert password.cwe.startswith("CWE-522")
    assert "MUST NOT" in password.evidence["forbidden_by"]
    assert "device authorization grant" in password.remediation


def test_modern_oauth_scheme_produces_no_flow_findings():
    from namazu.audit import specscan
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {},
        "components": {"securitySchemes": {"modern": {"type": "oauth2", "flows": {
            "authorizationCode": {"authorizationUrl": "https://id.example.test/authorize",
                                  "tokenUrl": "https://id.example.test/token",
                                  "scopes": {"orders:read": "Read orders"}}}}}},
    }, BASE)
    ids = [f.id for f in specscan.review_document(spec)]
    assert not [i for i in ids if i.startswith("spec.oauth-")]


# ── highlights and reproduction commands ────────────────────────────────────

def test_commands_are_generated_for_all_three_shells():
    exchange = Exchange(label="x", method="POST", url="https://a.test/x?q=a b",
                        request_headers={"Authorization": "Bearer t",
                                         "Content-Type": "application/json"},
                        request_body='{"role":"admin"}')
    commands = exchange.commands()
    assert set(commands) == {"bash", "powershell", "cmd"}
    # PowerShell aliases curl to Invoke-WebRequest, so the exe must be named.
    assert commands["powershell"].startswith("curl.exe ")
    assert commands["cmd"].startswith("curl.exe ")
    assert commands["bash"].startswith("curl ")
    # Redirects are read, not followed, in every variant.
    for text in commands.values():
        assert "--max-redirs 0" in text
        assert "<credential>" in text and "Bearer t" not in text
    # Quoting style differs per shell.
    assert "'{\"role\":\"admin\"}'" in commands["bash"]
    assert '"{\\"role\\":\\"admin\\"}"' in commands["cmd"]


def test_powershell_quoting_doubles_single_quotes():
    exchange = Exchange(label="x", method="GET", url="https://a.test/x",
                        request_headers={"X-Note": "it's here"})
    assert "'X-Note: it''s here'" in exchange.powershell()


def test_highlights_are_derived_from_evidence_keys():
    from namazu.audit.model import finding
    item = finding("jwt.weak-secret", "t", "critical", "confirmed",
                   evidence={"cracked_secret": "hunter2", "algorithm": "HS256",
                             "body_similarity": 0.99})
    marked = {entry["text"]: entry for entry in item.highlights}
    assert marked["hunter2"]["kind"] == "weak"
    assert marked["hunter2"]["note"]
    assert "0.99" in marked


def test_conditional_highlight_only_fires_when_damning():
    from namazu.audit.model import finding
    weak = finding("authz.bola-confirmed", "t", "critical", "confirmed",
                   evidence={"body_similarity": 0.99})
    strong = finding("authz.bola-confirmed", "t", "critical", "confirmed",
                     evidence={"body_similarity": 0.12})
    assert any(h["text"] == "0.99" for h in weak.highlights)
    assert not any(h["text"] == "0.12" for h in strong.highlights)


def test_short_highlights_are_dropped():
    from namazu.audit.model import finding
    item = finding("input.sql-error", "t", "high", "probable",
                   evidence={"payload": "'", "control": "''"})
    assert all(len(h["text"]) >= 3 for h in item.highlights)


def test_explicit_highlights_survive_and_lead():
    from namazu.audit import specscan
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {},
        "components": {"securitySchemes": {"legacy": {"type": "oauth2", "flows": {
            "implicit": {"authorizationUrl": "https://id.example.test/authorize",
                         "scopes": {"read": "Read"}}}}}},
    }, BASE)
    item = next(f for f in specscan.review_document(spec) if f.id == "spec.oauth-implicit-flow")
    texts = [h["text"] for h in item.highlights]
    assert "implicit" in texts and "ACCESS TOKEN" in texts
    assert texts[0] == "implicit"  # explicit highlights come first
    for entry in item.highlights:
        assert entry["note"], f"highlight {entry['text']!r} has no hover text"
        assert entry["kind"] in ("weak", "leak", "attacker", "proof")
    # Every highlighted phrase must occur in text the UI actually renders:
    # the observation, the impact, or an evidence value.
    haystack = " ".join([item.detail, item.background, item.impact, item.limitations,
                         json.dumps(item.evidence, ensure_ascii=False)])
    for entry in item.highlights:
        assert entry["text"] in haystack, f"{entry['text']!r} appears nowhere"


def test_contract_findings_get_verification_commands():
    from namazu.audit import audit_inventory
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {},
        "components": {"securitySchemes": {"legacy": {"type": "oauth2", "flows": {
            "implicit": {"authorizationUrl": "https://id.example.test/authorize", "scopes": {}}}}}},
    }, "https://api.example.test/openapi.json")

    with _client(lambda r: _json({"detail": "not found"}, 404)) as client:
        result = audit_inventory(spec, base_url=BASE, client=client)
    item = next(f for f in result["findings"] if f["id"] == "spec.oauth-implicit-flow")
    assert item["commands"]["bash"].startswith("curl -s https://api.example.test/openapi.json | jq ")
    assert ".components.securitySchemes.legacy.flows.implicit" in item["commands"]["bash"]
    assert "Invoke-RestMethod" in item["commands"]["powershell"]
    assert item["proof"] == []  # nothing was sent for it


def test_findings_with_requests_do_not_get_pointer_commands():
    """A replayable finding already has its command on each proof step."""
    def handler(request):
        return _json({"hits": 1, "password": "x"})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    replayable = [f for f in result["findings"] if f["proof"]]
    assert replayable
    for item in replayable:
        assert item["commands"] is None
        assert item["proof"][0]["commands"]["bash"].startswith("curl ")


def test_every_explicit_highlight_matches_text_the_ui_renders():
    """A marker that matches nothing would silently render as plain text.

    The UI marks the observation, the impact, evidence values and response
    excerpts, so a highlight has to occur in one of those.
    """
    import httpx as _httpx
    from namazu.audit import audit_inventory

    def handler(request):
        if request.url.path == "/orders/1":
            return _json({"id": 1, "owner": "alice", "password": "hunter2"})
        return _json({"detail": "not found"}, 404)

    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/orders/{orderId}": {"get": {
            "security": [{"bearer": []}],
            "parameters": [{"name": "orderId", "in": "path", "required": True,
                            "schema": {"type": "integer", "example": 1}}],
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}}}}},
        "components": {"securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
            "legacy": {"type": "oauth2", "flows": {
                "implicit": {"authorizationUrl": "https://id.example.test/a", "scopes": {}},
                "password": {"tokenUrl": "https://id.example.test/t", "scopes": {}}}}}},
    }, BASE)

    collected = []
    with _client(handler) as client:
        collected += audit_operation(spec, "GET /orders/{orderId}", base_url=BASE,
                                     identities={"primary": ALICE, "secondary": {"Authorization": "Bearer bob"}},
                                     client=client)["findings"]
    with _client(handler) as client:
        collected += audit_inventory(spec, base_url=BASE, client=client)["findings"]

    assert collected
    unmatched = []
    for item in collected:
        rendered = " ".join([
            item["detail"], item.get("background", ""), item["impact"],
            item.get("limitations", ""),
            json.dumps(item["evidence"], ensure_ascii=False),
            " ".join(step.get("body_excerpt", "") for step in item["proof"]),
            " ".join(step.get("commands", {}).get("bash", "") for step in item["proof"]),
            json.dumps(item.get("commands") or {}, ensure_ascii=False),
        ])
        for entry in item["highlights"]:
            assert entry["kind"] in ("weak", "leak", "attacker", "proof")
            assert entry["note"], f"{item['id']}: highlight {entry['text']!r} has no hover note"
            if entry["text"] not in rendered:
                unmatched.append(f"{item['id']}: {entry['text']!r}")
    assert not unmatched, "highlights that match no rendered text: " + "; ".join(unmatched)


# ── request log ─────────────────────────────────────────────────────────────

def test_audit_returns_every_request_it_made():
    sent = []

    def handler(request):
        sent.append(f"{request.method} {request.url.path}")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    log = result["log"]
    assert len(log) == len(sent) == result["requests_sent"]
    assert [entry["seq"] for entry in log] == list(range(1, len(log) + 1))
    assert log[0]["label"] == "baseline"
    # The anonymous replay deliberately carries no credentials, so assert the
    # stronger property instead: the real token appears nowhere in the log.
    rendered = json.dumps(log)
    assert "alice-token" not in rendered
    for entry in log:
        assert entry["endpoint"] == "GET /search"
        assert entry["commands"]["bash"].startswith("curl ")
        if any(name.lower() == "authorization" for name in entry["request_headers"]):
            assert "<credential>" in json.dumps(entry["request_headers"])


def test_log_includes_probes_that_found_nothing():
    """The point of a log is the requests that produced no finding."""
    with _client(lambda r: _json({"hits": 1})) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    labels = {entry["label"] for entry in result["log"]}
    assert len(result["log"]) > len(result["findings"])
    assert any("quote" in label or "control" in label for label in labels)


def test_inventory_sweep_also_logs():
    with _client(lambda r: _json({"detail": "nope"}, 404)) as client:
        result = audit_inventory(_spec_for_log(), base_url=BASE, client=client)
    assert result["log"]
    assert result["log"][0]["label"] == "404 calibration"


def _spec_for_log():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {}}, BASE)


def test_log_is_capped_and_says_so():
    from namazu.audit import engine
    original = engine.MAX_LOG_ENTRIES
    engine.MAX_LOG_ENTRIES = 3
    try:
        with _client(lambda r: _json({"hits": 1})) as client:
            result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
        assert len(result["log"]) == 3
        assert any("request log keeps the first 3" in note for note in result["notes"])
    finally:
        engine.MAX_LOG_ENTRIES = original


# ── advisory structure ──────────────────────────────────────────────────────

def test_implicit_flow_no_longer_claims_referer_or_log_exposure():
    """A URL fragment is not sent to the server, so that claim must be qualified."""
    from namazu.audit import specscan
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}], "paths": {},
        "components": {"securitySchemes": {"legacy": {"type": "oauth2", "flows": {
            "implicit": {"authorizationUrl": "https://id.example.test/a", "scopes": {}}}}}},
    }, BASE)
    item = next(f for f in specscan.review_document(spec) if f.id == "spec.oauth-implicit-flow")

    assert "is not sent to the server" in item.impact
    # The exposure routes that do not follow from a fragment must be qualified.
    for phrase in ("Referer header", "proxy logs", "server access logs"):
        assert phrase in item.impact
        assert item.impact.index("Those routes apply only if") > item.impact.index(phrase)
    assert "has not\n                determined" in item.impact or "has not determined" in item.impact

    # The limitation must be explicit about what was and was not tested.
    assert "statically" in item.limitations
    assert "does not establish that the implicit grant is enabled" in item.limitations
    assert item.evidence["authorization_server_tested"] is False

    # Issue background explains the class; issue detail stays about this target.
    assert "PKCE" in item.background and "fragment" in item.background
    assert "This is what the document advertises" in item.detail


def test_advisory_sections_are_populated_for_known_classes():
    from namazu.audit.model import finding
    for check in ("spec.oauth-implicit-flow", "authz.bola-confirmed", "input.sql-boolean",
                  "input.ssrf-confirmed", "jwt.signature-not-verified"):
        item = finding(check, "t", "high", "confirmed")
        assert item.background, f"{check} has no issue background"


def test_static_findings_carry_a_limitation_by_default():
    from namazu.audit.model import finding
    static = finding("spec.unbounded-pagination", "t", "low", "confirmed")
    assert "sent no request" in static.limitations
    surface = finding("spec.ssrf-surface", "t", "low", "possible")
    assert "attack surface rather than a demonstrated weakness" in surface.limitations


def test_no_em_dashes_anywhere_in_the_application():
    """Em dashes are not used in this project; punctuation carries the pause instead."""
    from pathlib import Path
    DASH = chr(8212)  # written by code point so this file passes its own check
    offenders = []
    for pattern in ("namazu/*.py", "namazu/audit/*.py", "namazu/static/*", "tests/*.py", "*.md", ".github/**/*.md"):
        for path in Path(".").glob(pattern):
            if path.suffix in (".pyc",) or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            if DASH in text:
                index = text.index(DASH)
                offenders.append(f"{path}: ...{text[max(0, index - 40):index + 40]}...")
    assert not offenders, "em dashes found:\n" + "\n".join(offenders)


# ── access control bypass battery ───────────────────────────────────────────

def _gated_spec():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "Admin", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/admin/reports": {"get": {
            "security": [{"bearer": []}],
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"rows": {"type": "integer"}}}}}}}}}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }, BASE)


def test_path_bypass_is_found_when_a_rewrite_slips_past_the_filter():
    def handler(request):
        path = request.url.path
        if path == "/admin/reports":          # the filter only knows this exact string
            return _json({"detail": "forbidden"}, 403)
        if path.rstrip("/").endswith("reports") or "//" in path or "/./" in path:
            return _json({"rows": 12, "secret": "internal"})
        return _json({"detail": "not found"}, 404)

    with _client(handler) as client:
        result = audit_operation(_gated_spec(), "GET /admin/reports", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "authz.path-bypass")
    assert hit["severity"] == "high" and hit["confidence"] == "confirmed"
    assert hit["evidence"]["baseline_status"] == 403
    assert hit["evidence"]["bypass_status"] == 200
    assert len(hit["proof"]) == 2


def test_header_bypass_is_found_when_a_forwarding_header_is_trusted():
    def handler(request):
        if request.headers.get("x-original-url") or request.headers.get("x-forwarded-for") == "127.0.0.1":
            return _json({"rows": 12})
        return _json({"detail": "forbidden"}, 403)

    with _client(handler) as client:
        result = audit_operation(_gated_spec(), "GET /admin/reports", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "authz.header-bypass")
    assert hit["evidence"]["header"] in ("X-Original-URL", "X-Forwarded-For")


def test_consistently_refused_route_produces_no_bypass_finding():
    with _client(lambda r: _json({"detail": "forbidden"}, 403)) as client:
        result = audit_operation(_gated_spec(), "GET /admin/reports", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    ids = _ids(result)
    assert "authz.path-bypass" not in ids and "authz.header-bypass" not in ids


def test_bypass_battery_only_runs_on_refused_routes():
    """A route that already answers must not spend budget on bypass variants."""
    sent = []

    def handler(request):
        sent.append(request.url.path)
        return _json({"rows": 1})

    with _client(handler) as client:
        audit_operation(_gated_spec(), "GET /admin/reports", base_url=BASE,
                        identities={"primary": ALICE}, client=client)
    assert not any("bypass" in path for path in sent)
    assert not any(";namazu=1" in path or "//" in path.lstrip("/") for path in sent)


# ── template injection across engines ───────────────────────────────────────

def test_dollar_brace_template_engine_is_detected():
    def handler(request):
        value = request.url.params.get("q", "")
        return _json({"echo": value.replace("${7*31}", "217").replace("${9*41}", "369")})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.template-injection")
    assert "Freemarker" in hit["evidence"]["engine_family"]


def test_erb_template_engine_is_detected():
    def handler(request):
        value = request.url.params.get("q", "")
        return _json({"echo": value.replace("<%= 7*31 %>", "217").replace("<%= 9*41 %>", "369")})

    with _client(handler) as client:
        result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.template-injection")
    assert "ERB" in hit["evidence"]["engine_family"]


# ── header parameters ───────────────────────────────────────────────────────

def test_documented_header_parameter_is_probed():
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "S", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/search": {"get": {
            "parameters": [{"name": "X-Tenant", "in": "header",
                            "schema": {"type": "string", "example": "acme"}}],
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object"}}}}}}}},
    }, BASE)

    def handler(request):
        if "'" in (request.headers.get("x-tenant") or ""):
            return httpx.Response(500, text="SQLSTATE[42000]: You have an error in your SQL syntax")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"]
               if f["id"] == "input.sql-error" and f["parameter"] == "X-Tenant")
    assert hit["evidence"]["header"] == "X-Tenant"


# ── source file exposure ────────────────────────────────────────────────────

def test_exposed_git_metadata_is_reported():
    def handler(request):
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        return _json({"detail": "not found"}, 404)

    with _client(handler) as client:
        result = audit_inventory(_spec_for_log(), base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "inventory.source-exposed")
    assert hit["severity"] == "high"
    assert hit["evidence"]["path"] == "/.git/HEAD"


def test_source_path_needs_the_right_content_not_just_a_200():
    """An SPA that serves index.html for everything must not look like exposed source."""
    def handler(request):
        return httpx.Response(200, text="<!doctype html><title>app</title>")

    with _client(handler) as client:
        result = audit_inventory(_spec_for_log(), base_url=BASE, client=client)
    assert "inventory.source-exposed" not in _ids(result)


def test_budget_exhaustion_is_reported_even_when_probes_skip_quietly():
    """Probes check affordability and return; that must still show in the report."""
    from namazu.audit import engine
    original = engine.PROFILES["readonly"]["requests_per_operation"]
    engine.PROFILES["readonly"]["requests_per_operation"] = 6
    try:
        with _client(lambda r: _json({"hits": 1})) as client:
            result = audit_operation(_search_spec(), "GET /search", base_url=BASE, client=client)
        assert result["requests_sent"] <= 6
        assert any("budget of 6 was reached" in note for note in result["notes"]), result["notes"]
    finally:
        engine.PROFILES["readonly"]["requests_per_operation"] = original


def test_no_budget_note_when_everything_ran():
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok",
            "content": {"application/json": {"schema": {"type": "object"}}}}}}}},
    }, BASE)
    with _client(lambda r: _json({"ok": True})) as client:
        result = audit_operation(spec, "GET /ping", base_url=BASE, client=client)
    assert not any("budget" in note for note in result["notes"]), result["notes"]


# ── optional second-opinion tools ───────────────────────────────────────────

def test_tool_detection_reports_both_tools():
    from namazu.audit import external
    tools = external.available()
    assert set(tools) == {"schemathesis", "nuclei"}
    for name, info in tools.items():
        assert isinstance(info["available"], bool)
        assert info["install"], f"{name} must say how to install it"
        assert info["role"], f"{name} must say what it adds"


def test_missing_tool_is_reported_not_swallowed(monkeypatch):
    """An absent tool is a stated gap, never a silent one."""
    from namazu.audit import external
    monkeypatch.setattr(external, "_schemathesis_bin", lambda: None)
    monkeypatch.setattr(external.shutil, "which", lambda name: None)

    for result in (external.run_schemathesis(schema="x", base_url=BASE),
                   external.run_nuclei(target=BASE)):
        assert result["ran"] is False
        assert result["findings"] == []
        assert result["notes"] and "not installed" in result["notes"][0]
        assert "install it with" in result["notes"][0].lower()


def test_schemathesis_failures_become_findings():
    from namazu.audit.external import _schemathesis_findings
    report = {
        "seed": 42,
        "failures": [
            {"type": "IgnoredAuth", "title": "API accepts invalid authentication",
             "severity": "critical", "count": 2, "operations": ["GET /orders/{id}"]},
            {"type": "ServerError", "title": "Server error", "severity": "critical",
             "count": 1, "operations": ["GET /search", "GET /items"]},
        ],
    }
    findings = _schemathesis_findings(report)
    assert len(findings) == 3  # one per operation
    auth = next(f for f in findings if f.id == "schemathesis.ignored-auth")
    assert auth.severity == "high"            # schemathesis critical maps down
    assert auth.confidence == "probable"      # Namazu did not verify it
    assert "did not re-verify" in auth.limitations or "not re-verified" in auth.limitations
    assert auth.evidence["seed"] == 42
    assert "--seed 42" in auth.evidence["reproduce"]
    assert auth.endpoint == "GET /orders/{id}"


def test_nuclei_matches_become_findings_and_repeat_matchers_merge():
    from namazu.audit.external import _nuclei_findings
    records = [
        {"template-id": "missing-headers", "matched-at": "https://a.test/",
         "matcher-name": "x-frame-options",
         "info": {"name": "Missing headers", "severity": "info"}},
        {"template-id": "missing-headers", "matched-at": "https://a.test/",
         "matcher-name": "content-security-policy",
         "info": {"name": "Missing headers", "severity": "info"}},
        {"template-id": "cve-2021-1234", "matched-at": "https://a.test/admin",
         "info": {"name": "Some CVE", "severity": "high",
                  "classification": {"cve-id": ["CVE-2021-1234"], "cwe-id": ["cwe-89"]},
                  "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1234"]}},
    ]
    findings = _nuclei_findings(records)
    assert len(findings) == 2  # the two matchers merge into one finding
    merged = next(f for f in findings if f.id == "nuclei.missing-headers")
    assert merged.evidence["matchers"] == ["x-frame-options", "content-security-policy"]
    cve = next(f for f in findings if f.id == "nuclei.cve-2021-1234")
    assert cve.severity == "high"
    assert cve.confidence == "probable"
    assert cve.evidence["cve"] == "CVE-2021-1234"
    assert cve.cwe == "CWE-89"
    assert cve.references[0]["url"].startswith("https://nvd.nist.gov")
    assert "not confirmed by Namazu" in cve.limitations


def test_external_findings_are_attributed_to_their_tool():
    from namazu.audit.external import _nuclei_findings, _schemathesis_findings
    items = _nuclei_findings([{"template-id": "t", "matched-at": "https://a.test",
                               "info": {"name": "n", "severity": "low"}}])
    items += _schemathesis_findings({"failures": [{"type": "ServerError", "title": "Server error",
                                                   "severity": "high", "count": 1,
                                                   "operations": ["GET /a"]}]})
    for item in items:
        assert item.evidence["source"] in ("nuclei", "schemathesis")
        assert any(h["text"] in ("nuclei", "schemathesis") for h in item.highlights)
        assert item.confidence == "probable"


def test_nuclei_command_excludes_destructive_tags_and_callbacks():
    """The safety flags are part of the contract with the user, so pin them."""
    from namazu.audit import external
    captured = {}

    def fake_run(command, timeout):
        captured["command"] = command
        return 0, "", "", ""

    original = external._run
    external._run = fake_run
    try:
        external.run_nuclei(target="https://a.test")
    finally:
        external._run = original
    command = captured["command"]
    assert "-no-interactsh" in command            # no outbound callback service
    assert "-exclude-tags" in command
    excluded = command[command.index("-exclude-tags") + 1]
    for tag in ("dos", "fuzz", "intrusive"):
        assert tag in excluded


def test_schemathesis_excludes_write_methods_unless_allowed():
    from namazu.audit import external
    captured = {}

    def fake_run(command, timeout):
        captured["command"] = command
        return 0, "", "", ""

    original = external._run
    external._run = fake_run
    try:
        external.run_schemathesis(schema="s", base_url=BASE)
        read_only = captured["command"]
        external.run_schemathesis(schema="s", base_url=BASE, allow_mutating=True)
        with_writes = captured["command"]
    finally:
        external._run = original
    assert "--exclude-method-regex" in read_only
    assert "POST|PUT|PATCH|DELETE" in read_only[read_only.index("--exclude-method-regex") + 1]
    assert "--exclude-method-regex" not in with_writes
