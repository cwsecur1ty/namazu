"""Audit engine tests against a deliberately broken mock API.

Each test asserts both directions where it matters: the finding fires on the
vulnerable handler, and does not fire on the handler that behaves correctly.
"""
import json

import httpx
import pytest

from namazu.audit import audit_inventory, audit_operation, jwtlab
from namazu.audit.model import Exchange, body_signature, similarity
from namazu.audit.transport import Budget, Executor, MutationRefused

BASE = "https://api.example.test"

ALICE = {"Authorization": "Bearer alice-token"}
BOB = {"Authorization": "Bearer bob-token"}

ORDER_1 = {"id": 1, "owner": "alice", "total": 42, "note": "first order"}
ORDER_2 = {"id": 2, "owner": "bob", "total": 99, "note": "second order"}


def _spec(paths=None, schemes=None, servers=None):
    document = {
        "openapi": "3.0.3",
        "info": {"title": "Broken shop", "version": "1.0"},
        "servers": [{"url": server} for server in (servers or [BASE])],
        "paths": paths if paths is not None else {
            "/orders/{orderId}": {
                "get": {
                    "security": [{"bearer": []}],
                    "parameters": [{"name": "orderId", "in": "path", "required": True,
                                    "schema": {"type": "integer", "example": 1}}],
                    "responses": {"200": {"description": "Order", "content": {"application/json": {
                        "schema": {"type": "object", "properties": {
                            "id": {"type": "integer"}, "owner": {"type": "string"},
                            "total": {"type": "integer"}}}}}}},
                },
            },
        },
        "components": {"securitySchemes": schemes or {"bearer": {"type": "http", "scheme": "bearer"}}},
    }
    from namazu.spec import parse_spec
    return parse_spec(document, BASE)


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE)


def _json(payload, status=200, headers=None):
    return httpx.Response(status, json=payload, headers=headers or {})


# ── BOLA ────────────────────────────────────────────────────────────────────

def test_cross_identity_read_is_confirmed_bola():
    """Bob asks for Alice's order and gets it: ownership is never checked."""
    def handler(request):
        if request.headers.get("authorization") in ("Bearer alice-token", "Bearer bob-token"):
            return _json(ORDER_1)
        return _json({"detail": "unauthorized"}, 401)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE, "secondary": BOB}, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "authz.bola-confirmed" in ids
    hit = next(f for f in result["findings"] if f["id"] == "authz.bola-confirmed")
    assert hit["severity"] == "critical" and hit["confidence"] == "confirmed"
    # The proof carries both exchanges and a replayable command.
    assert len(hit["proof"]) == 2
    assert hit["proof"][1]["identity"] == "identity B"
    assert hit["proof"][1]["curl"].startswith("curl")
    assert "<credential>" in json.dumps(hit["proof"][1]["request_headers"])


def test_per_user_scoping_is_not_reported_as_bola():
    """Each identity gets its own object, so nothing should fire."""
    def handler(request):
        token = request.headers.get("authorization", "")
        if "alice" in token:
            return _json(ORDER_1)
        if "bob" in token:
            return _json(ORDER_2)
        return _json({"detail": "unauthorized"}, 401)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE, "secondary": BOB}, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "authz.bola-confirmed" not in ids
    assert "authz.missing-authentication" not in ids


def test_missing_authentication_is_confirmed_when_anonymous_matches():
    def handler(request):
        return _json(ORDER_1)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "authz.missing-authentication")
    assert hit["confidence"] == "confirmed"
    assert hit["evidence"]["body_similarity"] >= 0.95


def test_identifier_swap_requires_the_id_to_be_echoed():
    """A handler that ignores the id must not produce an IDOR finding."""
    def handler(request):
        return _json(ORDER_1)  # same object whatever the id

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    assert "authz.idor" not in [f["id"] for f in result["findings"]]


def test_identifier_swap_fires_when_a_different_object_returns():
    def handler(request):
        order_id = request.url.path.rsplit("/", 1)[-1]
        return _json(ORDER_1 if order_id == "1" else ORDER_2)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "authz.idor")
    assert hit["evidence"]["original"] == "1" and hit["evidence"]["swapped"] == "2"
    assert hit["confidence"] == "probable"


# ── JWT ─────────────────────────────────────────────────────────────────────

def test_weak_jwt_secret_is_recovered_offline():
    token = jwtlab.forge_hmac({"sub": "alice", "role": "user", "exp": 9999999999}, "secret")
    report = jwtlab.analyze(token)
    assert report["cracked_secret"] == "secret"
    assert any(w["id"] == "weak-secret" for w in report["weaknesses"])


def test_strong_jwt_secret_is_not_cracked():
    token = jwtlab.forge_hmac({"sub": "alice", "exp": 9999999999}, "3f9c1d" * 12)
    report = jwtlab.analyze(token)
    assert "cracked_secret" not in report
    assert not any(w["id"] == "weak-secret" for w in report["weaknesses"])


def test_alg_none_token_accepted_is_confirmed():
    token = jwtlab.forge_hmac({"sub": "alice", "exp": 9999999999}, "3f9c1d" * 12)

    def handler(request):
        auth = request.headers.get("authorization", "")
        if not auth:
            return _json({"detail": "unauthorized"}, 401)
        return _json(ORDER_1)  # accepts any token, signed or not

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": {"Authorization": f"Bearer {token}"}},
                                 client=client)
    hit = next(f for f in result["findings"] if f["id"] == "jwt.signature-not-verified")
    assert hit["severity"] == "critical" and hit["confidence"] == "confirmed"


def test_verifying_server_does_not_trigger_signature_finding():
    secret = "3f9c1d" * 12
    token = jwtlab.forge_hmac({"sub": "alice", "exp": 9999999999}, secret)

    def handler(request):
        auth = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if jwtlab.verify_hmac(auth, secret):
            return _json(ORDER_1)
        return _json({"detail": "bad signature"}, 401)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": {"Authorization": f"Bearer {token}"}},
                                 client=client)
    assert "jwt.signature-not-verified" not in [f["id"] for f in result["findings"]]


def test_jwt_without_expiry_is_reported():
    token = jwtlab.forge_hmac({"sub": "alice"}, "3f9c1d" * 12)
    report = jwtlab.analyze(token)
    assert any(w["id"] == "no-expiry" for w in report["weaknesses"])


# ── CORS, headers, cookies ──────────────────────────────────────────────────

def test_reflected_origin_with_credentials_is_high():
    def handler(request):
        origin = request.headers.get("origin")
        headers = {}
        if origin:
            headers = {"access-control-allow-origin": origin,
                       "access-control-allow-credentials": "true"}
        return _json(ORDER_1, headers=headers)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "cors.origin-reflected")
    assert hit["severity"] == "high"
    assert hit["evidence"]["allow_credentials"] is True


def test_fixed_allowlist_origin_is_not_reported():
    def handler(request):
        return _json(ORDER_1, headers={"access-control-allow-origin": "https://app.example.test"})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "cors.origin-reflected" not in ids and "cors.wildcard" not in ids


def test_weak_cookie_flags_are_reported():
    def handler(request):
        return _json(ORDER_1, headers={"set-cookie": "session=abc123; Path=/"})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "cookie.weak-flags")
    assert set(hit["evidence"]["missing"]) == {"HttpOnly", "Secure", "SameSite"}
    assert hit["severity"] == "medium"  # session-like name without HttpOnly


def test_hardened_cookie_is_not_reported():
    def handler(request):
        return _json(ORDER_1, headers={
            "set-cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    assert "cookie.weak-flags" not in [f["id"] for f in result["findings"]]


# ── response content ────────────────────────────────────────────────────────

def test_secret_bearing_response_field_is_reported():
    def handler(request):
        return _json({"id": 1, "owner": "alice", "password_hash": "$2b$12$abcdefghij"})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "exposure.sensitive-field" in ids
    # The same field is undocumented in the 2xx schema, so that fires as high too.
    undocumented = next(f for f in result["findings"] if f["id"] == "exposure.undocumented-field")
    assert "password_hash" in undocumented["evidence"]["secret_bearing"]


def test_documented_fields_only_produce_no_exposure_finding():
    def handler(request):
        return _json({"id": 1, "owner": "alice", "total": 42})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "exposure.undocumented-field" not in ids
    assert "exposure.sensitive-field" not in ids


def test_stack_trace_in_body_is_reported():
    def handler(request):
        return httpx.Response(500, text="Traceback (most recent call last):\n  File \"/app/main.py\", line 20")

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "disclosure.verbose-error")
    assert hit["evidence"]["signature"] == "Python traceback"


# ── input probes ────────────────────────────────────────────────────────────

def _query_spec():
    from namazu.spec import parse_spec
    return parse_spec({
        "openapi": "3.0.3",
        "info": {"title": "Search", "version": "1.0"},
        "servers": [{"url": BASE}],
        "paths": {"/search": {"get": {
            "parameters": [
                {"name": "q", "in": "query", "required": True, "schema": {"type": "string", "example": "shoes"}},
                {"name": "redirect", "in": "query", "schema": {"type": "string", "example": "/home"}},
            ],
            "responses": {"200": {"description": "Results", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"hits": {"type": "integer"}}}}}}},
        }}},
    }, BASE)


def test_sql_error_needs_the_balanced_control_to_stay_clean():
    def handler(request):
        value = request.url.params.get("q", "")
        if value == "'":
            return httpx.Response(500, text='SQLSTATE[42000]: You have an error in your SQL syntax')
        return _json({"hits": 3})

    with _client(handler) as client:
        result = audit_operation(_query_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.sql-error")
    assert hit["evidence"]["control"] == "''"
    assert hit["confidence"] == "probable"


def test_server_that_rejects_all_quotes_is_not_flagged():
    """A field that errors on any quote is strict input handling, not injection."""
    def handler(request):
        if "'" in request.url.params.get("q", ""):
            return httpx.Response(500, text="SQLSTATE[42000]: You have an error in your SQL syntax")
        return _json({"hits": 3})

    with _client(handler) as client:
        result = audit_operation(_query_spec(), "GET /search", base_url=BASE, client=client)
    assert "input.sql-error" not in [f["id"] for f in result["findings"]]


def test_template_injection_requires_two_independent_sums():
    def handler(request):
        value = request.url.params.get("q", "")
        rendered = value.replace("{{7*31}}", "217").replace("{{9*41}}", "369")
        return _json({"hits": 1, "echo": rendered})

    with _client(handler) as client:
        result = audit_operation(_query_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.template-injection")
    assert hit["severity"] == "critical" and hit["confidence"] == "confirmed"


def test_echoing_server_does_not_trigger_template_injection():
    """Plain reflection of the payload must not be read as evaluation."""
    def handler(request):
        return _json({"hits": 1, "echo": request.url.params.get("q", "")})

    with _client(handler) as client:
        result = audit_operation(_query_spec(), "GET /search", base_url=BASE, client=client)
    assert "input.template-injection" not in [f["id"] for f in result["findings"]]


def test_open_redirect_is_confirmed_from_the_location_header():
    def handler(request):
        target = request.url.params.get("redirect")
        if request.url.path == "/search" and target and target.startswith("http"):
            return httpx.Response(302, headers={"location": target})
        return _json({"hits": 3})

    with _client(handler) as client:
        result = audit_operation(_query_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "input.open-redirect")
    assert "namazu-probe.invalid" in hit["evidence"]["location"]
    assert hit["confidence"] == "confirmed"


def test_relative_only_redirect_is_not_flagged():
    def handler(request):
        return httpx.Response(302, headers={"location": "/home"})

    with _client(handler) as client:
        result = audit_operation(_query_spec(), "GET /search", base_url=BASE, client=client)
    assert "input.open-redirect" not in [f["id"] for f in result["findings"]]


# ── contract-only checks ────────────────────────────────────────────────────

def test_mass_assignment_surface_from_schema_only():
    from namazu.audit import specscan
    spec = _spec(paths={"/users": {"post": {
        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
            "email": {"type": "string"}, "role": {"type": "string"}, "is_admin": {"type": "boolean"}}}}}},
        "responses": {"201": {"description": "Created"}},
    }}})
    operation = next(op for op in spec["operations"] if op["id"] == "POST /users")
    findings = specscan.review_operation(spec, operation)
    ids = [f.id for f in findings]
    assert "spec.mass-assignment-surface" in ids
    assert "spec.unauthenticated-write" in ids
    surface = next(f for f in findings if f.id == "spec.mass-assignment-surface")
    assert set(surface.evidence["properties"]) >= {"role", "is_admin"}


def test_readonly_privileged_property_is_not_mass_assignment_surface():
    from namazu.audit import specscan
    spec = _spec(paths={"/users": {"post": {
        "security": [{"bearer": []}],
        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
            "email": {"type": "string"}, "role": {"type": "string", "readOnly": True}}}}}},
        "responses": {"201": {"description": "Created"}},
    }}})
    operation = next(op for op in spec["operations"] if op["id"] == "POST /users")
    ids = [f.id for f in specscan.review_operation(spec, operation)]
    assert "spec.mass-assignment-surface" not in ids
    assert "spec.unauthenticated-write" not in ids


def test_api_key_in_query_and_cleartext_server():
    from namazu.audit import specscan
    spec = _spec(schemes={"key": {"type": "apiKey", "in": "query", "name": "api_key"}},
                 servers=["http://api.example.test"])
    ids = [f.id for f in specscan.review_document(spec)]
    assert "spec.apikey-in-query" in ids
    assert "spec.cleartext-server" in ids


def test_unbounded_pagination_detected():
    from namazu.audit import specscan
    spec = _spec(paths={"/orders": {"get": {
        "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
        "responses": {"200": {"description": "ok"}}}}})
    operation = next(op for op in spec["operations"] if op["id"] == "GET /orders")
    assert "spec.unbounded-pagination" in [f.id for f in specscan.review_operation(spec, operation)]


def test_bounded_pagination_is_clean():
    from namazu.audit import specscan
    spec = _spec(paths={"/orders": {"get": {
        "parameters": [{"name": "limit", "in": "query",
                        "schema": {"type": "integer", "maximum": 100}}],
        "responses": {"200": {"description": "ok"}}}}})
    operation = next(op for op in spec["operations"] if op["id"] == "GET /orders")
    assert "spec.unbounded-pagination" not in [f.id for f in specscan.review_operation(spec, operation)]


# ── inventory ───────────────────────────────────────────────────────────────

def test_inventory_finds_docs_graphql_and_shadow_paths():
    def handler(request):
        path = request.url.path
        if path == "/openapi.json":
            return _json({"openapi": "3.0.0", "paths": {}})
        if path == "/graphql":
            return _json({"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}})
        if path == "/actuator/env":
            return _json({"propertySources": [{"name": "systemEnvironment"}]})
        return _json({"detail": "not found"}, 404)

    with _client(handler) as client:
        result = audit_inventory(_spec(), base_url=BASE, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "inventory.docs-exposed" in ids
    assert "inventory.graphql-introspection" in ids
    assert "inventory.undocumented-endpoint" in ids
    assert result["requests_sent"] <= result["request_budget"]


def test_catch_all_host_does_not_produce_shadow_findings():
    """A host that answers 200 for everything must not look like a dozen findings."""
    def handler(request):
        return _json({"detail": "welcome"})

    with _client(handler) as client:
        result = audit_inventory(_spec(), base_url=BASE, client=client)
    assert result["discovery"]["catch_all"] is True
    assert "inventory.undocumented-endpoint" not in [f["id"] for f in result["findings"]]


def test_zombie_operation_detected():
    def handler(request):
        return _json({"detail": "not found"}, 404)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE, client=client)
    assert "inventory.zombie-operation" in [f["id"] for f in result["findings"]]


def test_undocumented_write_methods_from_options():
    def handler(request):
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"allow": "GET, PUT, DELETE, OPTIONS"})
        return _json(ORDER_1)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"] == "inventory.undocumented-methods")
    assert set(hit["evidence"]["undocumented"]) == {"DELETE", "PUT"}


# ── safety and budget ───────────────────────────────────────────────────────

def test_write_profile_requires_consent():
    with pytest.raises(ValueError, match="allow_mutating"):
        audit_operation(_spec(), "GET /orders/{orderId}", profile="writes", allow_mutating=False)


def test_executor_refuses_mutating_requests_without_consent():
    with _client(lambda request: _json({})) as client:
        executor = Executor(client, Budget(5), allow_mutating=False)
        with pytest.raises(MutationRefused):
            executor.send("DELETE", f"{BASE}/orders/1", label="destructive")
        assert executor.budget.spent == 0


def test_passive_profile_sends_exactly_one_request():
    sent = []

    def handler(request):
        sent.append(request.url.path)
        return _json(ORDER_1)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 profile="passive", identities={"primary": ALICE}, client=client)
    assert len(sent) == 1
    assert result["requests_sent"] == 1


def test_budget_is_never_exceeded_and_is_reported():
    def handler(request):
        return _json(ORDER_1)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE, "secondary": BOB}, client=client)
    assert result["requests_sent"] <= result["request_budget"]


def test_write_probe_against_post_is_gated_and_marked():
    from namazu.spec import parse_spec
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "Users", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/users": {"post": {
            "security": [{"bearer": []}],
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": ["email"], "properties": {
                    "email": {"type": "string", "example": "a@example.test"},
                    "role": {"type": "string"}}}}}},
            "responses": {"201": {"description": "Created", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}},
        }}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }, BASE)

    def handler(request):
        if request.method == "POST":
            body = json.loads(request.content or b"{}")
            return _json({"id": 7, **body}, 201)
        return _json({"detail": "not found"}, 404)

    with _client(handler) as client:
        result = audit_operation(spec, "POST /users", base_url=BASE, profile="writes",
                                 allow_mutating=True, identities={"primary": ALICE}, client=client)
    hit = next(f for f in result["findings"] if f["id"].startswith("input.mass-assignment"))
    assert hit["mutating"] is True
    assert "role" in hit["evidence"]["properties"]


def test_write_operations_are_skipped_without_write_profile():
    from namazu.spec import parse_spec
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "Users", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/users": {"post": {
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "properties": {"email": {"type": "string"}}}}}},
            "responses": {"201": {"description": "Created"}}}}},
    }, BASE)
    sent = []

    with _client(lambda r: sent.append(r.method) or _json({}, 201)) as client:
        result = audit_operation(spec, "POST /users", base_url=BASE, client=client)
    assert sent == []  # the baseline itself is mutating, so nothing was sent
    assert any("read-only" in note or "state" in note for note in result["notes"])
    # Contract findings still arrive without any traffic.
    assert "spec.unauthenticated-write" in [f["id"] for f in result["findings"]]


# ── model helpers ───────────────────────────────────────────────────────────

def test_proof_redacts_credentials_in_headers_and_query():
    exchange = Exchange(
        label="x", method="GET", url=f"{BASE}/orders/1?api_key=supersecret&page=2",
        request_headers={"Authorization": "Bearer abc", "Accept": "application/json"},
    )
    rendered = exchange.to_dict()
    assert rendered["request_headers"]["Authorization"] == "<credential>"
    assert rendered["request_headers"]["Accept"] == "application/json"
    assert "supersecret" not in rendered["url"] and "page=2" in rendered["url"]
    assert "supersecret" not in rendered["curl"]


def test_similarity_ignores_volatile_values():
    left = '{"id": 1, "ts": "2026-01-01T00:00:00Z", "name": "a"}'
    right = '{"id": 1, "ts": "2026-06-02T11:22:33Z", "name": "a"}'
    assert similarity(left, right) == 1.0
    assert body_signature(left) == body_signature(right)


def test_summary_counts_by_severity_and_owasp():
    def handler(request):
        return _json({"id": 1, "password": "hunter2"}, headers={"set-cookie": "session=1; Path=/"})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    summary = result["summary"]
    assert summary["total"] == len(result["findings"])
    assert sum(summary["severity"].values()) == summary["total"]
    assert sum(summary["confidence"].values()) == summary["total"]
    assert any(key.startswith("API") for key in summary["owasp"])


# ── scoping and shared-data false positives ─────────────────────────────────

def test_shared_collection_is_not_reported_as_bola():
    """Two users seeing the same search results is normal, not an authz break."""
    from namazu.spec import parse_spec
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "Catalogue", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/search": {"get": {
            "security": [{"bearer": []}],
            "parameters": [{"name": "q", "in": "query",
                            "schema": {"type": "string", "example": "shoes"}}],
            "responses": {"200": {"description": "Hits", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"hits": {"type": "integer"}}}}}}},
        }}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }, BASE)

    def handler(request):
        if not request.headers.get("authorization"):
            return _json({"detail": "unauthorized"}, 401)
        return _json({"hits": 3, "results": ["a", "b", "c"]})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /search", base_url=BASE,
                                 identities={"primary": ALICE, "secondary": BOB}, client=client)
    assert "authz.bola-confirmed" not in [f["id"] for f in result["findings"]]


def test_public_object_is_not_reported_as_bola():
    """If anonymous already reads it, the problem is missing auth, not BOLA."""
    def handler(request):
        return _json(ORDER_1)

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE, "secondary": BOB}, client=client)
    ids = [f["id"] for f in result["findings"]]
    assert "authz.missing-authentication" in ids
    assert "authz.bola-confirmed" not in ids


def test_admin_route_still_checked_without_an_object_id():
    from namazu.spec import parse_spec
    spec = parse_spec({
        "openapi": "3.0.3", "info": {"title": "Admin", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/admin/reports": {"get": {
            "security": [{"bearer": []}],
            "responses": {"200": {"description": "Reports", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"rows": {"type": "integer"}}}}}}},
        }}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }, BASE)

    def handler(request):
        token = request.headers.get("authorization", "")
        if not token:
            return _json({"detail": "unauthorized"}, 401)
        return _json({"rows": 12, "detail": "alice view"} if "alice" in token
                     else {"rows": 12, "detail": "bob view", "extra": "different"})

    with _client(handler) as client:
        result = audit_operation(spec, "GET /admin/reports", base_url=BASE,
                                 identities={"primary": ALICE, "secondary": BOB}, client=client)
    assert "authz.bfla" in [f["id"] for f in result["findings"]]


def test_host_level_findings_carry_host_scope():
    def handler(request):
        return _json(ORDER_1, headers={"server": "nginx/1.25.3",
                                       "set-cookie": "session=1; Path=/"})

    with _client(handler) as client:
        result = audit_operation(_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 identities={"primary": ALICE}, client=client)
    scopes = {f["id"]: f["scope"] for f in result["findings"]}
    assert scopes.get("transport.no-nosniff") == "host"
    assert scopes.get("disclosure.version-banner") == "host"
    assert scopes.get("cookie.weak-flags") == "host"
    # Per-route findings stay operation-scoped.
    assert scopes.get("exposure.undocumented-field", "operation") == "operation"
