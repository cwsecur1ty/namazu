"""Tests for cookie parameters, parallel execution and body-field injection.

The three share a theme: the probes do not change, only where the value is
placed and how many are in flight. So the properties worth asserting are that
a point in a cookie or a body gets the same paired control a query parameter
does, and that a concurrent run reports exactly what a serial one reports.
"""
import json
import re
import threading
import time

import httpx
import pytest

from namazu.audit import audit_operation, inputs
from namazu.audit.model import Exchange
from namazu.audit.transport import Budget, Executor, MutationRefused
from namazu.spec import parse_spec

BASE = "https://api.example.test"


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE)


def _json(payload, status=200, headers=None):
    return httpx.Response(status, json=payload, headers=headers or {})


def _ids(result):
    return [f["id"] for f in result["findings"]]


def _unbalanced(value: str) -> bool:
    """A quote that is not closed breaks a concatenated query; a pair does not."""
    return (value or "").count("'") % 2 == 1


# ── cookie parameters ───────────────────────────────────────────────────────

def _cookie_spec(required=True, extra=()):
    params = [{"name": "session", "in": "cookie", "required": required,
               "schema": {"type": "string", "example": "abc123"}}]
    params += list(extra)
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "S", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/search": {"get": {
            "parameters": params,
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object"}}}}}}}},
    }, BASE)


def _cookies(request):
    jar = {}
    for part in (request.headers.get("cookie") or "").split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            jar[name.strip()] = value.strip()
    return jar


def test_documented_cookie_parameter_is_probed():
    """A parameter declared in: cookie is an input the contract names."""
    def handler(request):
        if _unbalanced(_cookies(request).get("session", "")):
            return httpx.Response(500, text="SQLSTATE[42000]: You have an error in your SQL syntax")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_cookie_spec(), "GET /search", base_url=BASE, client=client)
    hit = next(f for f in result["findings"]
               if f["id"] == "input.sql-error" and f["parameter"] == "session")
    assert hit["evidence"]["location"] == "cookie"
    assert hit["evidence"]["control"] == "''"
    assert "documented cookie parameter" in hit["detail"]


def test_cookie_parameter_the_request_omitted_is_still_probed():
    """An optional cookie is absent from the generated request, not from the API."""
    seen = []

    def handler(request):
        seen.append(_cookies(request).get("session"))
        if _unbalanced(_cookies(request).get("session", "")):
            return httpx.Response(500, text="ORA-01756: quoted string not properly terminated")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_cookie_spec(required=False), "GET /search",
                                 base_url=BASE, client=client)
    assert seen[0] is None, "the baseline should not invent an optional cookie"
    assert any(value == "'" for value in seen), "the probe has to supply the cookie itself"
    assert "input.sql-error" in _ids(result)


def test_cookie_probe_replaces_one_cookie_and_keeps_the_rest():
    """Dropping the session cookie would turn every probe into a 401."""
    jars = []

    def handler(request):
        jars.append(_cookies(request))
        return _json({"hits": 1})

    with _client(handler) as client:
        audit_operation(_cookie_spec(), "GET /search", base_url=BASE, client=client,
                        identities={"primary": {"Cookie": "session=abc123; tracking=keep-me"}})
    probed = [jar for jar in jars if jar.get("session") not in (None, "abc123")]
    assert probed, "the session cookie was never given a probe value"
    assert all(jar.get("tracking") == "keep-me" for jar in probed)


def test_a_cookie_is_never_sent_a_line_break():
    """CRLF in a request header is request smuggling: a different, invasive class."""
    sent = []

    def handler(request):
        sent.append(request.headers.get("cookie") or "")
        return _json({"hits": 1})

    with _client(handler) as client:
        result = audit_operation(_cookie_spec(), "GET /search", base_url=BASE, client=client)
    assert sent, "no request reached the handler"
    assert not any("\r" in value or "\n" in value for value in sent)
    assert "input.crlf-injection" not in _ids(result)


def test_cookie_and_header_points_carry_their_documented_example():
    baseline = Exchange(label="baseline", method="GET", url=f"{BASE}/search")
    baseline.request_headers = {"Cookie": "session=live-value"}
    cookie = inputs.Point("session", location="cookie", example="from-contract")
    header = inputs.Point("X-Tenant", location="header", example="acme")
    assert cookie.current(baseline) == "live-value"
    assert inputs._seed_value(baseline, header, None) == "acme"


# ── parallel execution ──────────────────────────────────────────────────────

def _busy_spec():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "S", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/orders/{orderId}": {"get": {
            "parameters": [
                {"name": "orderId", "in": "path", "required": True,
                 "schema": {"type": "integer", "example": 7}},
                {"name": "q", "in": "query", "schema": {"type": "string", "example": "shoes"}},
                {"name": "redirect_url", "in": "query", "schema": {"type": "string"}},
                {"name": "X-Tenant", "in": "header", "schema": {"type": "string", "example": "acme"}},
                {"name": "session", "in": "cookie", "required": True,
                 "schema": {"type": "string", "example": "abc"}},
            ],
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object"}}}}}}}},
    }, BASE)


NONCE = re.compile(r"k[0-9a-f]{8}")


def _fingerprint(request):
    """What was probed, with the per-probe random canary normalised away."""
    pairs = sorted(request.url.params.multi_items())
    return NONCE.sub("<nonce>", f"{request.method} {request.url.path}?{pairs}")


def test_a_concurrent_run_sends_the_same_requests_as_a_serial_one():
    """Concurrency is a scheduling change. It must not change what is probed."""
    def run(workers):
        sent = []
        lock = threading.Lock()

        def handler(request):
            with lock:
                sent.append(_fingerprint(request))
            if _unbalanced(request.url.params.get("q", "")):
                return httpx.Response(500, text="PG::SyntaxError: unterminated quoted string")
            return _json({"hits": 1})

        with _client(handler) as client:
            result = audit_operation(_busy_spec(), "GET /orders/{orderId}", base_url=BASE,
                                     profile="thorough", concurrency=workers, client=client)
        return sorted(sent), result

    serial_sent, serial = run(1)
    parallel_sent, parallel = run(6)

    assert serial["concurrency"] == 1 and parallel["concurrency"] == 6
    assert parallel_sent == serial_sent
    assert sorted(_ids(parallel)) == sorted(_ids(serial))
    assert parallel["requests_sent"] == serial["requests_sent"]


def test_the_request_log_reads_the_same_whichever_way_it_ran():
    """Exchanges merge in submission order, not completion order."""
    def run(workers):
        def handler(request):
            # Make completion order differ from submission order.
            time.sleep(0.02 if "actuator" in request.url.path else 0)
            return _json({"detail": "not found"}, 404)

        with _client(handler) as client:
            return audit_operation(_busy_spec(), "GET /orders/{orderId}", base_url=BASE,
                                   profile="thorough", concurrency=workers, client=client)

    serial, parallel = run(1), run(8)
    assert [entry["label"] for entry in parallel["log"]] == \
           [entry["label"] for entry in serial["log"]]
    assert parallel["log"][0]["label"] == "baseline"
    assert [entry["seq"] for entry in parallel["log"]] == \
           list(range(1, len(parallel["log"]) + 1))


@pytest.mark.parametrize("attempt", range(4))
def test_the_budget_ceiling_holds_under_concurrency(attempt):
    """Two threads must not both be sold the last request in the budget."""
    from namazu.audit import engine
    original = engine.PROFILES["thorough"]["requests_per_operation"]
    engine.PROFILES["thorough"]["requests_per_operation"] = 12
    counted = []
    lock = threading.Lock()
    try:
        def handler(request):
            with lock:
                counted.append(1)
            return _json({"hits": 1})

        with _client(handler) as client:
            result = audit_operation(_busy_spec(), "GET /orders/{orderId}", base_url=BASE,
                                     profile="thorough", concurrency=16, client=client)
    finally:
        engine.PROFILES["thorough"]["requests_per_operation"] = original
    assert len(counted) <= 12, f"sent {len(counted)} requests against a budget of 12"
    assert result["requests_sent"] == len(counted)
    assert any("budget of 12 was reached" in note for note in result["notes"])


def test_budget_take_is_atomic():
    budget = Budget(500)
    barrier = threading.Barrier(10)

    def draw():
        barrier.wait()
        for _ in range(100):
            try:
                budget.take()
            except Exception:
                return

    threads = [threading.Thread(target=draw) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert budget.spent == 500


def test_a_fan_out_branch_refuses_to_change_state():
    """A write sequence must not be parallelisable by accident."""
    with _client(lambda r: _json({"ok": True})) as client:
        executor = Executor(client, Budget(20), allow_mutating=True, concurrency=4)

        def one(branch, path):
            return branch.send("POST", f"{BASE}{path}", label=f"write {path}", body="{}",
                               content_type="application/json")

        with pytest.raises(MutationRefused):
            executor.fan_out(["/a", "/b"], one)


def test_fan_out_returns_results_in_item_order():
    with _client(lambda r: _json({"ok": True})) as client:
        executor = Executor(client, Budget(20), concurrency=4)

        def one(branch, item):
            time.sleep(0.03 if item == "first" else 0)
            branch.send("GET", f"{BASE}/{item}", label=f"probe {item}")
            return item

        assert executor.fan_out(["first", "second", "third"], one) == \
               ["first", "second", "third"]
        assert [exchange.label for exchange in executor.exchanges] == \
               ["probe first", "probe second", "probe third"]


def test_concurrency_can_be_forced_down_to_one():
    """An operator who needs the target left alone keeps that option."""
    with _client(lambda r: _json({"hits": 1})) as client:
        result = audit_operation(_busy_spec(), "GET /orders/{orderId}", base_url=BASE,
                                 profile="thorough", concurrency=1, client=client)
    assert result["concurrency"] == 1


# ── request body injection ──────────────────────────────────────────────────

def _create_spec():
    return parse_spec({
        "openapi": "3.0.3", "info": {"title": "S", "version": "1"},
        "servers": [{"url": BASE}],
        "paths": {"/widgets": {"post": {
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": ["name", "items"],
                "properties": {
                    "name": {"type": "string", "example": "widget"},
                    "active": {"type": "boolean", "example": True},
                    "items": {"type": "array", "items": {
                        "type": "object", "properties": {
                            "sku": {"type": "string", "example": "SKU-1"},
                            "quantity": {"type": "integer", "example": 2}}}},
                }}}}},
            "responses": {"201": {"description": "created", "content": {"application/json": {
                "schema": {"type": "object"}}}}}}}},
    }, BASE)


def _write_audit(handler, **kwargs):
    with _client(handler) as client:
        return audit_operation(_create_spec(), "POST /widgets", base_url=BASE,
                               profile="writes", allow_mutating=True, client=client, **kwargs)


def test_a_body_field_reaching_a_query_is_found():
    def handler(request):
        body = json.loads(request.content or b"{}")
        if _unbalanced(str(body.get("name", ""))):
            return httpx.Response(500, text="SQLSTATE[42000]: You have an error in your SQL syntax")
        return _json({"id": 1}, 201)

    result = _write_audit(handler)
    hit = next(f for f in result["findings"]
               if f["id"] == "input.sql-error" and f["parameter"] == "name")
    assert hit["evidence"]["location"] == "body"
    assert hit["evidence"]["control"] == "''"
    assert hit["mutating"] is True
    assert "field in the request body" in hit["detail"]


def test_a_nested_body_field_is_reached():
    def handler(request):
        body = json.loads(request.content or b"{}")
        items = body.get("items") or [{}]
        if "{{7*31}}" in str(items[0].get("sku", "")):
            return _json({"echo": "217"}, 201)
        if "{{9*41}}" in str(items[0].get("sku", "")):
            return _json({"echo": "369"}, 201)
        return _json({"id": 1}, 201)

    result = _write_audit(handler)
    hit = next(f for f in result["findings"] if f["id"] == "input.template-injection")
    assert hit["parameter"] == "items[0].sku"
    assert hit["mutating"] is True


def test_body_injection_does_not_run_without_write_consent():
    """The readonly profile never sends a POST, so it never probes a body."""
    def handler(request):
        body = json.loads(request.content or b"{}")
        if _unbalanced(str(body.get("name", ""))):
            return httpx.Response(500, text="SQLSTATE[42000]: syntax error")
        return _json({"id": 1}, 201)

    with _client(handler) as client:
        result = audit_operation(_create_spec(), "POST /widgets", base_url=BASE,
                                 profile="readonly", client=client)
    assert "input.sql-error" not in _ids(result)
    assert result["requests_sent"] == 0


def test_the_report_says_how_much_the_body_battery_wrote():
    """A probe that creates objects on the target has to disclose it."""
    result = _write_audit(lambda r: _json({"id": 1}, 201))
    note = next(n for n in result["notes"] if "body injection battery" in n)
    assert "state-changing POST requests" in note
    assert "remove them" in note


def test_a_boolean_body_field_is_not_probed():
    """A string payload in a boolean field is rejected before it reaches a sink."""
    baseline = Exchange(label="baseline", method="POST", url=f"{BASE}/widgets")
    baseline.request_body = json.dumps({"active": True, "name": "widget", "count": 3})
    names = [str(point) for point in inputs._body_points(baseline, 10)]
    assert "active" not in names
    assert {"name", "count"} <= set(names)


def test_body_points_put_the_interesting_names_first():
    baseline = Exchange(label="baseline", method="POST", url=f"{BASE}/widgets")
    baseline.request_body = json.dumps({"quantity": 2, "filename": "report.pdf"})
    assert str(inputs._body_points(baseline, 1)[0]) == "filename"


def test_a_body_point_replaces_only_its_own_field():
    baseline = Exchange(label="baseline", method="POST", url=f"{BASE}/widgets")
    baseline.request_body = json.dumps({"name": "widget", "items": [{"sku": "SKU-1"}]})
    baseline.request_headers = {"Content-Type": "application/json"}
    point = inputs.BodyPoint(["items", 0, "sku"], example="SKU-1")
    plan = point.place(baseline, "'", {})
    assert json.loads(plan["body"]) == {"name": "widget", "items": [{"sku": "'"}]}
    assert plan["mutating"] is True
    assert json.loads(baseline.request_body)["items"][0]["sku"] == "SKU-1"
