"""Time-based blind SQL injection, and the three ways it must refuse to fire.

The fixture really sleeps, because the probe really measures. What it does not
do is sleep for the shipped two and four seconds: the thresholds are scaled
down for the logic tests, keeping the same ratios, so the suite does not spend
half a minute waiting. The shipped values are pinned by their own test, and
one end-to-end case runs at them.

The three refusals are the point of the design. An endpoint that is slow
whenever it sees a quote is caught by the zero-second control. An endpoint
that stalls a fixed amount is caught by the scaling re-test. An endpoint that
never sleeps produces nothing. Any of those reported as a finding would be a
high-severity false positive on an endpoint whose only fault is being slow.
"""
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

import pytest

from namazu.audit import audit_operation, inputs
from namazu.spec import parse_spec

MYSQL = re.compile(r"(?<!PG_)SLEEP\((\d+)\)", re.IGNORECASE)
POSTGRES = re.compile(r"PG_SLEEP\((\d+)\)", re.IGNORECASE)
MSSQL = re.compile(r"WAITFOR DELAY '0:0:(\d+)'", re.IGNORECASE)

SPEC = {
    "openapi": "3.0.3", "info": {"title": "Search", "version": "1"},
    "paths": {"/search": {"get": {
        "parameters": [{"name": "q", "in": "query",
                        "schema": {"type": "string", "example": "widget"}}],
        "responses": {"200": {"description": "ok", "content": {
            "application/json": {"schema": {"type": "object"}}}}}}}},
}


class _Database(BaseHTTPRequestHandler):
    """An endpoint whose timing behaviour is set by ``mode``."""

    protocol_version = "HTTP/1.1"
    mode = "safe"
    seen: ClassVar[list] = []
    lock = threading.Lock()

    def log_message(self, *_args):
        pass

    def _delay(self, value: str) -> float:
        quoted = "'" in value
        if _Database.mode == "always_slow":
            # Slow whenever a quote appears, sleep or not. The zero-second
            # control is the only thing that can tell this apart.
            return 1.0 if quoted else 0.0
        asked = None
        for mode, pattern in (("vulnerable_mysql", MYSQL),
                              ("vulnerable_postgres", POSTGRES),
                              ("vulnerable_mssql", MSSQL)):
            match = pattern.search(value)
            if match and _Database.mode in (mode, "fixed_delay"):
                asked = int(match.group(1))
                break
        if asked is None:
            return 0.0
        if _Database.mode == "fixed_delay":
            # Stalls when poked, but by the same amount however much is asked
            # for. Only the scaling re-test catches this.
            return 1.0 if asked else 0.0
        return float(asked)

    def do_GET(self):
        value = " ".join(parse_qs(urlsplit(self.path).query).get("q", [""]))
        with _Database.lock:
            _Database.seen.append(value)
        delay = self._delay(value)
        if delay:
            time.sleep(delay)
        raw = json.dumps({"results": [], "query": "redacted"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def quick(monkeypatch):
    """Same ratios, shorter waits, so the logic can be tested in seconds."""
    monkeypatch.setattr(inputs, "SLEEP_SECONDS", 1)
    monkeypatch.setattr(inputs, "SCALE_SECONDS", 2)
    monkeypatch.setattr(inputs, "DELAY_MARGIN_MS", 500)
    monkeypatch.setattr(inputs, "SLEEP_PAYLOADS", inputs.SLEEP_PAYLOADS)


@pytest.fixture
def database():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Database)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    spec = parse_spec(SPEC, base)

    def run(mode, profile="thorough"):
        _Database.mode = mode
        with _Database.lock:
            _Database.seen.clear()
        return audit_operation(spec, "GET /search", base_url=base, profile=profile)

    yield run
    server.shutdown()


def ids(result):
    return [item["id"] for item in result["findings"]]


def one(result, finding_id):
    matches = [item for item in result["findings"] if item["id"] == finding_id]
    assert len(matches) == 1, f"expected one {finding_id}, got {ids(result)}"
    return matches[0]


def sleeps_sent():
    with _Database.lock:
        return [value for value in _Database.seen
                if MYSQL.search(value) or POSTGRES.search(value) or MSSQL.search(value)]


# ── it fires when the delay is real ─────────────────────────────────────────

def test_a_sleeping_endpoint_is_confirmed(quick, database):
    report = one(database("vulnerable_mysql"), "input.sql-time-based")
    assert report["severity"] == "high"
    assert report["confidence"] == "confirmed"
    assert report["evidence"]["engine"] == "MySQL or MariaDB"
    timings = report["evidence"]
    assert timings["zero_sleep_ms"] < timings["sleep_ms"] < timings["scaled_ms"]


def test_the_engine_is_named_from_the_payload_that_worked(quick, database):
    report = one(database("vulnerable_mssql"), "input.sql-time-based")
    assert report["evidence"]["engine"] == "Microsoft SQL Server"


def test_postgres_is_told_apart_from_mysql(quick, database):
    report = one(database("vulnerable_postgres"), "input.sql-time-based")
    assert report["evidence"]["engine"] == "PostgreSQL"


def test_all_three_measurements_are_in_the_evidence(quick, database):
    report = one(database("vulnerable_postgres"), "input.sql-time-based")
    for key in ("baseline_ms", "sleep_ms", "zero_sleep_ms", "scaled_ms",
                "sleep_seconds", "scaled_seconds"):
        assert key in report["evidence"], key
    assert len(report["proof"]) == 3, "the reader needs all three requests"


def test_the_finding_states_what_it_cost_and_what_it_misses(quick, database):
    report = one(database("vulnerable_mysql"), "input.sql-time-based")
    assert "held database thread" in report["limitations"]
    assert "numeric context" in report["limitations"]
    assert "SQLite" in report["limitations"]


# ── and refuses to, three ways ──────────────────────────────────────────────

def test_an_endpoint_that_is_simply_slow_is_not_reported(quick, database):
    """The zero-second control. The payload is slow; the sleep is not why."""
    result = database("always_slow")
    assert "input.sql-time-based" not in ids(result)
    labels = [entry["label"] for entry in result["log"]]
    assert any("zero-second sleep" in label for label in labels), (
        "the control has to have been sent, or this passed for the wrong reason")


def test_an_endpoint_that_stalls_a_fixed_amount_is_not_reported(quick, database):
    """The scaling re-test. It delays when poked, but not proportionally."""
    result = database("fixed_delay")
    assert "input.sql-time-based" not in ids(result)
    labels = [entry["label"] for entry in result["log"]]
    assert any("delay scale" in label for label in labels), (
        "the scaling probe has to have been sent")


def test_an_endpoint_that_never_sleeps_produces_nothing(quick, database):
    assert "input.sql-time-based" not in ids(database("safe"))


# ── when it is allowed to run at all ────────────────────────────────────────

@pytest.mark.parametrize("profile", ["passive", "readonly"])
def test_the_lighter_profiles_send_no_sleep_payload(quick, database, profile):
    """It holds a database thread, so it stays out of the default profiles."""
    result = database("vulnerable_mysql", profile=profile)
    assert "input.sql-time-based" not in ids(result)
    assert sleeps_sent() == []


def test_the_thorough_profile_does_send_one(quick, database):
    database("vulnerable_mysql")
    assert sleeps_sent(), "thorough is the profile that opted in"


def test_only_the_thorough_profile_enables_it():
    from namazu.audit.engine import PROFILES

    assert [name for name, settings in PROFILES.items()
            if settings.get("time_based")] == ["thorough"]


def test_the_cost_is_bounded_per_operation(quick, database):
    """Two points at most, and one engine confirmed at a time."""
    assert inputs.TIME_BASED_POINTS == 2
    database("safe")
    # Three engines tried against one documented parameter, and nothing more:
    # no scaling probe is spent where the first measurement was fast.
    assert len(sleeps_sent()) <= len(inputs.SLEEP_PAYLOADS) * inputs.TIME_BASED_POINTS


def test_a_timeout_shorter_than_the_sleep_skips_the_probe(database):
    """A sleep longer than the timeout can only be timed out, which proves nothing."""
    _Database.mode = "vulnerable_mysql"
    with _Database.lock:
        _Database.seen.clear()
    spec = parse_spec(SPEC, "http://127.0.0.1:1")
    audit_operation(spec, "GET /search", base_url="http://127.0.0.1:1",
                    profile="thorough", timeout=3)
    assert sleeps_sent() == []


# ── the shipped values ──────────────────────────────────────────────────────

def test_the_shipped_thresholds_are_what_was_agreed():
    """Pinned, because the tests above run at scaled-down values."""
    assert inputs.SLEEP_SECONDS == 2
    assert inputs.SCALE_SECONDS == 4
    assert inputs.SCALE_SECONDS == inputs.SLEEP_SECONDS * 2, "scaling must be a clear doubling"
    assert inputs.DELAY_MARGIN_MS < inputs.SLEEP_SECONDS * 1000, (
        "the bar has to be reachable by the sleep it measures")


def test_the_payloads_close_the_string_and_comment_out_the_rest():
    for engine, template in inputs.SLEEP_PAYLOADS:
        rendered = template.format(seed="widget", seconds=2)
        assert rendered.startswith("widget'"), engine
        assert rendered.endswith("-- "), f"{engine}: MySQL needs the trailing space"
        assert "2" in rendered


def test_a_zero_second_payload_asks_for_no_delay():
    for engine, template in inputs.SLEEP_PAYLOADS:
        rendered = template.format(seed="x", seconds=0)
        found = (MYSQL.search(rendered) or POSTGRES.search(rendered)
                 or MSSQL.search(rendered))
        assert found, engine
        assert int(found.group(1)) == 0, engine


def test_the_whole_probe_runs_at_the_shipped_values(database):
    """One end-to-end case at two and four seconds, since the rest are scaled."""
    started = time.monotonic()
    report = one(database("vulnerable_mysql"), "input.sql-time-based")
    elapsed = time.monotonic() - started
    assert report["evidence"]["sleep_seconds"] == 2
    assert report["evidence"]["scaled_seconds"] == 4
    assert report["evidence"]["sleep_ms"] >= 2000
    assert report["evidence"]["scaled_ms"] >= 4000
    assert report["evidence"]["zero_sleep_ms"] < 1000
    assert elapsed >= 6, "the target really did hold a thread for six seconds"
