"""Response grouping and receipt comparisons use captured mock data only."""
import copy
import json
from types import SimpleNamespace

import pytest

from namazu.audit import inputs, probes
from namazu.audit.model import Exchange
from namazu.audit.response_compare import equivalent


def exchange(body, *, headers=None, **kwargs):
    text = body if isinstance(body, str) else json.dumps(body)
    return Exchange(label="local mock", method="POST", url="http://127.0.0.1/items",
                    status=403, body=text, headers=headers or {}, **kwargs)


def test_explicit_metadata_groups_without_changing_original_evidence():
    first = exchange({"detail": "Denied", "timestamp": "2026-10-08T12:00:00Z",
                      "requestId": "one", "metadata": {"correlation_id": "abc"}},
                     headers={"Date": "Thu, 08 Oct 2026 12:00:00 GMT", "X-Request-ID": "abc"})
    second = exchange({"requestId": "two-longer", "metadata": {"correlation_id": "different"},
                       "timestamp": "2026-10-08T13:00:00Z", "detail": "Denied"},
                      headers={"date": "Thu, 08 Oct 2026 13:00:00 GMT", "x-request-id": "different"})
    for item in (first, second):
        item.headers["Content-Length"] = str(len(item.body.encode("utf-8")))
    before = copy.deepcopy([first.to_dict(), second.to_dict()])
    assert equivalent(first, second) is True
    assert [first.to_dict(), second.to_dict()] == before


@pytest.mark.parametrize("first,second", [
    ({"quantity": 1000000000}, {"quantity": 1000000001}),
    ({"id": "123e4567-e89b-12d3-a456-426614174000"}, {"id": "123e4567-e89b-12d3-a456-426614174001"}),
    ({"hash": "a" * 64}, {"hash": "b" * 64}),
    ({"data": {"timestamp": "2026-10-08T12:00:00Z"}}, {"data": {"timestamp": "2026-10-08T13:00:00Z"}}),
    ({"data": {"metadata": {"requestId": "one"}}}, {"data": {"metadata": {"requestId": "two"}}}),
    ([{"timestamp": "one"}], [{"timestamp": "two"}]),
    ({"requestId": {"error": "invalid"}}, {"requestId": {"error": "missing"}}),
    ({"timestamp": None}, {"timestamp": "2026-10-08T12:00:00Z"}),
    ({"requestId": True}, {"requestId": False}),
    ({"message": "field contains  two spaces"}, {"message": "field contains two spaces"}),
    ("{\"quantity\":9007199254740992}", "{\"quantity\":9007199254740993}"),
    ("{\"quantity\":1}", "{\"quantity\":\"1\"}"),
    ("{\"quantity\":1}", "{\"quantity\":true}"),
    ("Denied 2026-10-08T12:00:00Z", "Denied 2026-10-08T13:00:00Z"),
    ("{" + '"detail":"discarded","detail":"Denied"}', '{"detail":"Denied"}'),
    ("x" * 9000 + "A", "x" * 9000 + "B"),
])
def test_meaningful_body_differences_are_never_hidden(first, second):
    assert equivalent(exchange(first), exchange(second)) is False


@pytest.mark.parametrize("name", [
    "X-Validation-Field", "X-Validation-RequestId", "Retry-After", "X-RateLimit-Remaining",
    "RateLimit", "Server-Timing", "Age", "Set-Cookie", "Last-Modified",
])
def test_non_allowlisted_headers_are_meaningful(name):
    assert equivalent(exchange({"detail": "Denied"}, headers={name: "one"}),
                      exchange({"detail": "Denied"}, headers={name: "two"})) is False


def test_a_mutated_metadata_named_field_is_not_hidden_by_normalization():
    first, second = exchange({"timestamp": "one"}), exchange({"timestamp": "two"})
    assert equivalent(first, second) is True
    assert equivalent(first, second, protected_keys=["timestamp"]) is False


def test_incorrect_content_length_and_incomplete_evidence_remain_visible():
    first = exchange("same", headers={"Content-Length": "5"})
    second = exchange("same", headers={"Content-Length": "4"})
    assert equivalent(first, second) is False
    assert equivalent(first, exchange("same", truncated=True)) is None
    assert equivalent(exchange("", error="timeout"), exchange("")) is None


def record(saved, result, *, field="quantity"):
    executor = SimpleNamespace(exchanges=[], probe_results=[])
    with probes.track(executor, "bounded-input", family="input-handling",
                      baseline=saved, endpoint="POST /items", field=field):
        executor.exchanges.append(result)
    return executor.probe_results[0]


def test_generic_receipts_keep_numeric_and_header_differences_as_leads():
    saved = exchange({"quantity": 1000000000})
    receipt = record(saved, exchange({"quantity": 1000000001}))
    assert receipt["status"] == "field-response-observed"
    assert receipt["requests"] == 1
    assert receipt["exchanges"][0]["response_body"] == '{"quantity": 1000000001}'
    receipt = record(saved, exchange({"quantity": 1000000000}, headers={"X-Validation-Field": "quantity"}))
    assert receipt["status"] == "field-response-observed"


def test_generic_receipts_keep_uniform_denial_inconclusive_and_truncation_unknown():
    saved = exchange({"detail": "Denied", "request_id": "one"})
    receipt = record(saved, exchange({"detail": "Denied", "request_id": "two"}))
    assert receipt["status"] == "same-denial"
    assert "unknown" in receipt["reason"]
    receipt = record(saved, exchange(saved.body, truncated=True))
    assert receipt["status"] == "request-sent"
    assert receipt["reason_code"] == "response-comparison-unavailable"


def test_generic_receipt_protects_mutated_metadata_field():
    receipt = record(exchange({"requestId": "one"}), exchange({"requestId": "two"}), field="requestId")
    assert receipt["status"] == "field-response-observed"


def test_generic_body_receipt_records_location_even_for_query_named_property():
    receipt = record(exchange({"detail": "Denied"}), exchange({"detail": "Denied"}),
                     field=inputs.BodyPoint(["query", "value"]))
    assert receipt["location"] == "body"
    assert receipt["field_pointer"] == "/query/value"
    plan = inputs.battery_plan(exchange({"detail": "Denied"}), endpoint="POST /items",
                               fields=[inputs.BodyPoint(["query", "value"])], budget=40, time_based=True)
    assert plan and all(item["location"] == "body" for item in plan)
