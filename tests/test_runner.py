"""Execution tests verify the actual wire request and returned contract report."""

import json

import httpx
import pytest

from namazu.runner import execute_request


def test_post_transmits_nested_json_and_validates_matching_response(api_document, widget_body, widget_response):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(201, json=widget_response)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body, allow_mutating=True,
                                 headers={"Authorization": "Bearer test-token"}, client=client)

    assert len(seen) == 1
    assert seen[0].method == "POST"
    assert str(seen[0].url) == "https://api.example.test/widgets"
    assert seen[0].headers["content-type"].startswith("application/json")
    assert seen[0].headers["authorization"] == "Bearer test-token"
    assert json.loads(seen[0].content) == widget_body
    assert result["response"]["status"] == 201
    assert result["validation"]["valid"] is True
    assert result["validation"]["errors"] == []


def test_text_json_media_serializes_and_validates_as_json(api_document, widget_body, widget_response):
    operation = api_document["paths"]["/widgets"]["post"]
    for content in (operation["requestBody"]["content"], operation["responses"]["201"]["content"]):
        content["text/json"] = content.pop("application/json")
    def handler(request):
        assert request.headers["content-type"] == "text/json"
        assert json.loads(request.content) == widget_body
        return httpx.Response(201, content=json.dumps(widget_response), headers={"content-type": "text/json"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 content_type="text/json", allow_mutating=True, client=client)
    assert result["validation"]["valid"] is True


def test_post_requires_mutating_opt_in_before_sending(api_document, widget_body):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(201, json={})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="(?i)mutating|allow_mutating|confirm"):
            execute_request(api_document, "POST /widgets", body=widget_body, client=client)

    assert seen == []


def test_nested_response_schema_failure_reports_location(api_document, widget_body):
    def handler(_request):
        return httpx.Response(201, json={"id": 42, "audit": {"created_by": 99}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is False
    assert "created_by" in json.dumps(result["validation"]["errors"])


def test_error_status_uses_its_own_schema_and_media_type(api_document, widget_body):
    def handler(_request):
        return httpx.Response(400, content=json.dumps({"detail": "SKU is not available"}),
                              headers={"content-type": "application/problem+json; charset=utf-8"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["response"]["status"] == 400
    assert result["validation"]["valid"] is True
    assert result["validation"]["errors"] == []


def test_undocumented_status_is_a_contract_failure(api_document, widget_body, widget_response):
    with httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(202, json=widget_response))) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is False
    assert "202" in json.dumps(result["validation"])


def test_wrong_media_type_is_a_contract_failure(api_document, widget_body, widget_response):
    def handler(_request):
        return httpx.Response(201, text=json.dumps(widget_response), headers={"content-type": "text/plain"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is False
    assert "content" in json.dumps(result["validation"]).lower() or "media" in json.dumps(result["validation"]).lower()


def test_default_response_contract_applies(api_document, widget_body):
    response_map = api_document["paths"]["/widgets"]["post"]["responses"]
    response_map["default"] = response_map.pop("400")

    def handler(_request):
        return httpx.Response(429, content='{"detail":"try later"}', headers={"content-type": "application/problem+json"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is True


def test_response_uses_schema_for_matching_media_type(api_document, widget_body):
    response_map = api_document["paths"]["/widgets"]["post"]["responses"]
    response_map["201"]["content"]["application/problem+json"] = response_map["400"]["content"]["application/problem+json"]

    def handler(_request):
        return httpx.Response(201, content='{"detail":"created asynchronously"}',
                              headers={"content-type": "application/problem+json"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is True
    assert result["validation"]["errors"] == []


def test_response_status_range_contract_applies(api_document, widget_body, widget_response):
    response_map = api_document["paths"]["/widgets"]["post"]["responses"]
    response_map["2XX"] = response_map.pop("201")

    with httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(202, json=widget_response))) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is True


def test_more_specific_wildcard_media_schema_wins(api_document, widget_body, widget_response):
    response = api_document["paths"]["/widgets"]["post"]["responses"]["201"]
    widget_schema = response["content"]["application/json"]["schema"]
    response["content"] = {
        "*/*": {"schema": {"type": "string"}},
        "application/*": {"schema": widget_schema},
    }

    with httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(201, json=widget_response))) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is True


def test_invalid_encoded_json_cannot_report_schema_success(api_document, widget_body):
    malformed = b'{"id":42,"audit":{"created_by":"\xff"}}'
    with httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(
        201, content=malformed, headers={"content-type": "application/json"}
    ))) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["validation"]["valid"] is not True
    assert "encod" in json.dumps(result["validation"]).lower()


def test_redirect_does_not_replay_post_or_credentials_to_different_origin(api_document, widget_body):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(307, headers={"location": "https://foreign.example.test/widgets"})

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        execute_request(api_document, "POST /widgets", body=widget_body, allow_mutating=True,
                        headers={"Authorization": "Bearer secret", "X-API-Key": "secret"}, client=client)

    assert len(seen) == 1
    assert seen[0].url.host == "api.example.test"


def test_oversized_response_is_bounded_and_not_reported_as_valid(api_document, widget_body):
    huge_body = json.dumps({"id": 42, "audit": {"created_by": "x" * (5 * 1024 * 1024)}})

    with httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(201, content=huge_body,
                     headers={"content-type": "application/json"}))) as client:
        result = execute_request(api_document, "POST /widgets", body=widget_body,
                                 allow_mutating=True, client=client)

    assert result["response"]["truncated"] is True
    assert len(str(result["response"]["body"])) < len(huge_body)
    assert result["validation"]["valid"] is not True
    assert result["validation"]["warnings"]


def test_empty_multipart_body_keeps_its_selected_media_type(api_document, widget_response):
    operation = api_document["paths"]["/widgets"]["post"]
    operation["requestBody"]["content"] = {"multipart/form-data": {"schema": {"type": "object"}}}
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(201, json=widget_response)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        execute_request(api_document, "POST /widgets", body={}, allow_mutating=True,
                        content_type="multipart/form-data", client=client)

    assert len(seen) == 1
    media = seen[0].headers.get("content-type", "")
    assert media.startswith("multipart/form-data; boundary=")
    boundary = media.split("boundary=", 1)[1]
    assert seen[0].content == f"--{boundary}--\r\n".encode("ascii")


def test_response_stream_cannot_extend_timeout_by_sending_small_chunks(api_document, widget_body, monkeypatch):
    now = [100.0]
    monkeypatch.setattr("namazu.runner.time.monotonic", lambda: now[0])

    class SlowBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"id":42,'
            now[0] += 2.0
            yield b'"audit":{"created_by":"tester"}}'

    with httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(
        201, stream=SlowBody(), headers={"content-type": "application/json"}
    ))) as client:
        with pytest.raises(httpx.TimeoutException):
            execute_request(api_document, "POST /widgets", body=widget_body,
                            allow_mutating=True, timeout=1, client=client)
