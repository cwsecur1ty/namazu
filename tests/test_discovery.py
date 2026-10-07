"""Swagger documentation discovery through injected HTTP transports."""

import contextlib

import httpx
import pytest

from namazu.discovery import fetch_document


def test_discovers_swagger_ui_initializer_and_resolves_relative_definition(api_document):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path == "/docs/index.html":
            return httpx.Response(200, text='<html><script src="./swagger-initializer.js"></script></html>',
                                  headers={"content-type": "text/html"})
        if request.url.path == "/docs/swagger-initializer.js":
            return httpx.Response(200, text='SwaggerUIBundle({url: "../spec/openapi.json"});',
                                  headers={"content-type": "application/javascript"})
        if request.url.path == "/spec/openapi.json":
            return httpx.Response(200, json=api_document)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        document, source, warnings = fetch_document("https://api.example.test/docs/index.html", client=client)

    assert document["info"]["title"] == "Widget test API"
    assert source == "https://api.example.test/spec/openapi.json"
    assert isinstance(warnings, list)
    assert "https://api.example.test/docs/swagger-initializer.js" in seen
    assert len(seen) < 30


def test_discovery_keeps_documentation_headers_on_same_origin(api_document):
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/docs":
            return httpx.Response(200, text='<html><script>SwaggerUIBundle({url:"/openapi.json"})</script></html>',
                                  headers={"content-type": "text/html"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=api_document)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch_document("https://api.example.test/docs", headers={"Authorization": "Bearer private-docs"}, client=client)

    definition_requests = [req for req in seen if req.url.path == "/openapi.json"]
    assert definition_requests
    assert definition_requests[0].headers["authorization"] == "Bearer private-docs"


@pytest.mark.parametrize("via_redirect", [False, True], ids=["linked-definition", "redirect"])
def test_discovery_never_forwards_credentials_to_another_origin(api_document, via_redirect):
    foreign_requests = []

    def handler(request):
        if request.url.host == "definitions.example.test":
            foreign_requests.append(request)
            return httpx.Response(200, json=api_document)
        if request.url.path == "/docs":
            destination = "https://definitions.example.test/openapi.json"
            if via_redirect:
                return httpx.Response(302, headers={"location": destination})
            return httpx.Response(200, text=f'<html><script>SwaggerUIBundle({{url:"{destination}"}})</script></html>',
                                  headers={"content-type": "text/html"})
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with contextlib.suppress(ValueError):
            fetch_document("https://api.example.test/docs", client=client,
                           headers={"Authorization": "Bearer secret", "Cookie": "session=secret",
                                    "X-API-Key": "secret"})  # Rejecting cross-origin discovery is also safe.

    for request in foreign_requests:
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert "x-api-key" not in request.headers


def test_discovery_rejects_non_openapi_document_without_echoing_credentials():
    def handler(_request):
        return httpx.Response(200, json={"message": "unauthorized", "token": "private-do-not-echo"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError) as caught:
            fetch_document("https://api.example.test/openapi.json", client=client)

    assert "private-do-not-echo" not in str(caught.value)


def test_discovery_redirect_loop_is_bounded():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "/docs"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError):
            fetch_document("https://api.example.test/docs", client=client)

    assert len(seen) < 30


def test_redirected_documentation_uses_conventional_swagger_paths(api_document):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/documentation":
            return httpx.Response(302, headers={"location": "/swagger/index.html"})
        if request.url.path == "/swagger/index.html":
            return httpx.Response(200, text="<html><body>Swagger UI</body></html>",
                                  headers={"content-type": "text/html"})
        if request.url.path == "/swagger/v1/swagger.json":
            return httpx.Response(200, json=api_document)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        document, source, _warnings = fetch_document("https://api.example.test/documentation", client=client)

    assert document["info"]["title"] == "Widget test API"
    assert source == "https://api.example.test/swagger/v1/swagger.json"
    assert seen[:2] == ["/documentation", "/swagger/index.html"]
