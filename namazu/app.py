"""Namazu's independent local web application. No K9 database or scanner required."""
from pathlib import Path
from typing import Any
import html
import ipaddress
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import oauth
from .audit import audit_inventory, audit_operation
from .audit import external
from .discovery import fetch_document
from .runner import execute_request, prepare_request
from .spec import parse_spec

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Namazu", version="0.1.0", description="Standalone API testing by K9", docs_url=None, redoc_url=None)


@app.middleware("http")
async def local_requests(request: Request, call_next):
    hostname = (request.url.hostname or "").lower()
    allowed = {"localhost", *(name.strip().lower() for name in os.environ.get("NAMAZU_ALLOWED_HOSTS", "").split(",") if name.strip())}
    try:
        ipaddress.ip_address(hostname)
        literal_ip = True
    except ValueError:
        literal_ip = False
    if not literal_ip and hostname not in allowed:
        return JSONResponse({"detail": "Unrecognized host. Open Namazu using localhost or its IP address."}, status_code=400)
    # Browser-origin checks prevent an unrelated site driving a local HTTP proxy.
    source = request.headers.get("origin")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if source and source.rstrip("/") != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "Use Namazu from its own application origin"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are not allowed"}, status_code=403)
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            return JSONResponse({"detail": "Use application/json"}, status_code=415)
        # Bound inputs before JSON parsing (raw OpenAPI plus derived view is duplicated).
        total = 0
        chunks = []
        async for chunk in request.stream():
            total += len(chunk)
            if total > 24 * 1024 * 1024:
                return JSONResponse({"detail": "Request exceeds 24 MiB"}, status_code=413)
            chunks.append(chunk)
        request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response


class ImportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str | None = None
    raw_spec: str | None = None
    source_url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True
    timeout: float = Field(default=15, ge=1, le=120)


class RequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: dict
    operation_id: str
    base_url: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    content_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    allow_mutating: bool = False
    verify_tls: bool = True
    timeout: float = Field(default=15, ge=1, le=120)

    def options(self):
        values = {"base_url": self.base_url, "parameters": self.parameters,
                  "content_type": self.content_type, "headers": self.headers}
        if "body" in self.model_fields_set:
            values["body"] = self.body
        return values


class AuditInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: dict
    operation_id: str | None = None
    base_url: str | None = None
    profile: str = "readonly"
    identities: dict[str, dict] = Field(default_factory=dict)
    allow_mutating: bool = False
    verify_tls: bool = True
    timeout: float = Field(default=15, ge=1, le=120)
    budget: int = Field(default=60, ge=1, le=200)


@app.exception_handler(ValueError)
async def value_error(_request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(httpx.HTTPError)
async def http_error(_request, exc):
    detail = "Request timed out; check the target and timeout setting" if isinstance(exc, httpx.TimeoutException) else "Could not send request; check the URL, TLS settings and target availability"
    return JSONResponse({"detail": detail}, status_code=502)


@app.get("/api/health")
def health():
    return {"status": "ok", "tool": "Namazu", "version": "0.1.0"}


@app.post("/api/import")
def import_document(body: ImportInput):
    if bool(body.url) == bool(body.raw_spec):
        raise ValueError("Provide either a documentation URL or a JSON/YAML specification")
    if body.url:
        document, source, warnings = fetch_document(body.url, headers=body.headers,
                                                  verify_tls=body.verify_tls, timeout=body.timeout)
        result = parse_spec(document, source)
        result["warnings"] = list(dict.fromkeys(result["warnings"] + warnings))
        return result
    return parse_spec(body.raw_spec, body.source_url)


@app.post("/api/prepare")
def prepare(body: RequestInput):
    return prepare_request(body.spec, body.operation_id, **body.options())


@app.post("/api/run")
def run(body: RequestInput):
    return execute_request(body.spec, body.operation_id, allow_mutating=body.allow_mutating,
                           verify_tls=body.verify_tls, timeout=body.timeout, **body.options())


@app.post("/api/audit")
def audit(body: AuditInput):
    if not body.operation_id:
        raise ValueError("Choose an operation to audit")
    return audit_operation(body.spec, body.operation_id, base_url=body.base_url,
                           identities=body.identities, profile=body.profile,
                           allow_mutating=body.allow_mutating, verify_tls=body.verify_tls,
                           timeout=body.timeout)


@app.post("/api/audit/inventory")
def audit_surface(body: AuditInput):
    return audit_inventory(body.spec, base_url=body.base_url, identities=body.identities,
                           verify_tls=body.verify_tls, timeout=body.timeout, budget=body.budget)


class OAuthInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grant: str = "authorization_code"
    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""
    audience: str = ""
    username: str = ""
    password: str = ""
    refresh_token: str = ""
    auth_style: str = "post"
    use_pkce: bool = True
    extra_params: dict[str, str] = Field(default_factory=dict)
    redirect_uri: str | None = None
    session: str | None = None
    spec: dict | None = None
    verify_tls: bool = True
    timeout: float = Field(default=15, ge=1, le=120)


@app.post("/api/oauth/discover")
def oauth_discover(body: OAuthInput):
    result = {"from_spec": oauth.from_spec(body.spec) if isinstance(body.spec, dict) else []}
    if body.issuer:
        result["metadata"] = oauth.discover(body.issuer, verify_tls=body.verify_tls, timeout=body.timeout)
    return result


@app.post("/api/oauth/token")
def oauth_token(body: OAuthInput):
    """Grants that need no browser round trip."""
    if not body.token_endpoint:
        raise ValueError("Enter the token endpoint URL")
    shared = {"token_url": body.token_endpoint, "client_id": body.client_id,
              "client_secret": body.client_secret, "auth_style": body.auth_style,
              "verify_tls": body.verify_tls, "timeout": body.timeout}
    if body.grant == "client_credentials":
        return oauth.client_credentials(scope=body.scope, audience=body.audience, **shared)
    if body.grant == "password":
        if not body.username:
            raise ValueError("Enter the username for the password grant")
        return oauth.password_grant(username=body.username, password=body.password,
                                    scope=body.scope, **shared)
    if body.grant == "refresh_token":
        if not body.refresh_token:
            raise ValueError("Enter the refresh token")
        return oauth.refresh(refresh_token=body.refresh_token, scope=body.scope, **shared)
    raise ValueError("Use /api/oauth/authorize for the authorization code grant")


@app.post("/api/oauth/authorize")
def oauth_authorize(body: OAuthInput, request: Request):
    """Begin the authorization code flow and return the URL to open."""
    if not body.authorization_endpoint or not body.token_endpoint:
        raise ValueError("Enter both the authorization and token endpoint URLs")
    redirect_uri = body.redirect_uri or str(request.base_url).rstrip("/") + "/oauth/callback"
    return oauth.start_authorization(
        authorization_endpoint=body.authorization_endpoint, token_endpoint=body.token_endpoint,
        client_id=body.client_id, client_secret=body.client_secret, redirect_uri=redirect_uri,
        scope=body.scope, audience=body.audience, auth_style=body.auth_style,
        use_pkce=body.use_pkce, extra_params=body.extra_params,
        verify_tls=body.verify_tls, timeout=body.timeout,
    )


@app.post("/api/oauth/collect")
def oauth_collect(body: OAuthInput):
    if not body.session:
        raise ValueError("Missing the authorization session id")
    return oauth.collect(body.session)


@app.post("/api/oauth/probe")
def oauth_probe(body: OAuthInput, request: Request):
    """Read-only checks against the authorization server itself."""
    if not body.authorization_endpoint:
        raise ValueError("Enter the authorization endpoint URL")
    redirect_uri = body.redirect_uri or str(request.base_url).rstrip("/") + "/oauth/callback"
    metadata = None
    if body.issuer:
        try:
            metadata = oauth.discover(body.issuer, verify_tls=body.verify_tls, timeout=body.timeout)
        except ValueError:
            metadata = None
    findings = oauth.probe_authorization_server(
        authorization_endpoint=body.authorization_endpoint, client_id=body.client_id,
        redirect_uri=redirect_uri, metadata=metadata,
        verify_tls=body.verify_tls, timeout=body.timeout,
    )
    return {"findings": [item.to_dict() for item in findings],
            "metadata": metadata, "redirect_uri": redirect_uri}


@app.get("/oauth/callback")
def oauth_callback(request: Request):
    """Redirect target for the authorization code flow."""
    params = request.query_params
    state = params.get("state", "")
    message = "Authorization complete. Return to the Namazu tab; the token has been collected."
    try:
        result = oauth.complete_authorization(
            state=state, code=params.get("code", ""), error=params.get("error", ""),
            error_description=params.get("error_description", ""),
        )
        if result["status"] == "error":
            message = f"Authorization failed: {result['error']}"
    except ValueError as exc:
        message = str(exc)
    page = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<title>Namazu authorization</title>"
        '<link rel="stylesheet" href="/static/style.css"></head>'
        '<body class="callback-page"><main class="callback"><h1>Namazu</h1>'
        f"<p>{html.escape(message)}</p>"
        '<p><a href="/">Back to the workbench</a></p></main></body></html>'
    )
    return HTMLResponse(page)


@app.get("/api/tools")
def tools():
    """Which optional second-opinion tools this machine can run."""
    return external.available()


@app.post("/api/tools/run")
def run_tool(body: AuditInput):
    name = (body.profile or "").strip()
    target = body.base_url or ""
    if not target:
        raise ValueError("Set a base URL before running an external tool")
    headers = (body.identities or {}).get("primary") or {}
    if name == "nuclei":
        return external.run_nuclei(target=target, headers=headers, verify_tls=body.verify_tls)
    if name == "schemathesis":
        source = (body.spec or {}).get("source_url") or ""
        if not source:
            raise ValueError("schemathesis needs the specification URL; import by URL to use it")
        return external.run_schemathesis(schema=source, base_url=target, headers=headers,
                                         allow_mutating=body.allow_mutating,
                                         verify_tls=body.verify_tls)
    raise ValueError("Unknown tool; use schemathesis or nuclei")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
