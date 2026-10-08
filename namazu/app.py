"""Namazu's independent local web application. No K9 database or scanner required."""
import html
import ipaddress
import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import __version__, oauth
from .audit import (
    audit_inventory,
    audit_operation,
    capture,
    correlate,
    external,
    matrix,
    transport,
    zap,
)
from .audit.model import finding_from_dict
from .discovery import Connection, fetch_document
from .runner import execute_request, prepare_request
from .signature import Signature
from .spec import parse_spec, spec_hash

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


class ConnectionInput(BaseModel):
    """How requests leave this machine, shared by every endpoint that sends one.

    An authorised engagement runs through Burp or ZAP, so the proxy belongs on
    every route rather than on one of them. The certificate fields are paths on
    the machine running Namazu, which keeps key material off the wire.
    """

    model_config = ConfigDict(extra="forbid")
    verify_tls: bool = True
    timeout: float = Field(default=15, ge=1, le=120)
    # httpx would otherwise announce itself as python-httpx, which a WAF in
    # front of the target often refuses outright.
    user_agent: str | None = Field(default=None, max_length=512)
    # Whether the requests name this tool at all: the user agent, and every
    # probe marker, header and path. See namazu/signature.py. A user agent set
    # above still wins over the browser string this would otherwise send.
    quiet: bool = False
    # http://127.0.0.1:8080 is Burp's default listener.
    proxy: str | None = Field(default=None, max_length=512)
    # An intercepting proxy presents its own certificate, so trusting it needs
    # its CA. Without this, pointing at a proxy turns every HTTPS probe into a
    # verification error.
    ca_bundle: str | None = Field(default=None, max_length=1024)
    client_cert: str | None = Field(default=None, max_length=1024)
    client_key: str | None = Field(default=None, max_length=1024)
    client_key_password: str | None = Field(default=None, max_length=512)

    def connection(self) -> Connection:
        link = Connection.build(
            verify_tls=self.verify_tls, user_agent=self.user_agent, quiet=self.quiet,
            proxy=self.proxy,
            ca_bundle=self.ca_bundle, client_cert=self.client_cert,
            client_key=self.client_key, client_key_password=self.client_key_password)
        # Fail here, where the message reaches the operator as a 400, rather
        # than on the first probe as a transport error.
        link.validate()
        return link


class ImportInput(ConnectionInput):
    url: str | None = None
    raw_spec: str | None = None
    source_url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class RequestInput(ConnectionInput):
    spec: dict
    operation_id: str
    base_url: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    content_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    allow_mutating: bool = False

    def options(self):
        values = {"base_url": self.base_url, "parameters": self.parameters,
                  "content_type": self.content_type, "headers": self.headers}
        if "body" in self.model_fields_set:
            values["body"] = self.body
        return values


class AuditInput(ConnectionInput):
    spec: dict
    operation_id: str | None = None
    base_url: str | None = None
    profile: str = "readonly"
    identities: dict[str, dict] = Field(default_factory=dict)
    allow_mutating: bool = False
    budget: int = Field(default=60, ge=1, le=200)
    # None lets the profile choose. The engine caps the top end.
    concurrency: int | None = Field(default=None, ge=1, le=16)
    # What a successful response looks like for this operation, including the
    # case where the correct answer is a refusal. See audit/baseline.py.
    expectation: dict | None = None
    # A saved request to use as the baseline instead of one generated from the
    # schema, which carries the literal "string" wherever the contract
    # documents no example.
    example: dict | None = None


class ToolInput(ConnectionInput):
    """Running one external tool. Separate from AuditInput, which used to carry
    the tool name in its ``profile`` field, so a request could not say both
    which tool to run and what traffic policy to run it under."""

    tool: str
    spec: dict = Field(default_factory=dict)
    base_url: str | None = None
    identities: dict[str, dict] = Field(default_factory=dict)
    allow_mutating: bool = False
    max_examples: int = Field(default=20, ge=1, le=500)
    # nuclei knobs, previously unreachable from the UI.
    severities: str = "info,low,medium,high,critical"
    tags: str | None = None
    rate_limit: int = Field(default=50, ge=1, le=500)
    duration_minutes: int = Field(default=5, ge=1, le=60)


class ReplayInput(ConnectionInput):
    """Replaying one captured case. Credentials come from ``identities`` here
    and never from the case, which carries only an identity reference."""

    case: dict
    identities: dict[str, dict] = Field(default_factory=dict)
    attempts: int = Field(default=2, ge=1, le=5)
    allow_mutating: bool = False
    budget: int = Field(default=10, ge=1, le=50)


class SequenceInput(ConnectionInput):
    steps: list[dict]
    identities: dict[str, dict] = Field(default_factory=dict)
    variables: dict[str, str] = Field(default_factory=dict)
    allow_mutating: bool = False
    budget: int = Field(default=30, ge=1, le=120)


class MatrixInput(ConnectionInput):
    rows: list[dict]
    identities: dict[str, dict] = Field(default_factory=dict)
    allow_mutating: bool = False
    budget: int = Field(default=60, ge=1, le=200)


class CorrelateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[dict]


@app.exception_handler(ValueError)
async def value_error(_request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(httpx.HTTPError)
async def http_error(_request, exc):
    detail = "Request timed out; check the target and timeout setting" if isinstance(exc, httpx.TimeoutException) else "Could not send request; check the URL, TLS settings and target availability"
    return JSONResponse({"detail": detail}, status_code=502)


@app.get("/api/health")
def health():
    return {"status": "ok", "tool": "Namazu", "version": __version__}


@app.post("/api/import")
def import_document(body: ImportInput):
    if bool(body.url) == bool(body.raw_spec):
        raise ValueError("Provide either a documentation URL or a JSON/YAML specification")
    if body.url:
        document, source, warnings = fetch_document(body.url, headers=body.headers,
                                                  timeout=body.timeout,
                                                  connection=body.connection())
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
                           timeout=body.timeout, connection=body.connection(),
                           **body.options())


@app.post("/api/audit")
def audit(body: AuditInput):
    if not body.operation_id:
        raise ValueError("Choose an operation to audit")
    return audit_operation(body.spec, body.operation_id, base_url=body.base_url,
                           identities=body.identities, profile=body.profile,
                           allow_mutating=body.allow_mutating, timeout=body.timeout,
                           concurrency=body.concurrency, connection=body.connection(),
                           expectation=body.expectation, example=body.example)


@app.post("/api/replay")
def replay(body: ReplayInput):
    """Send a captured case again, up to ``attempts`` times.

    Subject to the same write policy and request budget a probe is: the
    executor is the only way out of this tool, and replay does not get a
    private one.
    """
    case = capture.CapturedCase.from_dict(body.case)
    link = body.connection()
    http = transport.build_client(connection=link)
    executor = transport.Executor(http, transport.Budget(body.budget), timeout=body.timeout,
                                  allow_mutating=body.allow_mutating,
                                  signature=Signature(quiet=link.quiet))
    try:
        result = capture.replay(case, executor=executor, identities=body.identities,
                                attempts=body.attempts, allow_mutating=body.allow_mutating)
    finally:
        http.close()
    return {**result.to_dict(), "case": case.to_dict(),
            "requests_sent": executor.budget.spent}


@app.post("/api/sequence")
def sequence(body: SequenceInput):
    """Run a user-defined request sequence, extracting values as it goes."""
    if not body.steps:
        raise ValueError("Add at least one step to the sequence")
    link = body.connection()
    http = transport.build_client(connection=link)
    executor = transport.Executor(http, transport.Budget(body.budget), timeout=body.timeout,
                                  allow_mutating=body.allow_mutating,
                                  signature=Signature(quiet=link.quiet))
    try:
        result = matrix.run_sequence(body.steps, executor=executor,
                                     identities=body.identities, variables=body.variables,
                                     allow_mutating=body.allow_mutating)
    finally:
        http.close()
    return {**result.to_dict(), "requests_sent": executor.budget.spent,
            "log": [item.to_dict() for item in executor.exchanges]}


@app.post("/api/matrix")
def permission_matrix(body: MatrixInput):
    """Run a permission matrix, after each identity's own positive control."""
    if not body.rows:
        raise ValueError("Add at least one row to the permission matrix")
    link = body.connection()
    http = transport.build_client(connection=link)
    executor = transport.Executor(http, transport.Budget(body.budget), timeout=body.timeout,
                                  allow_mutating=body.allow_mutating,
                                  signature=Signature(quiet=link.quiet))
    try:
        result = matrix.evaluate(body.rows, executor=executor, identities=body.identities,
                                 allow_mutating=body.allow_mutating)
    finally:
        http.close()
    return {**result, "requests_sent": executor.budget.spent,
            "log": [item.to_dict() for item in executor.exchanges]}


@app.post("/api/correlate")
def correlate_findings(body: CorrelateInput):
    """Merge duplicates across Namazu's own findings and the external tools'.

    Done here rather than in the browser because the decision needs the
    captured exchanges, and because "are these the same defect" is a judgement
    that should be testable.
    """
    items = [finding_from_dict(item) for item in body.findings]
    kept, notes = correlate.correlate(items)
    return {"findings": [item.to_dict() for item in kept], "notes": notes,
            "merged": len(items) - len(kept), "received": len(items)}


@app.post("/api/audit/inventory")
def audit_surface(body: AuditInput):
    return audit_inventory(body.spec, base_url=body.base_url, identities=body.identities,
                           timeout=body.timeout, budget=body.budget,
                           concurrency=body.concurrency, connection=body.connection())


class OAuthInput(ConnectionInput):
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


@app.post("/api/oauth/discover")
def oauth_discover(body: OAuthInput):
    result = {"from_spec": oauth.from_spec(body.spec) if isinstance(body.spec, dict) else []}
    if body.issuer:
        result["metadata"] = oauth.discover(body.issuer, timeout=body.timeout,
                                            connection=body.connection())
    return result


@app.post("/api/oauth/token")
def oauth_token(body: OAuthInput):
    """Grants that need no browser round trip."""
    if not body.token_endpoint:
        raise ValueError("Enter the token endpoint URL")
    shared = {"token_url": body.token_endpoint, "client_id": body.client_id,
              "client_secret": body.client_secret, "auth_style": body.auth_style,
              "timeout": body.timeout, "connection": body.connection()}
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
        timeout=body.timeout, connection=body.connection(),
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
            metadata = oauth.discover(body.issuer, timeout=body.timeout,
                                      connection=body.connection())
        except ValueError:
            metadata = None
    findings = oauth.probe_authorization_server(
        authorization_endpoint=body.authorization_endpoint, client_id=body.client_id,
        redirect_uri=redirect_uri, metadata=metadata,
        timeout=body.timeout, connection=body.connection(),
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
    """Which optional second-opinion tools this machine can run, and what each can do."""
    return {**external.available(), "zap": zap.available()}


@app.post("/api/tools/run")
def run_tool(body: ToolInput):
    name = (body.tool or "").strip().lower()
    target = body.base_url or ""
    if not target:
        raise ValueError("Set a base URL before running an external tool")
    headers = (body.identities or {}).get("primary") or {}
    source = (body.spec or {}).get("source_url") or ""
    schema_hash = spec_hash(body.spec) if body.spec else ""
    if name == "nuclei":
        return external.run_nuclei(target=target, headers=headers, verify_tls=body.verify_tls,
                                   severities=body.severities,
                                   tags=body.tags if body.tags is not None
                                   else external.DEFAULT_NUCLEI_TAGS,
                                   rate_limit=body.rate_limit)
    if name == "schemathesis":
        if not source:
            raise ValueError("schemathesis needs the specification URL; import by URL to use it")
        return external.run_schemathesis(schema=source, base_url=target, headers=headers,
                                         allow_mutating=body.allow_mutating,
                                         max_examples=body.max_examples,
                                         verify_tls=body.verify_tls, schema_hash=schema_hash)
    if name == "zap":
        if not source:
            raise ValueError("ZAP imports the specification by URL; import by URL to use it")
        return zap.run(target=target, schema=source, headers=headers,
                       allow_mutating=body.allow_mutating,
                       requests_per_second=body.rate_limit,
                       duration_minutes=body.duration_minutes, schema_hash=schema_hash)
    raise ValueError("Unknown tool; use schemathesis, nuclei or zap")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
