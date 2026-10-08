"""Find OpenAPI documents behind Swagger UI/ReDoc pages without executing scripts.

Discovery patterns derive from K9's Swagger importer; this module has no K9 dependencies.
"""
from __future__ import annotations

import html
import json
import os
import re
import time
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import yaml

from . import __version__
from .signature import BROWSER_USER_AGENT

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_FETCHES = 24

# httpx identifies itself as python-httpx/<version>, which a WAF in front of
# the target commonly refuses outright: the operator sees a block page instead
# of a token. Namazu says what it is instead, and an engagement that needs a
# different value can set one.
DEFAULT_USER_AGENT = f"Namazu/{__version__} (+https://github.com/cwsecur1ty/namazu)"


# Headers a security product adds to its own block page. None of these belong
# to an API's own error response, so one of them plus a refusal status is a
# reliable way to say which hop answered.
WAF_HEADERS = {
    "x-iinfo": "Imperva",
    "x-cdn": "Imperva",
    "cf-ray": "Cloudflare",
    "cf-mitigated": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "akamai-grn": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-amz-apigw-id": "AWS",
    "x-amzn-waf-action": "AWS WAF",
    "x-azure-ref": "Azure Front Door",
}
# Wording block pages use. "Support ID" and "Ray ID" are the reference numbers
# Imperva and Cloudflare tell you to quote, so they are worth pulling out.
WAF_BODY = re.compile(
    r"(?i)(blocked by our security service|request (?:was |has been )?blocked|"
    r"attention required|access denied|incapsula|cloudflare|akamai|"
    r"unusual (?:traffic|activity)|bot ?detect|security policy)")
WAF_REFERENCE = re.compile(
    r"(?i)(support id|ray id|reference (?:number|id))(?:\s+is)?[:\s#]*([0-9a-z-]{6,40})")


def describe_block(status: int, headers: dict, body: str) -> str:
    """Say so when a response is a security product refusing the request.

    Returns an empty string when nothing suggests one, so the caller can fall
    back to reporting the response on its own terms.
    """
    lowered = {str(name).lower(): str(value) for name, value in (headers or {}).items()}
    vendors = sorted({label for header, label in WAF_HEADERS.items() if header in lowered})
    sample = (body or "")[:4000]
    wording = WAF_BODY.search(sample)
    if not vendors and not wording:
        return ""
    reference = WAF_REFERENCE.search(sample)
    who = " or ".join(vendors) if vendors else "a security service"
    parts = [
        f"HTTP {status} came from {who}, not from the authorization server. "
        "The request was refused before it arrived, so this is not an OAuth error "
        "and no credential of yours was rejected."
    ]
    if wording:
        parts.append(f"The response says: \u201c{wording.group(0)}\u201d.")
    if reference:
        parts.append(f"Quote {reference.group(1)} {reference.group(2)} if you raise it with them.")
    if vendors:
        shown = ", ".join(f"{name}: {lowered[name]}" for name in sorted(lowered)
                          if name in WAF_HEADERS)
        parts.append(f"Identifying headers: {shown}.")
    return " ".join(parts)


def client_headers(user_agent: str | None = None, *, quiet: bool = False) -> dict:
    """Default headers for any client Namazu builds.

    A user agent the operator typed always wins. ``quiet`` only changes what is
    sent when they typed nothing, so turning the mode on never overrides a
    value chosen for the engagement.
    """
    fallback = BROWSER_USER_AGENT if quiet else DEFAULT_USER_AGENT
    chosen = str(user_agent or "").strip() or fallback
    if "\r" in chosen or "\n" in chosen:
        raise ValueError("The user agent cannot contain line breaks")
    return {"User-Agent": chosen}


# Proxy schemes httpx can route through. socks5 needs the socksio package,
# which is not a dependency, so open() turns its ImportError into advice.
PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")


@dataclass(frozen=True)
class Connection:
    """How Namazu's requests leave this machine.

    One object shared by every client Namazu builds, so a path configured once
    holds for the spec fetch, the token exchange, the single request and every
    audit probe alike.

    The proxy and the CA bundle belong together: an intercepting proxy presents
    its own certificate, so a proxy set without its CA turns every HTTPS probe
    into a verification error, which reads like a broken target rather than a
    missing setting.
    """

    verify_tls: bool = True
    user_agent: str | None = None
    # Whether the requests name this tool. See namazu/signature.py; it travels
    # on the connection because the spec fetch and the token exchange have to
    # be as quiet as the probes, or the first request gives the run away.
    quiet: bool = False
    proxy: str | None = None
    ca_bundle: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    # Kept out of repr(). A dataclass repr reaches tracebacks, and a traceback
    # is the thing an operator pastes into a ticket.
    client_key_password: str | None = field(default=None, repr=False)

    @classmethod
    def build(cls, *, verify_tls: bool = True, user_agent: str | None = None,
              quiet: bool = False, proxy: str | None = None, ca_bundle: str | None = None,
              client_cert: str | None = None, client_key: str | None = None,
              client_key_password: str | None = None) -> Connection:
        """Construct from operator input, where a blank field means unset."""
        def clean(value):
            return (str(value).strip() or None) if value is not None else None

        return cls(
            verify_tls=bool(verify_tls), user_agent=clean(user_agent), quiet=bool(quiet),
            proxy=clean(proxy),
            ca_bundle=clean(ca_bundle), client_cert=clean(client_cert),
            client_key=clean(client_key),
            # Not stripped: whitespace can be part of a passphrase.
            client_key_password=(client_key_password or None),
        )

    @property
    def routed(self) -> bool:
        """Whether traffic leaves through something other than a direct connection."""
        return self.proxy is not None

    def describe(self) -> str:
        """A line for a report, naming the path without naming any secret."""
        parts = []
        if self.proxy:
            parts.append(f"through the proxy at {self.proxy}")
        if self.ca_bundle:
            parts.append("verifying TLS against the supplied CA bundle")
        elif not self.verify_tls:
            parts.append("without verifying TLS")
        if self.client_cert:
            parts.append("presenting a client certificate")
        return "Requests were sent " + ", ".join(parts) + "." if parts else ""

    def validate(self) -> None:
        """Fail on a bad setting now, rather than on the first probe."""
        if self.proxy is not None:
            try:
                parts = urlsplit(self.proxy)
                port = parts.port  # noqa: F841  see check_url
            except ValueError as exc:
                raise ValueError(f"The proxy URL is not valid: {self.proxy}") from exc
            if parts.scheme not in PROXY_SCHEMES or not parts.hostname:
                raise ValueError(
                    "The proxy must be an http://, https:// or socks5:// URL with a host, "
                    "for example http://127.0.0.1:8080 for Burp's default listener")
        if self.client_key is not None and self.client_cert is None:
            raise ValueError("A client key needs the certificate that goes with it")
        if self.client_key_password is not None and self.client_key is None:
            raise ValueError("A client key password needs the key file it unlocks")
        for label, path in (("CA bundle", self.ca_bundle),
                            ("client certificate", self.client_cert),
                            ("client key", self.client_key)):
            if path is not None and not os.path.isfile(path):
                raise ValueError(f"The {label} file was not found: {path}")

    def open(self) -> httpx.Client:
        """A client configured for this connection. Callers close it."""
        self.validate()
        # An explicit opt-out of verification wins over a CA bundle: asking for
        # both is contradictory, and the one that disables a control is the one
        # the operator typed on purpose.
        verify = False if not self.verify_tls else (self.ca_bundle or True)
        cert: object = None
        if self.client_cert is not None:
            if self.client_key is None:
                cert = self.client_cert
            elif self.client_key_password is None:
                cert = (self.client_cert, self.client_key)
            else:
                cert = (self.client_cert, self.client_key, self.client_key_password)
        try:
            return httpx.Client(verify=verify, cert=cert, proxy=self.proxy, trust_env=False,
                                headers=client_headers(self.user_agent, quiet=self.quiet))
        except ImportError as exc:
            raise ValueError(
                "Routing through a socks5 proxy needs the socksio package: "
                "pip install 'httpx[socks]'") from exc


def connection_for(connection: Connection | None, verify_tls: bool = True,
                   user_agent: str | None = None, quiet: bool = False) -> Connection:
    """The connection to use, from an explicit one or the older two arguments.

    Every entry point still accepts ``verify_tls`` and ``user_agent`` directly,
    so this keeps one meaning for both spellings instead of two code paths.
    """
    if connection is None:
        return Connection(verify_tls=verify_tls, user_agent=user_agent, quiet=quiet)
    if user_agent and not connection.user_agent:
        return replace(connection, user_agent=user_agent)
    return connection


def check_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        # Reading the port is the check: urlsplit defers parsing it, so this is
        # what makes a malformed port raise. Do not remove it as unused.
        port = parts.port  # noqa: F841
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Enter an absolute HTTP or HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Put credentials in headers instead of the URL")
    return url


def origin(url: str) -> tuple:
    parts = urlsplit(check_url(url))
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def check_headers(headers: dict) -> dict:
    if len(headers) > 100:
        raise ValueError("Use at most 100 request headers")
    result = {}
    for key, value in headers.items():
        if not isinstance(value, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise ValueError("Headers need valid names and string values")
        if "\r" in value or "\n" in value or len(value) > 16384:
            raise ValueError("Header values cannot contain line breaks or exceed 16 KiB")
        if key.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "upgrade"}:
            raise ValueError(f"Namazu manages the {key} header automatically")
        result[key] = value
    return result


def read_bounded(response: httpx.Response, limit: int, *, deadline: float | None = None) -> tuple[bytes, bool]:
    data = bytearray()
    # Consume transport chunks as they arrive. Buffering up to 64 KiB here can
    # hide a slow trickle from the overall deadline for arbitrarily long.
    for chunk in response.iter_bytes():
        if deadline is not None and time.monotonic() >= deadline:
            raise httpx.ReadTimeout("Response exceeded the request time limit")
        available = limit - len(data)
        data.extend(chunk[:available])
        if len(chunk) > available:
            return bytes(data), True
    if deadline is not None and time.monotonic() >= deadline:
        raise httpx.ReadTimeout("Response exceeded the request time limit")
    return bytes(data), False


def _decode(raw: str):
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        try:
            return yaml.safe_load(raw)
        except (yaml.YAMLError, RecursionError, ValueError):
            return None


def _is_document(value) -> bool:
    return isinstance(value, dict) and ("openapi" in value or "swagger" in value)


def _candidates(raw: str, url: str, value, conventional: bool) -> list[str]:
    candidates = list(parse_qs(urlsplit(url).query).get("url", []))
    candidates += parse_qs(urlsplit(url).query).get("configUrl", [])
    if isinstance(value, dict):
        for name in ("url", "configUrl"):
            if isinstance(value.get(name), str):
                candidates.append(value[name])
        for item in value.get("urls", []) if isinstance(value.get("urls"), list) else []:
            if isinstance(item, dict) and isinstance(item.get("url"), str):
                candidates.append(item["url"])
    decoded = html.unescape(raw).replace(r'\/', '/').replace(r'\"', '"')
    decoded = re.sub(r"\\u002[fF]|\\x2[fF]", "/", decoded)
    decoded = re.sub(r"\\u003[aA]|\\x3[aA]", ":", decoded)
    decoded = re.sub(r"\\u0026|\\x26", "&", decoded)
    patterns = [r'''["']?(?:url|configUrl|specUrl|openapi_url)["']?\s*:\s*["']([^"']+)["']''',
                r'''spec-url\s*=\s*["']([^"']+)["']''',
                r'''SwaggerEndpoint\s*\(\s*["']([^"']+)["']''']
    for pattern in patterns:
        candidates.extend(re.findall(pattern, decoded, re.I))
    for script in re.findall(r'''<script[^>]+src=["']([^"']+)["']''', decoded, re.I):
        name = urlsplit(script).path.rsplit("/", 1)[-1].lower()
        if name == "index.js" or "swagger-initializer" in name or "swagger-ui-init" in name:
            candidates.append(script)
    if conventional:
        path = urlsplit(url).path
        root = re.split(r"/(?:swagger(?:-ui)?|docs|redoc|api-docs)(?:/|$)", path, maxsplit=1, flags=re.I)[0]
        base = urljoin(url, root.rstrip("/") + "/")
        for name in ("openapi.json", "swagger.json", "swagger/v1/swagger.json", "v3/api-docs/swagger-config", "v3/api-docs"):
            candidates.append(urljoin(base, name))
        candidates.extend(urljoin(url, name) for name in ("v1/swagger.json", "openapi.json", "swagger.json"))
    return list(dict.fromkeys(urljoin(url, item.strip()) for item in candidates if item.strip()))


def fetch_document(url: str, *, headers: dict | None = None, verify_tls: bool = True,
                   timeout: float = 15, client: httpx.Client | None = None,
                   user_agent: str | None = None,
                   connection: Connection | None = None) -> tuple[dict, str, list[str]]:
    """Bounded same-origin credential use; foreign definitions receive no supplied headers."""
    check_url(url)
    link = connection_for(connection, verify_tls, user_agent)
    user_agent = link.user_agent
    headers = check_headers(headers or {})
    credential_origin = origin(url)
    pending = [url]
    visited = set()
    warnings = []
    used_conventional_paths = False
    deadline = time.monotonic() + min(max(timeout, 1) * 3, 120)
    context = nullcontext(client) if client is not None else link.open()
    with context as http:
        while pending and len(visited) < MAX_FETCHES:
            current = pending.pop(0)
            if current in visited:
                continue
            visited.add(current)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warnings.append("Documentation discovery reached its time limit")
                break
            try:
                current_origin = origin(current)
                scoped_headers = headers if current_origin == credential_origin else {}
                if headers and current_origin != credential_origin:
                    warnings.append("Documentation headers were omitted for a different origin")
                # Request() avoids client cookie jars/default headers persisting between
                # fetches. The user agent is not a credential, so it rides along on every
                # fetch; anything the caller set explicitly still wins.
                request = httpx.Request("GET", current,
                                        headers={**client_headers(user_agent), **scoped_headers},
                                        extensions={"timeout": dict.fromkeys(("connect", "read", "write", "pool"), min(timeout, remaining))})
                request_deadline = min(deadline, time.monotonic() + timeout)
                response = http.send(request, stream=True, follow_redirects=False, auth=None)
                try:
                    if response.status_code in (301, 302, 303, 307, 308):
                        if response.headers.get("location"):
                            pending.insert(0, urljoin(current, response.headers["location"]))
                        continue
                    if response.status_code != 200:
                        if current == url:
                            raise ValueError(f"Documentation returned HTTP {response.status_code}. Check its URL and headers.")
                        continue
                    data, truncated = read_bounded(response, MAX_DOCUMENT_BYTES, deadline=request_deadline)
                finally:
                    response.close()
                if truncated:
                    raise ValueError("Documentation exceeds the 8 MiB limit")
            except httpx.HTTPError:
                if current == url:
                    raise ValueError("Could not fetch documentation. Check the address, TLS settings and timeout.") from None
                continue
            except ValueError:
                if current == url:
                    raise
                continue
            raw = data.decode("utf-8-sig", errors="replace")
            value = _decode(raw)
            if _is_document(value):
                return value, current, list(dict.fromkeys(warnings))
            # Inline SwaggerUIBundle({spec: { ...JSON... }}) is common in static docs.
            for match in re.finditer(r'''["']?spec["']?\s*:\s*(?=\{)''', raw):
                try:
                    embedded, _ = json.JSONDecoder().raw_decode(raw[match.end():])
                    if _is_document(embedded):
                        return embedded, current, list(dict.fromkeys(warnings))
                except (ValueError, RecursionError):
                    pass
            is_html = "<html" in raw[:2000].lower() or "swagger" in raw.lower() or "<redoc" in raw.lower()
            # The initial URL often redirects to the actual documentation page.
            # Try fallback paths once, relative to that page rather than only the input URL.
            conventional = is_html and not used_conventional_paths
            candidates = _candidates(raw, current, value, conventional=conventional)
            used_conventional_paths = used_conventional_paths or conventional
            # Follow explicit configuration chains before trying fallback paths.
            pending = [item for item in candidates if item not in visited] + pending
    raise ValueError("No OpenAPI document found. Supply a direct JSON/YAML URL or paste the specification; this page may need browser login or unsupported JavaScript configuration.")
