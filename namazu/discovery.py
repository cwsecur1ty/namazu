"""Find OpenAPI documents behind Swagger UI/ReDoc pages without executing scripts.

Discovery patterns derive from K9's Swagger importer; this module has no K9 dependencies.
"""
from __future__ import annotations

import html
import json
import re
import time
from contextlib import nullcontext
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import yaml

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_FETCHES = 24


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
                   timeout: float = 15, client: httpx.Client | None = None) -> tuple[dict, str, list[str]]:
    """Bounded same-origin credential use; foreign definitions receive no supplied headers."""
    check_url(url)
    headers = check_headers(headers or {})
    credential_origin = origin(url)
    pending = [url]
    visited = set()
    warnings = []
    used_conventional_paths = False
    deadline = time.monotonic() + min(max(timeout, 1) * 3, 120)
    context = nullcontext(client) if client is not None else httpx.Client(verify=verify_tls, trust_env=False)
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
                # Request() avoids client cookie jars/default headers persisting between fetches.
                request = httpx.Request("GET", current, headers=scoped_headers,
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
