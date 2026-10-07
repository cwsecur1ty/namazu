"""Access-control bypass probes, and cache deception.

These only run where there is something to bypass: a route that answered 401 or
403. Each variant is a single read-only GET that an ordinary client could send
by accident, so nothing here changes state or carries a payload.

The useful property of this family is that a positive result is unambiguous.
The baseline already proved the route refuses the caller; if a trivially
different form of the same request returns data, the control is attached to the
request shape rather than to the resource.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from .model import Exchange, finding, mark, similarity
from .transport import BudgetExhausted, Executor

# Path rewrites that some servers, proxies and frameworks normalise differently
# from the component that made the authorization decision.
PATH_VARIANTS = (
    ("trailing slash", lambda path: path + "/" if not path.endswith("/") else path.rstrip("/")),
    ("duplicated separator", lambda path: "/" + path.lstrip("/").replace("/", "//", 1)),
    ("current-directory segment", lambda path: _insert_before_last(path, ".")),
    ("encoded separator", lambda path: path.replace("/", "%2f", 1) if path.count("/") > 1 else path),
    ("matrix parameter", lambda path: path + ";namazu=1"),
    ("case change", lambda path: _swap_case_last(path)),
)
# Headers a reverse proxy may set, which an application sometimes trusts.
HEADER_VARIANTS = (
    ("X-Original-URL", lambda path: path),
    ("X-Rewrite-URL", lambda path: path),
    ("X-Forwarded-For", lambda _path: "127.0.0.1"),
    ("X-Real-IP", lambda _path: "127.0.0.1"),
    ("X-Custom-IP-Authorization", lambda _path: "127.0.0.1"),
    ("X-Originating-IP", lambda _path: "127.0.0.1"),
)
CACHEABLE = re.compile(r"(?i)\b(public|max-age=[1-9])")


def _insert_before_last(path: str, segment: str) -> str:
    parts = path.rstrip("/").split("/")
    if len(parts) < 2:
        return path
    return "/".join(parts[:-1] + [segment, parts[-1]])


def _swap_case_last(path: str) -> str:
    parts = path.rstrip("/").split("/")
    last = parts[-1]
    if not last or not last.isalpha():
        return path
    parts[-1] = last.upper() if last.islower() else last.lower()
    return "/".join(parts)


def _with_path(url: str, path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def _is_data(exchange: Exchange) -> bool:
    return exchange.ok and 200 <= exchange.status < 300 and len(exchange.body.strip()) > 2


def probe(executor: Executor, *, baseline: Exchange, endpoint: str, headers: dict) -> list:
    """Try to reach a refused route by changing the request rather than the caller."""
    if baseline.status not in (401, 403) or baseline.method not in ("GET", "HEAD"):
        return []
    findings: list = []
    path = urlsplit(baseline.url).path
    try:
        findings += _path_variants(executor, baseline, endpoint, headers, path)
        findings += _header_variants(executor, baseline, endpoint, headers, path)
    except BudgetExhausted:
        pass
    return findings


def _rewrite(build, path: str) -> str | None:
    try:
        variant = build(path)
    except (IndexError, ValueError):
        return None
    return variant if variant and variant != path else None


def _path_variants(executor, baseline, endpoint, headers, path) -> list:
    """Six rewrites of the same refused path, each a single independent GET."""
    def one(branch, item):
        label, build = item
        variant = _rewrite(build, path)
        if variant is None or not branch.affordable(1):
            return None
        return branch.send(
            baseline.method, _with_path(baseline.url, variant),
            label=f"access control bypass: {label}", headers=headers, identity="identity A",
        )

    for (label, build), probe_exchange in zip(PATH_VARIANTS,
                                              executor.fan_out(PATH_VARIANTS, one)):
        if probe_exchange is None or not _is_data(probe_exchange):
            continue
        variant = _rewrite(build, path)
        return [finding(
            "authz.path-bypass", f"Refused route is reachable with a {label}",
            "high", "confirmed", owasp="API5:2023 Broken Function Level Authorization",
            endpoint=endpoint, parameter=label,
            method=(f"The baseline returned HTTP {baseline.status} for {path}. The same request to "
                    f"{variant}, differing only by a {label}, was sent and compared."),
            detail=(f"{path} returned HTTP {baseline.status}, but {variant} returned HTTP "
                    f"{probe_exchange.status} with a {len(probe_exchange.body)}-byte body. The two "
                    "paths address the same resource; only the string differs."),
            background=(
                "Authorization is often enforced at a different layer from the one that resolves the "
                "path: a gateway, a reverse proxy, or a framework filter matching on a literal string. "
                "Where that layer normalises the path differently from the component behind it, a form "
                "the filter does not recognise reaches a handler that resolves it to the protected "
                "resource anyway."),
            impact=("The access control on this route can be skipped by rewriting the path, so it "
                    "protects a string rather than a resource."),
            remediation=("Normalise the path once, at the edge, before any authorization decision is "
                         "made, and apply the rule to the resolved route rather than to a literal "
                         "pattern. Reject requests whose normalised form differs from what was sent."),
            highlights=[
                mark(variant, "attacker", "The path form that was allowed through."),
                mark("only the string differs", "proof",
                     "Both forms resolve to the same resource, so the control is not on the resource."),
            ],
            evidence={"documented_path": path, "bypass_path": variant, "variant": label,
                      "baseline_status": baseline.status, "bypass_status": probe_exchange.status,
                      "bypass_length": len(probe_exchange.body)},
            exchanges=[baseline, probe_exchange],
        )]
    return []


def _header_variants(executor, baseline, endpoint, headers, path) -> list:
    """Six forwarding headers an application sometimes trusts, one request each."""
    def one(branch, item):
        name, build = item
        if not branch.affordable(1):
            return None
        return branch.send(
            baseline.method, baseline.url, label=f"access control bypass: {name}",
            headers={**headers, name: build(path)}, identity="identity A",
        )

    for (name, build), probe_exchange in zip(HEADER_VARIANTS,
                                             executor.fan_out(HEADER_VARIANTS, one)):
        if probe_exchange is None or not _is_data(probe_exchange):
            continue
        return [finding(
            "authz.header-bypass", f"Refused route is reachable by sending {name}",
            "high", "confirmed", owasp="API5:2023 Broken Function Level Authorization",
            endpoint=endpoint, parameter=name,
            method=(f"The baseline returned HTTP {baseline.status}. The same request was repeated with "
                    f"{name}: {build(path)} added and nothing else changed."),
            detail=(f"Adding the request header {name}: {build(path)} changed the response from HTTP "
                    f"{baseline.status} to HTTP {probe_exchange.status} with a "
                    f"{len(probe_exchange.body)}-byte body."),
            background=(
                "Reverse proxies use headers of this kind to pass the original request details to the "
                "application behind them. The headers carry no authentication, so an application that "
                "trusts them is trusting whatever the client sent, unless the edge strips and re-adds "
                "them on every request."),
            impact=("Any client can present the header and be treated as an internal or already "
                    "authorized caller."),
            remediation=(f"Strip {name} and the other X-Forwarded and X-Original headers from inbound "
                         "requests at the edge, then set them yourself. Do not route or authorize on a "
                         "header value a client can choose."),
            highlights=[
                mark(name, "attacker", "The header Namazu added. Nothing else about the request changed."),
            ],
            evidence={"header": name, "value": build(path), "baseline_status": baseline.status,
                      "bypass_status": probe_exchange.status,
                      "bypass_length": len(probe_exchange.body)},
            exchanges=[baseline, probe_exchange],
        )]
    return []


def cache_deception(executor: Executor, *, baseline: Exchange, endpoint: str, headers: dict) -> list:
    """Does a static-looking suffix turn an authenticated response into a cacheable one?"""
    if baseline.method != "GET" or not _is_data(baseline) or not executor.affordable(1):
        return []
    if not any(name.lower() in ("authorization", "cookie") for name in headers):
        return []
    path = urlsplit(baseline.url).path.rstrip("/")
    probe_exchange = executor.send(
        "GET", _with_path(baseline.url, f"{path}/namazu-probe.css"),
        label="cache deception: static suffix", headers=headers, identity="identity A",
    )
    if not _is_data(probe_exchange):
        return []
    if similarity(baseline.body, probe_exchange.body) < 0.9:
        return []
    cache = probe_exchange.header("cache-control")
    cacheable = CACHEABLE.search(cache or "") or not cache
    if not cacheable:
        return []
    return [finding(
        "cache.deception", "Authenticated response is served under a static-looking path",
        "medium", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        method=(f"Requested {path}/namazu-probe.css with the same credentials, then compared the body "
                "with the baseline and read the Cache-Control header of the response."),
        detail=(f"Appending /namazu-probe.css to the path still returned the authenticated body "
                f"(HTTP {probe_exchange.status}, {int(similarity(baseline.body, probe_exchange.body) * 100)}% "
                f"similar) with Cache-Control: {cache or '(absent)'}. The server ignored the extra "
                "segment but a cache keying on the extension would not."),
        background=(
            "Web cache deception relies on two components disagreeing about what a URL means. The "
            "application ignores a trailing segment and serves the user's page; a CDN or reverse proxy "
            "sees a .css suffix, treats the response as a static asset, and stores it under a URL an "
            "attacker chose. The attacker then requests that URL and is served the victim's content."),
        impact=("If a cache in front of this API stores the response, one user's authenticated data can "
                "be served to anyone who requests the same crafted path."),
        limitations=("Namazu observed that the application ignores the appended segment and that the "
                     "response is not marked private. It did not confirm that a cache is present in "
                     "front of this host or that it would store the response. Check the CDN or proxy "
                     "configuration to complete this finding."),
        remediation=("Return 404 for paths the route does not define rather than ignoring extra "
                     "segments, send Cache-Control: no-store on authenticated responses, and configure "
                     "caches to key on the full path and to never store responses to credentialed "
                     "requests."),
        highlights=[mark("/namazu-probe.css", "attacker", "The suffix Namazu appended; the server ignored it.")],
        evidence={"probe_path": f"{path}/namazu-probe.css", "status": probe_exchange.status,
                  "body_similarity": similarity(baseline.body, probe_exchange.body),
                  "cache_control": cache or None},
        exchanges=[baseline, probe_exchange],
    )]
