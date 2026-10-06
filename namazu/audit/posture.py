"""Host posture checks: TLS, dangerous methods, framing and resource limits.

These sit between the passive single-response review and the per-parameter
probes. Each one is a small, read-only experiment with a clear pass condition,
and each reports what it compared so the result can be re-derived by hand.
"""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .model import Exchange, finding
from .transport import BudgetExhausted, Executor

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
RATE_HEADERS = ("ratelimit", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
                "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit",
                "retry-after", "x-rate-limit-remaining")
PAGINATION_NAMES = ("limit", "per_page", "perPage", "page_size", "pageSize", "size",
                    "count", "max_results", "maxResults", "top", "rows")


# ── TLS ──────────────────────────────────────────────────────────────────────

def inspect_tls(base_url: str, *, timeout: float = 10.0) -> list:
    """Look at the certificate the host presents. Costs no HTTP request."""
    parts = urlsplit(base_url)
    if parts.scheme != "https" or not parts.hostname:
        return []
    host = parts.hostname
    port = parts.port or 443
    endpoint = f"{host}:{port}"
    findings: list = []

    # A verifying handshake first: it is the question an ordinary client asks.
    context = ssl.create_default_context()
    verified, verify_error = True, ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                certificate = tls.getpeercert()
                protocol = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, str(exc)
        certificate, protocol, cipher = None, None, None
    except (OSError, ssl.SSLError) as exc:
        return [finding(
            "tls.certificate", "TLS handshake failed",
            "info", "confirmed", owasp="API8:2023 Security Misconfiguration",
            endpoint=endpoint,
            method=f"Opened a TLS connection to {endpoint} and read the handshake result.",
            detail=f"Namazu could not complete a TLS handshake with {endpoint}: {exc}.",
            impact="The transport could not be assessed.",
            remediation="Confirm the host is reachable and serving TLS on this port.",
            evidence={"host": host, "port": port, "error": str(exc)}, scope="host",
        )]

    if not verified:
        # Repeat without verification purely to read what was presented.
        permissive = ssl.create_default_context()
        permissive.check_hostname = False
        permissive.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with permissive.wrap_socket(raw, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    protocol = tls.version()
                    cipher = tls.cipher()
            certificate = _decode_certificate(der)
        except (OSError, ssl.SSLError):
            certificate = None
        findings.append(finding(
            "tls.certificate", "TLS certificate does not validate",
            "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            method=(f"Opened a TLS connection to {endpoint} using the system trust store with hostname "
                    "verification enabled, and recorded the verification error."),
            detail=f"The certificate presented by {endpoint} failed verification: {verify_error.strip()}.",
            impact=("Clients that verify correctly cannot connect, so integrations are pushed towards "
                    "disabling verification, and a client that does not verify cannot distinguish the "
                    "real host from an interceptor."),
            remediation=("Install a certificate from a trusted CA covering the exact hostname clients use, "
                         "including every SAN entry, and serve the full intermediate chain."),
            evidence={"host": host, "port": port, "verification_error": verify_error.strip(),
                      "protocol": protocol, **(certificate or {})}, scope="host",
        ))
        return findings

    expiry = _expiry(certificate)
    if expiry is not None:
        days = (expiry - datetime.now(timezone.utc)).days
        if days < 0:
            findings.append(finding(
                "tls.certificate", "TLS certificate has expired",
                "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
                method=f"Read notAfter from the certificate {endpoint} presented during the handshake.",
                detail=f"The certificate expired {abs(days)} day(s) ago, on {expiry:%Y-%m-%d}.",
                impact="Verifying clients refuse the connection; users are trained to click through warnings.",
                remediation="Renew the certificate and automate renewal so it cannot lapse again.",
                evidence={"host": host, "not_after": expiry.isoformat(), "days_remaining": days,
                          **_names(certificate)}, scope="host",
            ))
        elif days < 21:
            findings.append(finding(
                "tls.certificate", f"TLS certificate expires in {days} day(s)",
                "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
                method=f"Read notAfter from the certificate {endpoint} presented during the handshake.",
                detail=f"The certificate is valid until {expiry:%Y-%m-%d}, which is {days} day(s) away.",
                impact="An expiry during business hours takes every verifying client offline at once.",
                remediation="Renew now and automate renewal.",
                evidence={"host": host, "not_after": expiry.isoformat(), "days_remaining": days,
                          **_names(certificate)}, scope="host",
            ))

    if protocol in WEAK_PROTOCOLS:
        findings.append(finding(
            "tls.certificate", f"Connection negotiated {protocol}",
            "medium", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            method=f"Recorded the protocol version negotiated with {endpoint} by a default client.",
            detail=(f"The handshake settled on {protocol}. TLS 1.0 and 1.1 were deprecated by RFC 8996 and "
                    "are no longer accepted by current browsers and platform libraries."),
            impact="Deprecated versions lack modern cipher suites and carry known downgrade weaknesses.",
            remediation="Serve TLS 1.2 as a minimum, prefer TLS 1.3, and disable earlier versions.",
            evidence={"host": host, "protocol": protocol,
                      "cipher": cipher[0] if cipher else None}, scope="host",
        ))
    return findings


def _decode_certificate(der: bytes | None) -> dict:
    if not der:
        return {}
    try:
        text = ssl.DER_cert_to_PEM_cert(der)
    except ValueError:
        return {}
    return {"certificate_pem_length": len(text)}


def _expiry(certificate) -> datetime | None:
    if not certificate or "notAfter" not in certificate:
        return None
    try:
        return datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _names(certificate) -> dict:
    if not certificate:
        return {}
    def flatten(field):
        return {key: value for group in (certificate.get(field) or ()) for key, value in group}
    subject, issuer = flatten("subject"), flatten("issuer")
    return {"subject_cn": subject.get("commonName"), "issuer_cn": issuer.get("commonName")}


# ── dangerous methods ────────────────────────────────────────────────────────

def trace_enabled(executor: Executor, *, base_url: str, endpoint: str, headers: dict) -> list:
    """TRACE echoes the request back, including headers a client never meant to reveal."""
    if not executor.affordable(1):
        return []
    marker = "NamazuProbe"
    probe = executor.send("TRACE", base_url, label="TRACE request",
                          headers={**headers, "X-Namazu-Probe": marker}, identity="identity A")
    if not probe.ok or probe.status != 200:
        return []
    if marker not in (probe.body or ""):
        return []
    return [finding(
        "http.trace-enabled", "TRACE method is enabled",
        "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        method=("Sent a TRACE request carrying a unique header value and confirmed the server echoed "
                "that value back in the response body."),
        detail=(f"TRACE returned HTTP 200 and the response body contained the probe header "
                f"(X-Namazu-Probe: {marker}), so the server reflects the request it received."),
        impact=("Reflects headers the client sent, including cookies and Authorization, which historically "
                "enabled Cross-Site Tracing. It also serves no purpose in production."),
        remediation="Disable TRACE (and TRACK) at the web server, load balancer and application framework.",
        evidence={"status": probe.status, "echoed_header": f"X-Namazu-Probe: {marker}"},
        exchanges=[probe], scope="host",
    )]


def framing_controls(baseline: Exchange, endpoint: str) -> list:
    """Only meaningful when the API hands a browser something renderable."""
    if "html" not in baseline.content_type:
        return []
    frame_options = baseline.header("x-frame-options")
    csp = baseline.header("content-security-policy")
    if frame_options or "frame-ancestors" in csp.lower():
        return []
    return [finding(
        "clickjacking.missing-frame-controls", "HTML response allows framing by any site",
        "low", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        detail=(f"The response is {baseline.content_type} but sets neither X-Frame-Options nor a "
                "Content-Security-Policy frame-ancestors directive."),
        impact="Any site can frame this page and overlay it, so clicks can be redirected to actions here.",
        remediation="Send Content-Security-Policy: frame-ancestors 'none' (or an explicit allow-list).",
        evidence={"content_type": baseline.content_type,
                  "x_frame_options": frame_options or None,
                  "content_security_policy": csp or None},
        exchanges=[baseline], scope="host",
    )]


def downgrade_redirect(baseline: Exchange, endpoint: str) -> list:
    """An HTTPS route that sends the client to HTTP."""
    if baseline.status not in (301, 302, 303, 307, 308):
        return []
    location = baseline.header("location")
    if not location.lower().startswith("http://"):
        return []
    if urlsplit(baseline.url).scheme != "https":
        return []
    return [finding(
        "transport.downgrade-redirect", "HTTPS endpoint redirects to plain HTTP",
        "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        detail=f"The HTTPS request returned HTTP {baseline.status} with Location: {location}.",
        impact=("The client is sent to an unencrypted destination, so the next request, carrying the same "
                "credentials, travels in clear text and can be intercepted or rewritten."),
        remediation="Redirect only to https:// targets and send Strict-Transport-Security.",
        evidence={"status": baseline.status, "location": location}, exchanges=[baseline], scope="host",
    )]


# ── resource limits ──────────────────────────────────────────────────────────

def _set_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(name, existing) for name, existing in parse_qsl(parts.query, keep_blank_values=True)
             if name != key]
    pairs.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def pagination_enforced(executor: Executor, *, baseline: Exchange, endpoint: str, headers: dict,
                        operation: dict) -> list:
    """Ask for an absurd page size and see whether the server caps it."""
    names = [p.get("name") for p in (operation.get("parameters") or [])
             if p.get("in") == "query" and p.get("name") in PAGINATION_NAMES]
    if not names or baseline.method != "GET" or not executor.affordable(1):
        return []
    name = names[0]
    probe = executor.send("GET", _set_query(baseline.url, name, "100000"),
                          label=f"{name}=100000", headers=headers, identity="identity A")
    if not probe.ok or probe.status >= 400:
        return []
    # A server that caps the page returns about the same amount of data as the baseline.
    grew = len(probe.body) > max(len(baseline.body) * 4, len(baseline.body) + 20000)
    if not grew:
        return []
    return [finding(
        "limits.pagination-not-enforced", "Collection size parameter is not capped",
        "medium", "confirmed", owasp="API4:2023 Unrestricted Resource Consumption",
        endpoint=endpoint, parameter=name,
        method=(f"Requested {name}=100000 and compared the response size with the baseline request. "
                f"Baseline returned {len(baseline.body)} bytes; the probe returned {len(probe.body)}."),
        detail=(f"Setting “{name}” to 100000 returned HTTP {probe.status} with "
                f"{len(probe.body)} bytes, against {len(baseline.body)} bytes for the default page. "
                "The server honoured the requested size rather than applying a maximum."),
        impact=("One request can force the server to read, serialise and transmit an unbounded result set. "
                "A handful of concurrent requests becomes a denial of service, and egress cost scales "
                "with whatever the caller asks for."),
        remediation=(f"Clamp “{name}” server-side to a documented maximum (commonly 100), return the "
                     "clamped value in the response metadata, and declare `maximum` in the contract."),
        evidence={"parameter": name, "requested": 100000, "baseline_bytes": len(baseline.body),
                  "probe_bytes": len(probe.body), "status": probe.status},
        exchanges=[baseline, probe],
    )]


def rate_limiting(executor: Executor, *, baseline: Exchange, endpoint: str, headers: dict,
                  burst: int = 8) -> list:
    """A short burst: enough to see a limiter, far too few to be a load test."""
    if baseline.method not in ("GET", "HEAD") or not executor.affordable(burst):
        return []
    if any(baseline.header(name) for name in RATE_HEADERS):
        return []  # The server already advertises a limit.
    statuses, exchanges = [], []
    started = time.monotonic()
    for index in range(burst):
        probe = executor.send(baseline.method, baseline.url,
                              label=f"burst request {index + 1} of {burst}",
                              headers=headers, identity="identity A")
        statuses.append(probe.status)
        if index in (0, burst - 1):
            exchanges.append(probe)
        if probe.status == 429 or any(probe.header(name) for name in RATE_HEADERS):
            return []
        if not probe.ok:
            return []
    elapsed = round(time.monotonic() - started, 2)
    if not all(200 <= status < 400 for status in statuses):
        return []
    return [finding(
        "limits.no-rate-limit", "No rate limiting observed on a short burst",
        "low", "possible", owasp="API4:2023 Unrestricted Resource Consumption", endpoint=endpoint,
        method=(f"Sent {burst} identical requests back to back in {elapsed}s and checked every response "
                "for HTTP 429, Retry-After or RateLimit headers. This is a deliberately small burst: it "
                "can show that a limiter is absent at this rate, not that none exists at a higher one."),
        detail=(f"All {burst} requests returned {sorted(set(statuses))} within {elapsed}s, and none carried "
                "a RateLimit, X-RateLimit or Retry-After header. No throttling is visible at this volume."),
        impact=("Without a limit, this route can be used for credential stuffing, enumeration or simple "
                "resource exhaustion. The absence of RateLimit headers also means legitimate clients "
                "cannot back off cooperatively."),
        remediation=("Apply a per-client and per-IP limit at the gateway, return HTTP 429 with Retry-After, "
                     "and advertise the budget with the RateLimit headers from RFC 9239bis. Apply tighter "
                     "limits to authentication and search routes."),
        evidence={"requests_sent": burst, "elapsed_seconds": elapsed, "statuses": sorted(set(statuses)),
                  "rate_limit_headers": "none observed",
                  "caveat": "a small burst cannot prove the absence of a higher-threshold limiter"},
        exchanges=exchanges,
    )]


def review(executor: Executor, *, baseline: Exchange, endpoint: str, headers: dict,
           operation: dict, base_url: str, do_rate_limit: bool = False) -> list:
    """Run the posture probes that need traffic."""
    out: list = []
    out += downgrade_redirect(baseline, endpoint)
    out += framing_controls(baseline, endpoint)
    try:
        out += trace_enabled(executor, base_url=base_url, endpoint=endpoint, headers=headers)
        out += pagination_enforced(executor, baseline=baseline, endpoint=endpoint,
                                   headers=headers, operation=operation)
        if do_rate_limit:
            out += rate_limiting(executor, baseline=baseline, endpoint=endpoint, headers=headers)
    except BudgetExhausted:
        pass
    return out
