"""Shared types for the Namazu security audit.

Every probe produces :class:`Exchange` records and :class:`Finding` objects.
A finding carries the exchanges that proved it, so the UI and the JSON export
can render a replayable proof of concept without the engine formatting text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
import hashlib
import json
import re
import shlex

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("confirmed", "probable", "possible")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
CONFIDENCE_RANK = {name: index for index, name in enumerate(CONFIDENCES)}

# Header names whose values are replaced with a placeholder in proofs of concept.
CREDENTIAL_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
    "x-session-token", "x-csrf-token", "x-xsrf-token", "authentication",
}
CREDENTIAL_QUERY = re.compile(r"(?i)^(.*(token|api[-_]?key|secret|password|passwd|auth|sig|signature|session).*)$")

# Volatile values that differ between two otherwise identical responses.
_VOLATILE = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\b\d{10,13}\b"), "<epoch>"),
    (re.compile(r"\b[0-9a-fA-F]{32,64}\b"), "<hash>"),
]


def normalize_body(body: str, limit: int = 4000) -> str:
    """Strip volatile tokens and collapse whitespace so two bodies compare stably."""
    text = (body or "")[:limit]
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return re.sub(r"\s+", " ", text).strip()


def body_signature(body: str) -> str:
    return hashlib.sha1(normalize_body(body).encode("utf-8", "replace")).hexdigest()[:16]


def similarity(left: str, right: str) -> float:
    """0.0–1.0 similarity of two normalized bodies."""
    a, b = normalize_body(left), normalize_body(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return round(SequenceMatcher(None, a, b).ratio(), 3)


def redact_headers(headers: dict) -> dict:
    return {
        name: ("<credential>" if name.lower() in CREDENTIAL_HEADERS else value)
        for name, value in (headers or {}).items()
    }


def redact_url(url: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = [
        (key, "<credential>" if CREDENTIAL_QUERY.match(key) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _sh_quote(value: str) -> str:
    """POSIX single-quote quoting: literal everywhere, '' closes and reopens."""
    text = str(value)
    if text and re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", text):
        return text
    return "'" + text.replace("'", "'\''") + "'"


def _ps_quote(value: str) -> str:
    """PowerShell single-quote quoting: literal, and '' escapes a quote."""
    text = str(value)
    if text and re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", text):
        return text
    return "'" + text.replace("'", "''") + "'"


def _cmd_quote(value: str) -> str:
    """Command Prompt quoting: double quotes, with \" for an inner quote."""
    text = str(value)
    if text and re.fullmatch(r"[A-Za-z0-9_@+=:,./-]+", text):
        return text
    return '"' + text.replace('"', '\\"') + '"'


@dataclass
class Exchange:
    """One request/response pair captured by a probe."""

    label: str
    method: str
    url: str
    request_headers: dict = field(default_factory=dict)
    request_body: str | None = None
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    truncated: bool = False
    error: str = ""
    mutating: bool = False
    identity: str = "anonymous"

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def content_type(self) -> str:
        return str(self.headers.get("content-type", "")).split(";", 1)[0].strip().lower()

    @property
    def length(self) -> int:
        return len(self.body)

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default

    def excerpt(self, limit: int = 600) -> str:
        text = self.body or ""
        return text[:limit] + ("…" if len(text) > limit else "")

    def _parts(self) -> list:
        """The curl arguments, before any shell-specific quoting."""
        parts = ["-i", "-sS"]
        if self.method not in ("GET", "POST"):
            parts += ["-X", self.method]
        elif self.method == "POST" and not self.request_body:
            parts += ["-X", "POST"]
        # Probes read redirects rather than following them, so the command must too.
        parts.append("--max-redirs")
        parts.append("0")
        for name, value in redact_headers(self.request_headers).items():
            if name.lower() in ("host", "content-length", "accept-encoding", "connection"):
                continue
            # HTTP header names are case-insensitive; canonical case reads better
            # in a report than whatever the client library happened to send.
            canonical = "-".join(word.capitalize() for word in name.split("-"))
            parts += ["-H", f"{canonical}: {value}"]
        if self.request_body:
            body = self.request_body
            parts += ["--data-raw", body if len(body) <= 2000 else body[:2000]]
        parts.append(redact_url(self.url))
        return parts

    def curl(self) -> str:
        """POSIX shell reproduction. Single quotes keep every character literal."""
        return "curl " + " ".join(_sh_quote(part) for part in self._parts())

    def powershell(self) -> str:
        """PowerShell reproduction.

        ``curl`` is an alias for Invoke-WebRequest in PowerShell, so the command
        has to name ``curl.exe`` explicitly. Windows 10 1803 and later ship it.
        """
        return "curl.exe " + " ".join(_ps_quote(part) for part in self._parts())

    def cmd(self) -> str:
        """Windows Command Prompt reproduction."""
        return "curl.exe " + " ".join(_cmd_quote(part) for part in self._parts())

    def commands(self) -> dict:
        return {"bash": self.curl(), "powershell": self.powershell(), "cmd": self.cmd()}

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "identity": self.identity,
            "method": self.method,
            "url": redact_url(self.url),
            "request_headers": redact_headers(self.request_headers),
            "request_body": self.request_body if self.request_body and len(self.request_body) <= 4000 else (self.request_body or "")[:4000] or None,
            "status": self.status,
            "response_headers": self.headers,
            "body_excerpt": self.excerpt(),
            "body_length": self.length,
            "body_signature": body_signature(self.body),
            "elapsed_ms": self.elapsed_ms,
            "truncated": self.truncated,
            "error": self.error,
            "mutating": self.mutating,
            "curl": self.curl(),
            "commands": self.commands(),
        }


@dataclass
class Finding:
    """One security observation with the evidence that produced it."""

    id: str
    title: str
    severity: str
    confidence: str
    owasp: str = ""
    endpoint: str = ""
    parameter: str | None = None
    detail: str = ""          # Issue detail: what was observed here, on this target.
    background: str = ""      # Issue background: how this class of weakness works.
    impact: str = ""
    limitations: str = ""     # What this finding does NOT establish.
    remediation: str = ""
    remediation_background: str = ""
    # How the finding was established, in one sentence the reader can audit.
    method: str = ""
    cwe: str | None = None
    references: list = field(default_factory=list)
    # Substrings worth marking in the UI, with the reason shown on hover.
    highlights: list = field(default_factory=list)
    # Shell commands that re-derive a finding which has no request behind it.
    commands: dict | None = None
    evidence: dict = field(default_factory=dict)
    exchanges: list = field(default_factory=list)
    mutating: bool = False
    # "operation" findings belong to one route; "host" findings describe the
    # whole origin (headers, TLS, CORS middleware) and must not be re-reported
    # once per endpoint.
    scope: str = "operation"

    def sort_key(self) -> tuple:
        return (SEVERITY_RANK.get(self.severity, 9), CONFIDENCE_RANK.get(self.confidence, 9), self.id)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "owasp": self.owasp,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "detail": self.detail,
            "background": self.background,
            "impact": self.impact,
            "limitations": self.limitations,
            "remediation": self.remediation,
            "remediation_background": self.remediation_background,
            "method": self.method,
            "cwe": self.cwe,
            "references": self.references,
            "highlights": self.highlights,
            "commands": self.commands,
            "scope": self.scope,
            "evidence": self.evidence,
            "proof": [exchange.to_dict() for exchange in self.exchanges],
            "mutating": self.mutating,
        }


def finding(id: str, title: str, severity: str, confidence: str, **kwargs) -> Finding:
    """Build a finding, filling CWE, references and the default method from the catalogue.

    A probe that can describe its own procedure more precisely passes ``method=``
    and keeps it; otherwise the catalogue's default sentence is used.
    """
    from .catalogue import decorate

    if severity not in SEVERITIES:
        raise ValueError(f"Unknown severity {severity}")
    if confidence not in CONFIDENCES:
        raise ValueError(f"Unknown confidence {confidence}")
    from .catalogue import default_limitation, derive_highlights

    reference = decorate(id)
    for key in ("background", "remediation_background"):
        if not kwargs.get(key) and reference.get(key):
            kwargs[key] = reference[key]
    if not kwargs.get("limitations"):
        fallback = default_limitation(id, kwargs.get("method") or reference["method"], confidence)
        if fallback:
            kwargs["limitations"] = fallback
    explicit = list(kwargs.pop("highlights", []) or [])
    kwargs["highlights"] = _merge_highlights(explicit, derive_highlights(kwargs.get("evidence") or {}))
    kwargs.setdefault("cwe", reference["cwe"])
    kwargs.setdefault("references", reference["references"])
    if not kwargs.get("method"):
        kwargs["method"] = reference["method"]
    return Finding(id=id, title=title, severity=severity, confidence=confidence, **kwargs)


def mark(text, kind: str = "weak", note: str = "") -> dict:
    """One highlight: the exact substring to mark, why, and how to colour it."""
    return {"text": str(text), "kind": kind, "note": note}


def _merge_highlights(explicit: list, derived: list) -> list:
    """Explicit highlights win; derived ones fill in what they do not cover."""
    seen = {entry["text"] for entry in explicit if entry.get("text")}
    out = list(explicit)
    for entry in derived:
        text = entry.get("text")
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(entry)
    # Very short strings match too much text to be useful markers.
    return [entry for entry in out if len(str(entry["text"]).strip()) >= 3][:24]


def json_body(exchange: Exchange):
    """Parsed JSON for a response, or None when it is not JSON."""
    if "json" not in exchange.content_type and not (exchange.body or "").lstrip()[:1] in ("{", "["):
        return None
    try:
        return json.loads(exchange.body)
    except (ValueError, TypeError):
        return None


def walk_json(value, path: str = "$"):
    """Yield (path, key, value) for every scalar in a parsed JSON document."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if isinstance(item, (dict, list)):
                yield from walk_json(item, child)
            else:
                yield child, key, item
    elif isinstance(value, list):
        for index, item in enumerate(value[:50]):
            child = f"{path}[{index}]"
            if isinstance(item, (dict, list)):
                yield from walk_json(item, child)
            else:
                yield child, "", item
