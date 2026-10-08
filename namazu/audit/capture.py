"""Captured cases: enough of a failing exchange to send it again.

A finding that says another tool found something, and carries a seed, is not
evidence. The seed reproduces the input only if the same tool, the same
version, the same schema and the same generator all line up, and a reader
holding the report has none of those. A real export contained exactly that: a
medium-severity finding whose entire proof was ``seed`` and a command line, and
whose seed had already been destroyed by a JSON round trip through a double.

A :class:`CapturedCase` carries the request as sent, the response as received,
which identity sent it, when, what the expected outcome was, which prerequisite
steps had to run first, and what is missing from the capture. It can be
rendered, exported, re-imported and replayed.

Two rules hold throughout:

**Credentials never enter a case.** Header values for credential names are
replaced with a placeholder on capture, and the case records an *identity
reference* instead: the name of an identity configured on this machine. Replay
resolves that name locally. A placeholder is never sent as a credential, and a
case whose identity is not configured is blocked rather than replayed
anonymously, because an anonymous replay of an authenticated request answers a
different question and would read as "not reproduced".

**Replay establishes behaviour, not impact.** It answers whether the recorded
response happens again. Whether that response constitutes a security weakness
is a separate judgement, made where the finding is assessed, and replay never
raises a finding's verification past ``reproduced``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .model import REDACTED_HEADERS, big_int, json_safe, redact_headers, redact_url

# Response body kept with a case. Smaller than a log entry because a case is
# meant to be read closely and there may be many of them in one export.
CASE_BODY_CHARS = 1500
# How many times replay will send one case, however many are asked for. Replay
# exists to establish repeatability, and a tool pointed at someone else's API
# should not turn that into traffic out of proportion to what it proves.
MAX_ATTEMPTS = 5
REPLAY_OUTCOMES = ("reproduced", "not-reproduced", "intermittent", "blocked", "error")

# Header names worth keeping so a response can be traced in the target's own
# logs. These are not credentials and a report is far more useful with them.
CORRELATION_HEADERS = (
    "x-request-id", "x-correlation-id", "x-amzn-requestid", "x-amz-request-id",
    "x-amzn-trace-id", "traceparent", "x-trace-id", "x-ms-request-id",
    "cf-ray", "x-github-request-id", "request-id", "x-operation-id",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def correlation_ids(headers: dict) -> dict:
    lowered = {str(name).lower(): value for name, value in (headers or {}).items()}
    return {name: lowered[name] for name in CORRELATION_HEADERS if lowered.get(name)}


@dataclass
class CapturedCase:
    """One reproducible exchange and everything needed to judge a replay of it."""

    label: str = ""
    method: str = "GET"
    url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str | None = None
    status: int = 0
    response_headers: dict = field(default_factory=dict)
    body_excerpt: str = ""
    body_length: int = 0
    body_truncated: bool = False
    error: str = ""
    mutating: bool = False
    # The name of a local identity, never a credential. Replay resolves it.
    identity_ref: str = "anonymous"
    recorded_at: str = field(default_factory=_now)
    elapsed_ms: float = 0.0
    correlation: dict = field(default_factory=dict)
    # Which tool produced this, its version, and the configuration that matters
    # for reading the case. A seed lives here as a decimal string.
    source: str = "namazu"
    tool_version: str = ""
    config: dict = field(default_factory=dict)
    seed: str = ""
    # The identity of the contract this was generated from, so a case can be
    # recognised as stale when the specification has moved on.
    schema_hash: str = ""
    schema_source: str = ""
    # What a replay should look for, and what had to happen first.
    assertions: dict = field(default_factory=dict)
    prerequisites: list = field(default_factory=list)
    # Named gaps. A reader should never have to infer that something is absent.
    missing: list = field(default_factory=list)
    redacted: list = field(default_factory=list)
    replay: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return json_safe({
            "label": self.label,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status": self.status,
            "response_headers": self.response_headers,
            "body_excerpt": self.body_excerpt,
            "body_length": self.body_length,
            "body_truncated": self.body_truncated,
            "error": self.error,
            "mutating": self.mutating,
            "identity_ref": self.identity_ref,
            "recorded_at": self.recorded_at,
            "elapsed_ms": self.elapsed_ms,
            "correlation": self.correlation,
            "source": self.source,
            "tool_version": self.tool_version,
            "config": self.config,
            # Always a string. See model.json_safe for why a number here is a bug.
            "seed": self.seed,
            "schema_hash": self.schema_hash,
            "schema_source": self.schema_source,
            "assertions": self.assertions,
            "prerequisites": self.prerequisites,
            "missing": self.missing,
            "redacted": self.redacted,
            **({"replay": self.replay} if self.replay else {}),
        })

    @classmethod
    def from_dict(cls, data) -> CapturedCase:
        """Read a case back, ignoring fields this version does not know.

        Exports outlive the version that wrote them. A case from an older
        Namazu is missing fields that now have defaults, and one from a newer
        Namazu carries fields this code has never heard of; neither is a reason
        to refuse to open a report.
        """
        if not isinstance(data, dict):
            return cls()
        known = set(cls.__dataclass_fields__)
        values = {key: value for key, value in data.items() if key in known}
        # A seed may arrive as a string (correct), an int (from Python), or a
        # float (from a JavaScript round trip, by which point it is no longer
        # the seed). big_int refuses the float rather than truncating it.
        if "seed" in values:
            recovered = big_int(values["seed"])
            values["seed"] = str(recovered) if recovered is not None else ""
            if recovered is None and data.get("seed") not in (None, "", 0):
                values["missing"] = list(values.get("missing") or data.get("missing") or []) + [
                    "The recorded seed did not survive export and cannot be used to reproduce "
                    "the input. It arrived as a floating point number."]
        for key in ("request_headers", "response_headers", "correlation", "config",
                    "assertions"):
            if key in values and not isinstance(values[key], dict):
                values[key] = {}
        for key in ("prerequisites", "missing", "redacted"):
            if key in values and not isinstance(values[key], list):
                values[key] = []
        unknown = sorted(set(data) - known)
        case = cls(**values)
        if unknown:
            case.config = {**case.config, "unrecognised_fields": unknown}
        return case

    def describe(self) -> str:
        return f"{self.method} {self.url} -> {self.status or self.error or 'no response'}"


def _redacted_names(headers: dict) -> list:
    return sorted({str(name) for name in (headers or {})
                   if str(name).lower() in REDACTED_HEADERS})


def from_exchange(exchange, *, source: str = "namazu", tool_version: str = "",
                  assertions: dict | None = None, prerequisites: list | None = None,
                  schema_hash: str = "", schema_source: str = "", seed: str = "",
                  config: dict | None = None, label: str = "") -> CapturedCase:
    """Capture one :class:`~namazu.audit.model.Exchange` as a replayable case.

    The redaction is the same function the proof of concept and the traffic
    view use, so a credential cannot be visible in one place and hidden in
    another.
    """
    missing = []
    if exchange.truncated:
        missing.append(f"The response body was truncated at the transport limit; "
                       f"{exchange.length} characters were read and "
                       f"{len(exchange.excerpt(CASE_BODY_CHARS))} are kept here.")
    elif exchange.length > CASE_BODY_CHARS:
        missing.append(f"The response body is {exchange.length} characters and the first "
                       f"{CASE_BODY_CHARS} are kept here.")
    if exchange.request_body and len(exchange.request_body) > 4000:
        missing.append("The request body was longer than 4000 characters and is truncated.")
    return CapturedCase(
        label=label or exchange.label,
        method=exchange.method,
        url=redact_url(exchange.url),
        request_headers=redact_headers(exchange.request_headers),
        request_body=(exchange.request_body or "")[:4000] or None,
        status=exchange.status,
        response_headers=dict(exchange.headers),
        body_excerpt=exchange.excerpt(CASE_BODY_CHARS),
        body_length=exchange.length,
        body_truncated=exchange.truncated,
        error=exchange.error,
        mutating=exchange.mutating,
        identity_ref=exchange.identity,
        elapsed_ms=exchange.elapsed_ms,
        correlation=correlation_ids(exchange.headers),
        source=source,
        tool_version=tool_version,
        config=dict(config or {}),
        seed=str(seed or ""),
        schema_hash=schema_hash,
        schema_source=schema_source,
        assertions=dict(assertions or {}),
        prerequisites=list(prerequisites or []),
        missing=missing,
        redacted=_redacted_names(exchange.request_headers),
    )


# ── replay ───────────────────────────────────────────────────────────────────

@dataclass
class ReplayResult:
    """The outcome of replaying one case, with every attempt accounted for."""

    outcome: str
    attempts: int = 0
    matched: int = 0
    reason: str = ""
    exchanges: list = field(default_factory=list)
    failures: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "attempts": self.attempts,
            "matched": self.matched,
            "reason": self.reason,
            "failed_assertions": self.failures[:8],
            "exchanges": [item.to_dict() for item in self.exchanges],
            # Said every time, because a reproduced response is a fact about
            # the target and not a judgement about its seriousness.
            "note": "Replay establishes that the recorded behaviour happens again. It does not "
                    "establish that the behaviour is a security weakness.",
        }


def _blocked(reason: str) -> ReplayResult:
    return ReplayResult("blocked", reason=reason)


def replay(case: CapturedCase, *, executor, identities: dict | None = None,
           attempts: int = 2, allow_mutating: bool = False,
           expectation=None) -> ReplayResult:
    """Send a captured case again, up to ``attempts`` times, and judge the result.

    ``executor`` carries the audit's budget, write policy and outbound route,
    so a replay is subject to exactly the controls a probe is. It is not a
    separate path out of the tool.
    """
    from . import baseline as baseline_module
    from .transport import BudgetExhausted, MutationRefused

    rounds = max(1, min(int(attempts or 1), MAX_ATTEMPTS))

    if case.error and not case.status:
        return _blocked(
            "The recorded case never got a response, so there is no behaviour to reproduce. "
            f"The original attempt failed with: {case.error}")
    if not case.url:
        return _blocked("The case has no URL to send.")
    if case.mutating and not allow_mutating:
        return _blocked(
            "This case changes server state. Replay is refused unless write requests are "
            "enabled for the run, and repeating a write to raise confidence is not something "
            "Namazu will do on its own.")

    headers, problem = resolve_headers(case, identities)
    if problem:
        return _blocked(problem)

    expectation = expectation or _expectation_for(case, baseline_module)
    results: list = []
    matched = 0
    failures: list = []
    errors = 0
    for index in range(rounds):
        try:
            exchange = executor.send(
                case.method, case.url, label=f"replay {index + 1} of {case.label or 'case'}",
                headers=headers, body=case.request_body,
                identity=case.identity_ref, mutating=case.mutating)
        except MutationRefused as exc:
            return _blocked(str(exc))
        except BudgetExhausted:
            if not results:
                return _blocked(
                    "The audit's request budget was already spent, so the replay could not "
                    "send anything. Raise the budget or choose a larger profile.")
            break
        results.append(exchange)
        if not exchange.ok:
            errors += 1
            failures.append(f"attempt {index + 1}: {exchange.error}")
            continue
        satisfied, why = baseline_module.check(expectation, exchange)
        if satisfied:
            matched += 1
        else:
            failures.append(f"attempt {index + 1}: " + "; ".join(why))

    sent = len(results)
    if not sent:
        return _blocked("No replay attempt was sent.")
    if errors == sent:
        return ReplayResult("error", attempts=sent, matched=0,
                            reason=f"Every one of {sent} attempts failed in transport.",
                            exchanges=results, failures=failures)
    if matched == sent:
        return ReplayResult("reproduced", attempts=sent, matched=matched,
                            reason=f"All {sent} attempts reproduced the recorded response "
                                   f"({expectation.describe()}).",
                            exchanges=results)
    if matched == 0:
        return ReplayResult("not-reproduced", attempts=sent, matched=0,
                            reason=f"None of {sent} attempts reproduced the recorded response. "
                                   "The behaviour may have been fixed, may depend on state this "
                                   "replay did not set up, or may never have been repeatable.",
                            exchanges=results, failures=failures)
    return ReplayResult("intermittent", attempts=sent, matched=matched,
                        reason=f"{matched} of {sent} attempts reproduced the recorded response, "
                               "so the behaviour is real but conditional.",
                        exchanges=results, failures=failures)


def resolve_headers(case: CapturedCase, identities: dict | None) -> tuple[dict, str]:
    """The headers to replay with, or the reason the replay is blocked.

    Redacted values are dropped and the named identity's real credentials are
    substituted from local configuration. Sending ``<credential>`` as a bearer
    token would produce a 401 and a confident "not reproduced", which is worse
    than refusing.
    """
    identities = identities or {}
    placeholder = {name for name, value in (case.request_headers or {}).items()
                   if isinstance(value, str) and value.strip() in ("<credential>", "[Filtered]")}
    headers = {name: value for name, value in (case.request_headers or {}).items()
               if name not in placeholder
               and str(name).lower() not in ("host", "content-length", "connection")}

    reference = (case.identity_ref or "anonymous").strip()
    if not placeholder:
        return headers, ""
    if reference in ("", "anonymous", "none"):
        # Nothing to resolve and nothing was needed: the case was anonymous and
        # the placeholders came from headers that are not this run's business.
        return headers, ""
    supplied = identities.get(reference)
    if supplied is None:
        supplied = identities.get(_identity_key(reference))
    if not isinstance(supplied, dict) or not supplied:
        return headers, (
            f"This case was recorded as “{reference}” and carries redacted credential headers "
            f"({', '.join(sorted(placeholder))}). No identity of that name is configured on this "
            "machine, so the replay has no credential to use. Configure it on the Auth tab; the "
            "replay will not send the redaction placeholder as a token.")
    headers.update({str(name): str(value) for name, value in supplied.items()})
    return headers, ""


def _identity_key(reference: str) -> str:
    """Map the labels exchanges carry back to the identity keys the API uses."""
    lowered = reference.strip().lower()
    if lowered in ("identity a", "primary", "a"):
        return "primary"
    if lowered in ("identity b", "secondary", "b"):
        return "secondary"
    return reference


def _expectation_for(case: CapturedCase, baseline_module):
    """What a replay of this case is looking for.

    The recorded assertions when the case has them. Otherwise the status code
    that was recorded, which is the weakest honest statement of "the same thing
    happened" and avoids calling a response different because a timestamp in it
    changed.
    """
    if case.assertions:
        return baseline_module.Expectation.from_dict(case.assertions)
    return baseline_module.Expectation(
        status=str(case.status),
        note="No assertions were recorded with this case, so the replay checks the status code "
             "only.")
