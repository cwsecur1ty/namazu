"""What the first request actually established, and what may be concluded from it.

The audit used to send one baseline request and then run the whole battery as
long as the transport had not failed. A 403 saying the caller was not entitled
to the resource counted as a working baseline, so forty authorization and
injection probes ran against a response that never contained the resource. Each
compared itself to that denial, found nothing, and said nothing, and the report
came back thin with no indication that the audit had never got in.

This module names the six states a baseline can be in, and the engine uses the
verdict to decide which probes can draw a conclusion. The distinction that
matters most is between the three ways of not getting a resource:

* **authentication-failure**: the credential was not accepted at all.
* **permission-denied**: the credential was accepted, and this caller is not
  allowed this resource. Which may be entirely correct behaviour.
* **invalid-data**: the request never named a real resource, usually because
  the identifier was a placeholder generated from the schema.

Those look alike in a status code and are not alike at all. A 403 is *not*
read as a credential problem: it is read as a permission decision, and the
verdict says so rather than guessing which.

Nothing here is specific to any API. Classification uses the status code, the
challenge headers the response carries, the response body's own description of
itself, and whether the request was built from documented examples or from
generated filler. An operator who knows better overrides all of it with an
:class:`Expectation`, which is also what makes a negative test expressible: an
operation that is *supposed* to return 403 to this identity has a baseline
that succeeds when it does.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# The six states. "success" does not mean 2xx, it means the baseline
# established what the probes that follow need to be able to assume.
OUTCOMES = (
    "success",
    "authentication-failure",
    "permission-denied",
    "invalid-data",
    "unexpected",
    "transport-failure",
)

# A baseline in one of these states cannot support a probe that needs a working
# request to compare against.
BLOCKING = frozenset({"authentication-failure", "permission-denied", "invalid-data",
                      "unexpected", "transport-failure"})

# Values the example generator in spec.py produces when a schema documents no
# example. A request carrying one of these in a path parameter has not named a
# real object, and a 404 or a 422 answering it is a statement about the input
# rather than about authorization. Kept in sync with _sample() by a test.
GENERATED_FILLER = frozenset({
    "string", "0", "0.0", "true", "false",
    "123e4567-e89b-12d3-a456-426614174000", "2026-01-01T00:00:00Z",
    "2026-01-01", "user@example.com", "https://example.com",
})

_AUTH_WORDS = re.compile(
    r"(?i)\b(unauthenticated|unauthorized|not\s+authenticated|invalid[_\s-]?(token|credential|api[_\s-]?key)"
    r"|token\s+(expired|invalid)|missing\s+(token|credential|authorization)|login\s+required)\b")
_PERMISSION_WORDS = re.compile(
    r"(?i)\b(forbidden|not\s+entitled|not\s+allowed|permission\s+denied|insufficient\s+(scope|permission|privilege)"
    r"|access\s+denied|not\s+authorized\s+to)\b")
_VALIDATION_WORDS = re.compile(
    r"(?i)\b(validation|invalid\s+(value|format|parameter|input|identifier|id)|must\s+be"
    r"|is\s+not\s+a\s+valid|malformed|could\s+not\s+be\s+parsed|required\s+(field|property))\b")


# ── configurable assertions ──────────────────────────────────────────────────

@dataclass
class Expectation:
    """What the operator says a successful request looks like for this operation.

    Every field is optional and an empty expectation asserts nothing, which
    leaves classification to the heuristics. ``negative`` inverts the meaning
    of the whole thing: it marks an operation whose expected, correct answer is
    a refusal, so a 403 there is a baseline that worked.
    """

    # "200", "2xx", "200-204" and "200,201" all parse. Empty means any.
    status: str = ""
    body_contains: str = ""
    body_excludes: str = ""
    # A JSON Pointer into the response body and the value expected at it. The
    # pointer form is used rather than a path expression because it is the one
    # already in the codebase and it has an RFC behind it.
    pointer: str = ""
    pointer_equals: str = ""
    header: str = ""
    header_contains: str = ""
    negative: bool = False
    note: str = ""

    def asserted(self) -> bool:
        return any([self.status, self.body_contains, self.body_excludes, self.pointer,
                    self.header])

    def to_dict(self) -> dict:
        return {key: value for key, value in {
            "status": self.status, "body_contains": self.body_contains,
            "body_excludes": self.body_excludes, "pointer": self.pointer,
            "pointer_equals": self.pointer_equals, "header": self.header,
            "header_contains": self.header_contains, "negative": self.negative,
            "note": self.note,
        }.items() if value not in ("", False)}

    @classmethod
    def from_dict(cls, data) -> Expectation:
        """Tolerant of unknown keys, so an export written by a later version still loads."""
        if not isinstance(data, dict):
            return cls()
        known = {field_name for field_name in cls.__dataclass_fields__}
        return cls(**{key: value for key, value in data.items()
                      if key in known and value is not None})

    def describe(self) -> str:
        parts = []
        if self.status:
            parts.append(f"status {self.status}")
        if self.body_contains:
            parts.append(f"body containing “{self.body_contains}”")
        if self.body_excludes:
            parts.append(f"body not containing “{self.body_excludes}”")
        if self.pointer:
            parts.append(f"{self.pointer} equal to “{self.pointer_equals}”")
        if self.header:
            parts.append(f"header {self.header} containing “{self.header_contains}”")
        if not parts:
            return "no assertions were configured"
        joined = ", ".join(parts)
        return (f"a refusal was expected: {joined}" if self.negative
                else f"success was defined as {joined}")


def _status_matches(pattern: str, status: int) -> bool:
    for piece in str(pattern).replace(" ", "").split(","):
        if not piece:
            continue
        if re.fullmatch(r"\d[xX]{2}", piece):
            if status // 100 == int(piece[0]):
                return True
        elif "-" in piece:
            low, _, high = piece.partition("-")
            if low.isdigit() and high.isdigit() and int(low) <= status <= int(high):
                return True
        elif piece.isdigit() and int(piece) == status:
            return True
    return False


def _pointer_value(body: str, pointer: str):
    """The value at a JSON Pointer in a response body, or the sentinel on any failure."""
    try:
        document = json.loads(body or "")
    except (ValueError, TypeError):
        return _MISSING
    current = document
    for token in [piece for piece in pointer.split("/") if piece != ""]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return _MISSING
    return current


_MISSING = object()


def check(expectation: Expectation, exchange) -> tuple[bool, list]:
    """Whether a response satisfies the assertions, and which ones failed.

    ``negative`` is handled by the caller: this answers only whether the
    assertions hold, not whether holding is the desired outcome.
    """
    failures = []
    if expectation.status and not _status_matches(expectation.status, exchange.status):
        failures.append(f"status {exchange.status} does not match {expectation.status}")
    body = exchange.body or ""
    if expectation.body_contains and expectation.body_contains not in body:
        failures.append(f"the body does not contain “{expectation.body_contains}”")
    if expectation.body_excludes and expectation.body_excludes in body:
        failures.append(f"the body contains “{expectation.body_excludes}”, which it should not")
    if expectation.pointer:
        value = _pointer_value(body, expectation.pointer)
        if value is _MISSING:
            failures.append(f"the body has no value at {expectation.pointer}")
        elif str(value) != str(expectation.pointer_equals):
            failures.append(
                f"{expectation.pointer} is “{value}”, not “{expectation.pointer_equals}”")
    if expectation.header:
        actual = exchange.header(expectation.header)
        if not actual:
            failures.append(f"the response has no {expectation.header} header")
        elif expectation.header_contains and expectation.header_contains not in actual:
            failures.append(
                f"{expectation.header} is “{actual}”, which does not contain "
                f"“{expectation.header_contains}”")
    return not failures, failures


# ── the verdict ──────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    """What the baseline established, why, and what to do about it."""

    outcome: str
    reason: str
    remediation: str = ""
    # Probe families that cannot draw a conclusion from this baseline.
    evidence: dict = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        """Whether a probe may compare against this response and conclude from it."""
        return self.outcome == "success"

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "reason": self.reason,
                "remediation": self.remediation, "usable": self.usable,
                "evidence": self.evidence}


def placeholder_inputs(operation: dict) -> list:
    """Inputs whose value the request builder had to invent, by name.

    An operation documenting no example for a path parameter gets the literal
    "string", and a request for /reports/string is not a request for a report.
    Reading the declaration is better than guessing from the built value,
    because an API whose identifiers really are the word "string" exists
    somewhere and would otherwise be mis-reported forever.
    """
    invented = []
    for parameter in (operation.get("parameters") or []):
        if parameter.get("in") not in ("path", "query") or not parameter.get("name"):
            continue
        schema = parameter.get("schema") or {}
        documented = any([
            "example" in parameter, parameter.get("examples"),
            "example" in schema, "default" in schema, schema.get("enum"),
            "const" in schema, schema.get("examples"),
        ])
        if not documented:
            invented.append(f"{parameter['in']}.{parameter['name']}")
    return invented


def classify(exchange, *, operation: dict | None = None,
             expectation: Expectation | None = None,
             identity: str = "") -> Verdict:
    """Decide what one baseline response established."""
    operation = operation or {}
    expectation = expectation or Expectation()
    who = identity or "the configured identity"

    if not exchange.ok:
        return Verdict(
            "transport-failure",
            f"The baseline request did not complete: {exchange.error}. Nothing about the "
            "operation was established.",
            "Check the base URL, the proxy and TLS settings, and whether the host is reachable "
            "from this machine.",
            {"error": exchange.error})

    # An operator's own assertions settle it, including the case where a
    # refusal is the correct answer. This is checked before any heuristic so
    # that a deliberate negative test is never reported as a blocked baseline.
    if expectation.asserted():
        satisfied, failures = check(expectation, exchange)
        if expectation.negative:
            if satisfied:
                return Verdict(
                    "success",
                    f"The operation refused {who} as expected, and the configured assertions hold "
                    f"({expectation.describe()}). This is a negative test that passed.",
                    evidence={"status": exchange.status, "expectation": expectation.to_dict(),
                              "negative_test": True})
            return Verdict(
                "unexpected",
                f"A refusal was expected but the assertions do not hold: {'; '.join(failures)}.",
                "Review the expectation for this operation, or the behaviour that changed.",
                {"status": exchange.status, "failed_assertions": failures,
                 "expectation": expectation.to_dict()})
        if satisfied:
            return Verdict(
                "success",
                f"The baseline met the configured assertions ({expectation.describe()}).",
                evidence={"status": exchange.status, "expectation": expectation.to_dict()})
        # Assertions failed. Fall through so the reason names the *kind* of
        # failure rather than only listing the assertions, but remember that
        # the operator's definition of success was not met.
        verdict = _heuristic(exchange, operation, who)
        verdict.evidence["failed_assertions"] = failures
        verdict.evidence["expectation"] = expectation.to_dict()
        if verdict.outcome == "success":
            return Verdict(
                "unexpected",
                f"The response looks like a success but does not meet the configured assertions: "
                f"{'; '.join(failures)}.",
                "Either the assertions describe something the operation no longer returns, or the "
                "response is not the one expected.",
                verdict.evidence)
        return verdict

    return _heuristic(exchange, operation, who)


def _heuristic(exchange, operation: dict, who: str) -> Verdict:
    """Classification from the response itself, with no operator assertions to go on."""
    status = exchange.status
    body = (exchange.body or "")[:4000]
    invented = placeholder_inputs(operation)
    challenge = exchange.header("www-authenticate")
    evidence = {"status": status, "content_type": exchange.content_type}
    if challenge:
        evidence["www_authenticate"] = challenge
    if invented:
        evidence["generated_inputs"] = invented

    if 200 <= status < 300:
        return Verdict("success",
                       f"The baseline returned HTTP {status}, so the operation answered {who} "
                       "with a response the probes can compare against.",
                       evidence=evidence)

    if status == 401:
        return Verdict(
            "authentication-failure",
            "The baseline returned HTTP 401"
            + (f" with a {challenge.split(' ', 1)[0]} challenge" if challenge else "")
            + f", so the credential for {who} was not accepted. Every probe that needs an "
              "authenticated request is comparing against a rejection.",
            "Supply a working credential for this identity on the Auth tab, or configure an "
            "OAuth grant so the audit can mint one. If the operation is genuinely public, "
            "record an expectation for it instead.",
            evidence)

    if status == 403:
        # Deliberately not called a credential problem. 403 means the request
        # was understood and refused; which of the two reasons applies is not
        # something a status code states, so the verdict does not claim one.
        reason = (f"The baseline returned HTTP 403, so the request was refused. A 403 does not "
                  f"say whether the credential for {who} was rejected or whether it was accepted "
                  "and this caller is not permitted this resource, and Namazu has not "
                  "established which.")
        if _PERMISSION_WORDS.search(body):
            reason += " The response body describes it as a permission decision."
            evidence["body_indicates"] = "permission"
        elif _AUTH_WORDS.search(body):
            reason += " The response body describes it as a credential problem."
            evidence["body_indicates"] = "authentication"
        if invented:
            reason += (" The request also carried generated placeholder values for "
                       f"{', '.join(invented)}, so it may have been refused for naming nothing "
                       "that exists.")
        return Verdict(
            "permission-denied", reason,
            "Use an identity entitled to this resource, or supply a saved example request that "
            "is known to succeed. If a refusal is the correct answer for this identity, record it "
            "as an expected negative test so the coverage report stops treating it as a gap.",
            evidence)

    if status in (400, 404, 405, 409, 410, 415, 422):
        looks_like_validation = bool(_VALIDATION_WORDS.search(body)) or status in (400, 422)
        if invented and (looks_like_validation or status == 404):
            return Verdict(
                "invalid-data",
                f"The baseline returned HTTP {status} to a request whose "
                f"{', '.join(invented)} value was generated from the schema rather than taken "
                "from a documented example, so the request probably never named anything that "
                "exists.",
                "Add an example to the specification for those inputs, or save a known-good "
                "example request for this operation and reuse it as the baseline.",
                evidence)
        if looks_like_validation:
            return Verdict(
                "invalid-data",
                f"The baseline returned HTTP {status} and the response describes a problem with "
                "the request itself, so the operation was never exercised.",
                "Supply a request body and parameters the operation accepts, or save a known-good "
                "example request for it.",
                evidence)
        return Verdict(
            "unexpected",
            f"The baseline returned HTTP {status}, which is neither a success nor a refusal this "
            "tool can interpret.",
            "Look at the baseline exchange and decide whether the request or the target needs "
            "attention.",
            evidence)

    if status >= 500:
        return Verdict(
            "unexpected",
            f"The baseline returned HTTP {status}, so the operation failed on the documented "
            "request. Probes comparing against a server error cannot distinguish their own "
            "effect from it.",
            "This is worth reporting on its own. Fix or avoid the failing input before reading "
            "the rest of this operation's result.",
            evidence)

    if 300 <= status < 400:
        location = exchange.header("location")
        if location:
            evidence["location"] = location
        return Verdict(
            "unexpected",
            f"The baseline returned HTTP {status} and was not followed, so no representation of "
            "the resource was read.",
            "Point the audit at the location this redirects to, or supply a request that does "
            "not redirect.",
            evidence)

    return Verdict("unexpected", f"The baseline returned HTTP {status}, which was not expected.",
                   "Inspect the baseline exchange.", evidence)
