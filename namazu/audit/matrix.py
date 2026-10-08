"""A permission matrix, and a small sequence runner to make one testable.

Two problems, one module, because neither is useful without the other.

**The matrix** states who should be able to do what: an identity, the role or
tenant it represents, a test resource it owns, an operation, and whether access
is expected to be allowed or denied. Writing it down is what turns a 403 from
an obstacle into a result. A denial on a row marked ``deny`` is the control
passing; the same denial on a row marked ``allow`` is either a broken
entitlement or a broken test setup, and the two are worth telling apart.

The matrix also supplies what status codes cannot: a **positive control**. A
cross-identity read means nothing unless the owning identity can read the
resource in the first place. Without that control, an API that returns 403 to
everybody looks exactly like an API with a working boundary, and an API that is
simply down looks like both. So a row's conclusion is only drawn after its own
positive control has passed, and the verification is by **resource marker**
rather than by status or body similarity: a known string that appears in that
resource and in no other.

**The sequence runner** exists because most real authorization tests cannot be
written as one request. An identifier has to come from somewhere, and the
honest place to get one is the API: create a session, list the objects, take an
id out of the response, then use it. The runner does exactly that and nothing
more. It is deliberately not a workflow language: steps run in order, each can
extract values from its response by JSON Pointer, and later steps substitute
them by name. There are no conditionals, no loops and no expressions, because
every one of those would need its own safety argument and none of them is
needed to get an identifier into a path.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .baseline import Expectation
from .baseline import check as check_assertions
from .capture import from_exchange
from .transport import BudgetExhausted, MutationRefused

# ${name} only. A bare $name would make every dollar sign in a body a
# substitution site, and bodies contain prices.
PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}")
MAX_STEPS = 12
# What a created object's state is known to be. "possible" is the state a
# request that timed out or returned an ambiguous status leaves behind, and it
# is the one that matters: an object that may exist is the one a cleanup pass
# must be told about.
CREATION = ("created", "possibly-created", "attempted")


class SequenceError(ValueError):
    """A sequence is not runnable as written."""


@dataclass
class Step:
    """One request in a sequence, and what to take out of its response."""

    name: str
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None
    content_type: str = ""
    # Which configured identity sends this step. Resolved locally, never
    # carried in the sequence itself.
    identity: str = "primary"
    # {variable name: JSON Pointer into the response body}. A pointer that
    # does not resolve is a failed step, not an empty variable, because an
    # empty variable silently turns the next request into a different one.
    extract: dict = field(default_factory=dict)
    # Also extractable: a response header, by name.
    extract_headers: dict = field(default_factory=dict)
    expect: dict = field(default_factory=dict)
    # Whether this step is understood to create something that may need
    # removing afterwards.
    creates: bool = False

    def to_dict(self) -> dict:
        return {"name": self.name, "method": self.method, "url": self.url,
                "headers": self.headers, "body": self.body,
                "content_type": self.content_type, "identity": self.identity,
                "extract": self.extract, "extract_headers": self.extract_headers,
                "expect": self.expect, "creates": self.creates}

    @classmethod
    def from_dict(cls, data) -> Step:
        if not isinstance(data, dict):
            raise SequenceError("Every step must be an object.")
        known = set(cls.__dataclass_fields__)
        values = {key: value for key, value in data.items() if key in known}
        if not values.get("url"):
            raise SequenceError("Every step needs a url.")
        values.setdefault("name", values.get("url", "step"))
        values["method"] = str(values.get("method") or "GET").upper()
        for key in ("headers", "extract", "extract_headers", "expect"):
            if key in values and not isinstance(values[key], dict):
                values[key] = {}
        return cls(**values)


def substitute(value, variables: dict) -> tuple:
    """``value`` with ${name} replaced, and the names that were not defined.

    Substitution is textual and applies inside strings only, so a variable can
    land in a path, a query value, a header or a JSON body without the caller
    describing where. An undefined name is reported rather than replaced with
    an empty string: a request to /reports/ is a different request from a
    request to /reports/r-100, and would be a different finding.
    """
    missing: set = set()

    def one(text: str) -> str:
        def swap(match):
            name = match.group(1)
            if name not in variables:
                missing.add(name)
                return match.group(0)
            return str(variables[name])
        return PLACEHOLDER.sub(swap, text)

    def walk(item):
        if isinstance(item, str):
            return one(item)
        if isinstance(item, dict):
            return {one(str(key)): walk(child) for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child) for child in item]
        return item

    return walk(value), sorted(missing)


def pointer(document, path: str):
    """RFC 6901 JSON Pointer resolution, returning :data:`MISSING` on any failure."""
    current = document
    for token in [piece for piece in str(path).split("/") if piece != ""]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.lstrip("-").isdigit():
            index = int(token)
            if -len(current) <= index < len(current):
                current = current[index]
            else:
                return MISSING
        else:
            return MISSING
    return current


MISSING = object()


def _mask(case, extracted: dict):
    """``case`` with every extracted value replaced by a named placeholder.

    Short values are left alone: masking a page number or a two-character
    status code would make the evidence unreadable and reveals nothing, and a
    one-character value would match half the body.
    """
    masked = list(extracted.items())
    if not masked:
        return case

    def scrub(text):
        if not isinstance(text, str):
            return text
        for name, value in masked:
            text_value = str(value)
            if len(text_value) >= 6:
                text = text.replace(text_value, f"<extracted:{name}>")
        return text

    case.body_excerpt = scrub(case.body_excerpt)
    case.request_body = scrub(case.request_body)
    case.url = scrub(case.url)
    case.response_headers = {name: scrub(value)
                             for name, value in (case.response_headers or {}).items()}
    case.redacted = sorted(set(case.redacted or []) | {
        f"extracted value “{name}”" for name, value in masked if len(str(value)) >= 6})
    return case


@dataclass
class StepResult:
    name: str
    status: int
    outcome: str
    detail: str = ""
    extracted: dict = field(default_factory=dict)
    creation: str = ""
    case: object | None = None

    def to_dict(self) -> dict:
        out = {"name": self.name, "status": self.status, "outcome": self.outcome,
               "detail": self.detail, "extracted": sorted(self.extracted)}
        if self.creation:
            out["creation"] = self.creation
        if self.case is not None:
            out["case"] = self.case.to_dict()
        return out


@dataclass
class SequenceResult:
    outcome: str
    steps: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)
    reason: str = ""
    # Objects this run may have left behind, for a cleanup pass to be told about.
    created: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "steps": [step.to_dict() for step in self.steps],
            # Values are deliberately absent: an extracted value can be a
            # session token, and the names are what a reader needs.
            "variables": sorted(self.variables),
            "created": self.created,
            "cleanup": ("Nothing was removed. Namazu does not delete resources without a "
                        "configured cleanup step and an identity authorised to run it."
                        if self.created else ""),
        }


def run_sequence(steps: list, *, executor, identities: dict | None = None,
                 variables: dict | None = None, allow_mutating: bool = False) -> SequenceResult:
    """Run steps in order, extracting and substituting as it goes.

    Stops at the first step that does not meet its expectation, because every
    later step was written assuming it did.
    """
    identities = identities or {}
    values = dict(variables or {})
    results: list = []
    created: list = []

    if len(steps) > MAX_STEPS:
        raise SequenceError(f"A sequence runs at most {MAX_STEPS} steps; this one has "
                            f"{len(steps)}.")

    for raw in steps:
        step = raw if isinstance(raw, Step) else Step.from_dict(raw)
        url, missing_url = substitute(step.url, values)
        headers, missing_headers = substitute(dict(step.headers or {}), values)
        body, missing_body = substitute(step.body, values) if step.body is not None else (None, [])
        missing = sorted(set(missing_url) | set(missing_headers) | set(missing_body))
        if missing:
            results.append(StepResult(
                step.name, 0, "blocked",
                f"These variables were never defined by an earlier step: {', '.join(missing)}. "
                "The request was not sent, because sending it with the placeholders left in, or "
                "with them blanked out, would be a different request."))
            return SequenceResult("blocked", results, values,
                                  f"Step “{step.name}” needs {', '.join(missing)}.", created)

        credential = identities.get(step.identity)
        sent = {**({str(k): str(v) for k, v in credential.items()} if isinstance(credential, dict)
                   else {}), **headers}
        if isinstance(credential, dict) and not credential:
            sent = headers

        mutating = step.method not in ("GET", "HEAD", "OPTIONS", "TRACE")
        try:
            exchange = executor.send(
                step.method, url, label=f"sequence: {step.name}", headers=sent, body=body,
                content_type=step.content_type or ("application/json" if body else None),
                identity=step.identity, mutating=mutating)
        except MutationRefused as exc:
            results.append(StepResult(step.name, 0, "blocked", str(exc)))
            return SequenceResult("blocked", results, values, str(exc), created)
        except BudgetExhausted as exc:
            results.append(StepResult(step.name, 0, "blocked", str(exc)))
            return SequenceResult("blocked", results, values, str(exc), created)

        case = from_exchange(exchange, label=f"sequence step: {step.name}",
                             assertions=step.expect or {})
        if not exchange.ok:
            # A write whose response never arrived may still have been applied.
            creation = "possibly-created" if (step.creates and mutating) else ""
            if creation:
                created.append({"step": step.name, "url": url, "state": creation,
                                "why": f"The request failed in transport ({exchange.error}), so "
                                       "whether the object was created is unknown."})
            results.append(StepResult(step.name, 0, "error", exchange.error, creation=creation,
                                      case=case))
            return SequenceResult("error", results, values,
                                  f"Step “{step.name}” failed: {exchange.error}", created)

        expectation = Expectation.from_dict(step.expect or {})
        if expectation.asserted():
            satisfied, failures = check_assertions(expectation, exchange)
            if not satisfied:
                results.append(StepResult(step.name, exchange.status, "failed",
                                          "; ".join(failures), case=case))
                return SequenceResult(
                    "failed", results, values,
                    f"Step “{step.name}” did not meet its expectation: {'; '.join(failures)}",
                    created)

        extracted: dict = {}
        try:
            document = json.loads(exchange.body or "")
        except (ValueError, TypeError):
            document = None
        for name, path in (step.extract or {}).items():
            value = pointer(document, path) if document is not None else MISSING
            if value is MISSING or isinstance(value, (dict, list)):
                detail = (f"{path} did not resolve to a scalar in the response body"
                          if document is not None else
                          "the response body is not JSON, so nothing could be extracted")
                results.append(StepResult(step.name, exchange.status, "failed",
                                          f"Could not extract “{name}”: {detail}.", case=case))
                return SequenceResult("failed", results, values,
                                      f"Step “{step.name}” could not extract “{name}”.", created)
            extracted[str(name)] = value
        for name, header_name in (step.extract_headers or {}).items():
            value = exchange.header(str(header_name))
            if not value:
                results.append(StepResult(
                    step.name, exchange.status, "failed",
                    f"Could not extract “{name}”: the response has no {header_name} header.",
                    case=case))
                return SequenceResult("failed", results, values,
                                      f"Step “{step.name}” could not extract “{name}”.", created)
            extracted[str(name)] = value
        values.update(extracted)
        # A value a step extracts is about to be used as a credential or an
        # identifier in a later request, and the most common thing to extract
        # is a session token. The response body is evidence and is kept, but
        # the specific substrings this step pulled out of it are masked,
        # because the runner knows what they are for.
        if extracted:
            case = _mask(case, extracted)

        creation = ""
        if step.creates and mutating:
            creation = "created" if 200 <= exchange.status < 300 else "attempted"
            created.append({
                "step": step.name, "url": url, "state": creation,
                "status": exchange.status,
                "why": ("The request reported success." if creation == "created" else
                        f"The request returned HTTP {exchange.status}, so nothing indicates an "
                        "object was created, but the attempt was made."),
                "identifiers": {name: str(value) for name, value in extracted.items()},
            })
        results.append(StepResult(step.name, exchange.status, "ok", extracted=extracted,
                                  creation=creation, case=case))

    return SequenceResult("ok", results, values, "", created)


# ── the permission matrix ────────────────────────────────────────────────────

@dataclass
class Row:
    """One expectation about who may do what, and how to tell.

    ``marker`` is the string that proves which resource came back. A status
    code cannot do that: an API that answers every id with the caller's own
    object returns 200 either way, and body similarity cannot tell "the same
    object" from "the same shape". A marker can.
    """

    identity: str
    operation: str
    role: str = ""
    tenant: str = ""
    resource: str = ""
    marker: str = ""
    expect: str = "allow"           # "allow" or "deny"
    url: str = ""
    method: str = ""
    # Steps that must run before this row, to obtain an identifier or a session.
    prerequisites: list = field(default_factory=list)
    assertions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"identity": self.identity, "operation": self.operation, "role": self.role,
                "tenant": self.tenant, "resource": self.resource,
                "marker": self.marker, "expect": self.expect, "url": self.url,
                "method": self.method, "prerequisites": self.prerequisites,
                "assertions": self.assertions}

    @classmethod
    def from_dict(cls, data) -> Row:
        if not isinstance(data, dict):
            raise SequenceError("Every matrix row must be an object.")
        known = set(cls.__dataclass_fields__)
        values = {key: value for key, value in data.items() if key in known}
        if not values.get("identity"):
            raise SequenceError("Every matrix row names an identity.")
        if str(values.get("expect") or "allow") not in ("allow", "deny"):
            raise SequenceError("A row expects either “allow” or “deny”.")
        return cls(**values)


MATRIX_OUTCOMES = ("as-expected", "unexpected-allow", "unexpected-deny", "inconclusive",
                   "blocked", "error")


@dataclass
class RowResult:
    row: Row
    outcome: str
    reason: str
    status: int = 0
    marker_seen: bool | None = None
    case: object | None = None

    def to_dict(self) -> dict:
        out = {**self.row.to_dict(), "outcome": self.outcome, "reason": self.reason,
               "status": self.status}
        if self.marker_seen is not None:
            out["marker_seen"] = self.marker_seen
        if self.case is not None:
            out["case"] = self.case.to_dict()
        return out


def evaluate(rows: list, *, executor, identities: dict | None = None,
             allow_mutating: bool = False) -> dict:
    """Run every row, after establishing each identity's own positive control.

    A row whose identity has no passing positive control is ``inconclusive``,
    never a finding. That is the rule the brief this was written against asks
    for, and it is also the only way to tell a working boundary from an API
    that is refusing everybody.
    """
    identities = identities or {}
    parsed = [row if isinstance(row, Row) else Row.from_dict(row) for row in rows]
    results: list = []
    # An identity's positive control is its own "allow" row: proof that it can
    # reach something before anything is concluded about what it cannot reach.
    controls: dict = {}
    for row in parsed:
        if row.expect == "allow":
            controls.setdefault(row.identity, row)

    control_results: dict = {}
    for identity, row in controls.items():
        outcome = _run_row(row, executor=executor, identities=identities,
                           allow_mutating=allow_mutating)
        control_results[identity] = outcome
        results.append(outcome)

    for row in parsed:
        if row.expect == "allow" and controls.get(row.identity) is row:
            continue
        control = control_results.get(row.identity)
        if row.expect == "deny":
            if control is None:
                results.append(RowResult(
                    row, "inconclusive",
                    f"No positive control exists for “{row.identity}”. A denial here is not "
                    "evidence of a working boundary, because nothing establishes that this "
                    "identity can reach anything at all. Add a row marked allow for an object "
                    "this identity does own."))
                continue
            if control.outcome != "as-expected":
                results.append(RowResult(
                    row, "inconclusive",
                    f"The positive control for “{row.identity}” did not pass "
                    f"({control.outcome}: {control.reason}), so a denial here cannot be "
                    "distinguished from the identity being unable to reach anything."))
                continue
        results.append(_run_row(row, executor=executor, identities=identities,
                                allow_mutating=allow_mutating))

    return {
        "rows": [item.to_dict() for item in results],
        "summary": _matrix_summary(results),
        "controls": {identity: item.outcome for identity, item in control_results.items()},
        "note": ("A row is only concluded after its identity's own positive control passed. "
                 "Access is judged by whether the resource marker appeared, not by the status "
                 "code or by how similar two bodies are."),
    }


def _matrix_summary(results: list) -> dict:
    counts = dict.fromkeys(MATRIX_OUTCOMES, 0)
    for item in results:
        counts[item.outcome] = counts.get(item.outcome, 0) + 1
    return {"rows": len(results),
            "outcomes": {name: value for name, value in counts.items() if value},
            "problems": [item.to_dict() for item in results
                         if item.outcome in ("unexpected-allow", "unexpected-deny")]}


def _run_row(row: Row, *, executor, identities: dict, allow_mutating: bool) -> RowResult:
    """Send one row's request and decide whether the expectation held."""
    values: dict = {}
    if row.prerequisites:
        prepared = run_sequence(row.prerequisites, executor=executor, identities=identities,
                                allow_mutating=allow_mutating)
        if prepared.outcome != "ok":
            return RowResult(row, "blocked",
                             f"The prerequisite sequence did not complete ({prepared.outcome}): "
                             f"{prepared.reason}")
        values = prepared.variables

    url = row.url or ""
    if not url:
        return RowResult(row, "blocked", "The row has no URL to send.")
    url, missing = substitute(url, values)
    if missing:
        return RowResult(row, "blocked",
                         f"The row's URL needs variables no prerequisite defined: "
                         f"{', '.join(missing)}.")

    credential = identities.get(row.identity)
    if credential is None:
        return RowResult(row, "blocked",
                         f"No identity named “{row.identity}” is configured, so this row could "
                         "not be sent.")
    method = (row.method or "GET").upper()
    mutating = method not in ("GET", "HEAD", "OPTIONS", "TRACE")
    try:
        exchange = executor.send(method, url, label=f"matrix: {row.identity} -> {row.operation}",
                                 headers={str(k): str(v) for k, v in (credential or {}).items()},
                                 identity=row.identity, mutating=mutating)
    except (MutationRefused, BudgetExhausted) as exc:
        return RowResult(row, "blocked", str(exc))

    case = from_exchange(exchange, label=f"matrix row: {row.identity} -> {row.operation}",
                         assertions=row.assertions or {})
    if not exchange.ok:
        return RowResult(row, "error", exchange.error, case=case)

    reached, why, marker_seen = _reached(row, exchange)
    if row.expect == "allow":
        if reached:
            return RowResult(row, "as-expected",
                             f"“{row.identity}” reached {row.resource or row.operation}: {why}",
                             exchange.status, marker_seen, case)
        return RowResult(row, "unexpected-deny",
                         f"“{row.identity}” is expected to have access and did not get it: "
                         f"{why}", exchange.status, marker_seen, case)
    if reached:
        return RowResult(row, "unexpected-allow",
                         f"“{row.identity}” is not expected to have access and reached "
                         f"{row.resource or row.operation}: {why}",
                         exchange.status, marker_seen, case)
    return RowResult(row, "as-expected",
                     f"“{row.identity}” was refused as expected: {why}",
                     exchange.status, marker_seen, case)


def _reached(row: Row, exchange) -> tuple:
    """Did this request actually get the resource? Marker first, assertions second.

    Returning ``(False, ...)`` on a 2xx with no marker is deliberate. A 200
    that does not contain the resource's marker has not shown that the resource
    was reached, and treating 2xx as access is how a tool reports a bypass
    against an API that returns an empty list to everyone.
    """
    if row.assertions:
        satisfied, failures = check_assertions(Expectation.from_dict(row.assertions), exchange)
        if satisfied:
            return True, "the configured assertions for this resource hold", None
        return False, f"the configured assertions do not hold ({'; '.join(failures)})", None
    if row.marker:
        seen = row.marker in (exchange.body or "")
        if seen:
            return True, (f"the response carries the marker “{row.marker}”, which belongs to "
                          f"{row.resource or 'that resource'}"), True
        return False, (f"the response does not carry the marker “{row.marker}”, so this "
                       f"resource was not returned (HTTP {exchange.status})"), False
    # No marker and no assertions: say so rather than fall back to the status
    # code, which is what this module exists to avoid relying on.
    if 200 <= exchange.status < 300:
        return True, (f"HTTP {exchange.status} was returned. No resource marker is configured "
                      "for this row, so this rests on the status code alone and does not "
                      "establish which resource came back"), None
    return False, f"HTTP {exchange.status} was returned", None
