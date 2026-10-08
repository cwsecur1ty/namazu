"""Merging two reports of the same thing, without merging two different things.

Namazu and the external tools overlap. A run against one operation produced
``contract.content-type-mismatch`` from Namazu, which had captured a 403
returning ``application/problem+json`` where the contract documented only
``application/json``, and ``schemathesis.content-type`` from schemathesis,
which had its own opinion about the same operation. Those are very probably one
defect reported twice. They are not certainly one defect: until both sides have
an exchange to compare, "very probably" is the honest answer, and a report that
silently collapses them has thrown away the only evidence that would have
settled it.

So this module merges only on evidence, and says which kind it had:

* **confirmed duplicate**: both sides carry a captured exchange and the
  exchanges agree on the operation, the response status and the specific thing
  observed, for example the same media type. Merged into one finding, keeping
  both sources.
* **possible duplicate**: the semantics line up but at least one side has no
  exchange, so the agreement cannot be checked. Both findings are kept and
  cross-referenced, because dropping one would discard a source and keeping
  them silently would overstate the count.

Nothing merges on a matching title or a matching endpoint. Two findings on
``GET /orders/{id}`` with the same title can be two different failures of the
same check against two different inputs, and a report that merges them loses
one of them.
"""
from __future__ import annotations

import re

# Check ids that make the same observation from different sources. The key is a
# semantic name for the observation; everything under it is comparable *if the
# evidence agrees*. Membership here never merges anything on its own.
EQUIVALENT = {
    "undocumented-response-media-type": {
        "contract.content-type-mismatch",
        "schemathesis.content-type",
        "zap.content-type",
    },
    "undocumented-response-status": {
        "contract.undocumented-status",
        "schemathesis.undocumented-status",
    },
    "response-schema-violation": {
        "contract.response-schema-violation",
        "schemathesis.response-schema",
    },
    "server-error-on-valid-input": {
        "contract.server-error",
        "schemathesis.server-error",
    },
    "credential-not-verified": {
        "authz.invalid-credentials-accepted",
        "contract.invalid-credentials-accepted",
        "schemathesis.ignored-auth",
    },
}

# What has to match, per semantic group, beyond the operation and the status.
# A group with no discriminator is compared on operation and status alone,
# which is why every group that has a more specific fact to compare names it.
DISCRIMINATOR = {
    "undocumented-response-media-type": "media_type",
    "undocumented-response-status": "status",
    "response-schema-violation": None,
    "server-error-on-valid-input": "status",
    "credential-not-verified": None,
}

_MEDIA = re.compile(r"(?i)\b([a-z0-9!#$%&'*+.^_`|~-]+/[a-z0-9!#$%&'*+.^_`|~-]+)")


def _group(check_id: str) -> str:
    for name, members in EQUIVALENT.items():
        if check_id in members:
            return name
    return ""


def _media_type(finding) -> str:
    """The media type a finding is about, from its evidence or its captured response."""
    evidence = finding.evidence or {}
    for key in ("content_type", "media_type"):
        value = evidence.get(key)
        if isinstance(value, str) and "/" in value:
            return value.split(";", 1)[0].strip().lower()
    for case in finding.cases or []:
        headers = getattr(case, "response_headers", None) or {}
        for name, value in headers.items():
            if str(name).lower() == "content-type" and isinstance(value, str):
                return value.split(";", 1)[0].strip().lower()
    for exchange in finding.exchanges or []:
        if exchange.content_type:
            return exchange.content_type
    # Last resort: the detail sentence names it, because that is what the
    # reader sees. Only used when nothing structured carries it.
    match = _MEDIA.search(finding.detail or "")
    return match.group(1).lower() if match else ""


def _statuses(finding) -> set:
    """Every response status this finding has evidence for."""
    out = set()
    evidence = finding.evidence or {}
    if isinstance(evidence.get("status"), int):
        out.add(evidence["status"])
    for case in finding.cases or []:
        if getattr(case, "status", 0):
            out.add(int(case.status))
    for exchange in finding.exchanges or []:
        if exchange.status:
            out.add(int(exchange.status))
    return out


def _has_evidence(finding) -> bool:
    """Whether this finding carries an exchange that can be compared at all."""
    return bool(finding.cases) or bool(finding.exchanges)


def _sources(finding) -> list:
    source = (finding.evidence or {}).get("source")
    if isinstance(source, str) and source:
        return [source]
    return ["namazu"]


def _describe(finding) -> str:
    return f"{', '.join(_sources(finding))}:{finding.id}"


def compare(left, right) -> tuple[str, str]:
    """Whether two findings report one thing: ("confirmed"|"possible"|"", why)."""
    group = _group(left.id)
    if not group or group != _group(right.id):
        return "", "the two checks do not make the same observation"
    if left.id == right.id and left.endpoint == right.endpoint:
        # The engine's own per-id dedupe handles this; correlation is for
        # findings from different checks.
        return "", "same check and endpoint"
    if _normalise_endpoint(left.endpoint) != _normalise_endpoint(right.endpoint):
        return "", "different operations"
    if _sources(left) == _sources(right):
        return "", "both came from the same source"

    left_statuses, right_statuses = _statuses(left), _statuses(right)
    shared_status = left_statuses & right_statuses
    discriminator = DISCRIMINATOR.get(group)

    if not (_has_evidence(left) and _has_evidence(right)):
        missing = _describe(left) if not _has_evidence(left) else _describe(right)
        return "possible", (
            f"Both report {group.replace('-', ' ')} on {left.endpoint or 'the same operation'}, "
            f"but {missing} carries no captured exchange, so the two cannot be compared. Kept "
            "separate on purpose: merging without comparable evidence would discard a source.")

    if left_statuses and right_statuses and not shared_status:
        return "", (f"the response statuses differ ({sorted(left_statuses)} against "
                    f"{sorted(right_statuses)})")

    if discriminator == "media_type":
        left_media, right_media = _media_type(left), _media_type(right)
        if not left_media or not right_media:
            return "possible", (
                "Both report an undocumented response media type on the same operation and "
                "status, but at least one does not say which media type, so the match cannot "
                "be checked.")
        if left_media != right_media:
            return "", f"different media types ({left_media} against {right_media})"
        return "confirmed", (
            f"Both captured a {' and '.join(str(code) for code in sorted(shared_status))} "
            f"response carrying {left_media} on {left.endpoint}, which the operation does not "
            "document for that status. The exchanges establish the same mismatch.")

    if discriminator == "status":
        if not shared_status:
            return "possible", (
                "Both report the same kind of disagreement on the same operation, but neither "
                "captured a status code to compare.")
        return "confirmed", (
            f"Both captured HTTP {sorted(shared_status)[0]} on {left.endpoint}, which is the "
            "same observation from two sources.")

    return "confirmed", (
        f"Both captured evidence of {group.replace('-', ' ')} on {left.endpoint} with the same "
        "response status, which is the same observation from two sources.")


def _normalise_endpoint(endpoint: str) -> str:
    """Compare operations ignoring how each tool spells the template.

    schemathesis writes ``GET /orders/{orderId}`` and a captured URL may be
    ``/orders/o-1``; both reduce to the same shape only when the parameter
    names agree, so the template name itself is normalised away rather than
    the value, which would merge two different objects.
    """
    text = (endpoint or "").strip()
    method, _, path = text.partition(" ")
    if not path:
        method, path = "", text
    path = re.sub(r"\{[^{}]*\}", "{}", path.rstrip("/") or "/")
    return f"{method.upper()} {path}".strip()


def correlate(findings: list) -> tuple[list, list]:
    """Merge confirmed duplicates and cross-reference possible ones.

    Returns the findings to report and a list of notes describing what was
    merged and what was only suspected, so the decision is visible rather than
    inferred from a count that does not add up.
    """
    items = list(findings)
    notes: list = []
    merged_into: dict = {}

    for index, left in enumerate(items):
        if id(left) in merged_into:
            continue
        for right in items[index + 1:]:
            if id(right) in merged_into:
                continue
            level, why = compare(left, right)
            if level == "confirmed":
                # Described before absorbing. _absorb folds the absorbed
                # finding's evidence into the keeper, including its "source",
                # so describing the keeper afterwards names the wrong tool.
                description = f"Merged {_describe(right)} into {_describe(left)}: {why}"
                _absorb(left, right, why)
                merged_into[id(right)] = left
                notes.append(description)
            elif level == "possible":
                left.duplicate_of = left.duplicate_of or right.id
                left.duplicate_confidence = "possible"
                right.duplicate_of = right.duplicate_of or left.id
                right.duplicate_confidence = "possible"
                notes.append(
                    f"{_describe(left)} and {_describe(right)} may be the same defect: {why}")

    return [item for item in items if id(item) not in merged_into], notes


def _absorb(keeper, absorbed, why: str) -> None:
    """Fold one finding into another, keeping everything that was evidence."""
    keeper.provenance = list(dict.fromkeys(
        (keeper.provenance or _sources(keeper)) + (absorbed.provenance or _sources(absorbed))))
    keeper.cases = list(keeper.cases or []) + list(absorbed.cases or [])
    keeper.exchanges = list(keeper.exchanges or []) + list(absorbed.exchanges or [])
    keeper.references = list({
        reference.get("url"): reference
        for reference in (keeper.references or []) + (absorbed.references or [])
        if isinstance(reference, dict)}.values())
    keeper.evidence = {**(absorbed.evidence or {}), **(keeper.evidence or {}),
                       "merged_from": sorted(set(
                           (keeper.evidence or {}).get("merged_from") or []) | {absorbed.id}),
                       "merge_basis": why}
    # The merged finding inherits the stronger verification, because the
    # evidence for it is now the union of both sides.
    if keeper.assessment is not None and absorbed.assessment is not None:
        from .evidence import VERIFICATION_RANK, assign_severity
        if (VERIFICATION_RANK.get(absorbed.assessment.verification, 0)
                > VERIFICATION_RANK.get(keeper.assessment.verification, 0)):
            keeper.assessment.verification = absorbed.assessment.verification
        keeper.assessment.source_severity = list(
            keeper.assessment.source_severity) + list(absorbed.assessment.source_severity)
        # Two independent sources agreeing is worth saying, and it can change
        # the ceiling, so the severity is settled again rather than left stale.
        settled, rule, reason = assign_severity(
            keeper.assessment.proposed_severity or keeper.severity,
            category=keeper.assessment.category, origin=keeper.assessment.origin,
            verification=keeper.assessment.verification)
        keeper.severity, keeper.assessment.severity_rule = settled, rule
        keeper.assessment.severity_reason = reason
    keeper.limitations = (keeper.limitations or "") + (
        f"\n\nThis finding was merged with {absorbed.id} because {why[0].lower()}{why[1:]}")
