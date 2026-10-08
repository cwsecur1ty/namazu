"""What kind of thing a finding is, where its evidence came from, and how far it was taken.

Severity and confidence alone cannot express an honest report. A static read of
an OpenAPI document can establish beyond doubt that the document declares an
implicit OAuth flow, so "confirmed" is accurate; what it must not be allowed to
mean is that a confirmed authentication vulnerability was found. The two claims
differ in kind, not in certainty, and one field cannot carry both.

So a finding carries four independent axes:

**Category** is what kind of defect this is. A response media type missing from
the contract is a real defect and worth fixing, but it is a documentation
defect, not a weakness, and the severity it is given should say so.

**Origin** is where the evidence came from: the specification, a response this
run observed, or another tool's report. Origin is not quality. A runtime
observation of a 403 is a fact about one request; it is not a fact about
authorization.

**Verification** is how far the behaviour was taken: nothing beyond the
evidence, observed once, reproduced on demand, or carried through to a
demonstrated security consequence. Only the last one earns the language of
exploitation.

**Confidence** keeps its original meaning, but a ``confirmed`` finding now has
to say what was confirmed. ``confirmed_claim`` is that sentence, and it is
required, because "confirmed" with no object is the failure this module exists
to prevent.

Security severity is then assigned by the rules in :data:`SEVERITY_RULES`
rather than by each probe's own judgement, and the finding records which rule
decided it. A severity an operator cannot trace to a rule is a severity they
cannot argue with a client about.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── the axes ─────────────────────────────────────────────────────────────────

CATEGORIES = {
    "security": "A weakness an attacker could use, or the surface of one.",
    "hardening": "A control that is absent or weaker than current guidance, with no "
                 "demonstrated route to abuse it here.",
    "contract": "The implementation and its published specification disagree.",
    "reliability": "The implementation fails or errors on input it accepts.",
    "informational": "An observation recorded for the reader, asserting no defect.",
}

ORIGINS = {
    "static-declaration": "Read from the specification. No request was sent.",
    "runtime-observation": "Observed in a response during this run.",
    "external-report": "Reported by another tool and normalised, not re-verified by Namazu.",
}

# Deliberately ordered: each level includes everything the one before it
# established, so a comparison answers "is this at least reproduced?".
VERIFICATION = ("unverified", "observed", "reproduced", "impact-demonstrated")
VERIFICATION_RANK = {name: index for index, name in enumerate(VERIFICATION)}
VERIFICATION_MEANING = {
    "unverified": "Nothing beyond the evidence shown here was established.",
    "observed": "The behaviour was seen in a response captured during this run.",
    "reproduced": "The behaviour was replayed and happened again.",
    "impact-demonstrated": "A security consequence was demonstrated, not inferred.",
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def at_least(verification: str, floor: str) -> bool:
    """Whether ``verification`` reaches ``floor`` on the verification ladder."""
    return VERIFICATION_RANK.get(verification, 0) >= VERIFICATION_RANK.get(floor, 0)


def _cap(severity: str, ceiling: str) -> str:
    """``severity``, lowered to ``ceiling`` when it claims more than the rule allows."""
    if _SEVERITY_RANK.get(severity, 4) < _SEVERITY_RANK.get(ceiling, 4):
        return ceiling
    return severity


# ── the severity rules ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    """One documented reason a class of evidence cannot exceed a severity.

    ``category`` and ``origin`` are the values the rule applies to, empty
    meaning any. ``below`` makes the rule lift once the evidence reaches that
    rung of the verification ladder, which is how a demonstrated consequence
    escapes a ceiling that an inference does not.
    """

    id: str
    ceiling: str
    why: str
    category: tuple = ()
    origin: tuple = ()
    below: str = ""

    def applies(self, category: str, origin: str, verification: str) -> bool:
        if self.category and category not in self.category:
            return False
        if self.origin and origin not in self.origin:
            return False
        if self.below and at_least(verification, self.below):
            return False
        return True


# Ordered most specific first only for readability; every matching rule applies
# and the lowest ceiling wins, so the order cannot change an outcome.
SEVERITY_RULES: tuple = (
    Rule("informational-is-info", "info",
          "An observation that asserts no defect is not a severity.",
          category=("informational",)),
    Rule("contract-defect-is-informational", "info",
          "A disagreement between an implementation and its own specification is a "
          "documentation defect. It becomes a security severity only when a security "
          "consequence is demonstrated, not because a client might mishandle it.",
          category=("contract",), below="impact-demonstrated"),
    Rule("reliability-defect-is-low", "low",
          "An unhandled path is a reliability defect until something is shown to come "
          "of it. A 500 is evidence of a bug, not of a weakness.",
          category=("reliability",), below="impact-demonstrated"),
    Rule("hardening-without-impact-is-medium", "medium",
          "A missing or outdated control with no demonstrated route to abuse cannot "
          "outrank a weakness that was actually shown.",
          category=("hardening",), below="impact-demonstrated"),
    Rule("static-declaration-is-low", "low",
          "A specification states an intention. It is not evidence that the running "
          "server behaves that way, so it cannot carry the severity of an observed "
          "weakness.",
          origin=("static-declaration",), below="observed"),
    Rule("unreproduced-external-report-is-medium", "medium",
          "Another tool's unreproduced report is a lead. Namazu has not re-sent the "
          "request, so it cannot vouch for the severity.",
          origin=("external-report",), below="reproduced"),
    Rule("critical-needs-demonstrated-impact", "high",
          "Critical is reserved for a weakness whose consequence was demonstrated.",
          below="impact-demonstrated"),
)


def assign_severity(proposed: str, *, category: str, origin: str,
                    verification: str) -> tuple[str, str, str]:
    """The severity the rules permit, the rule that decided it, and why.

    Returns ``(severity, rule_id, explanation)``. When nothing lowered the
    proposed severity the rule id is ``"as-assessed"``: the probe's own
    judgement stands, which is the common case for an observed weakness.
    """
    severity = proposed if proposed in SEVERITIES else "info"
    decided, reason = "as-assessed", ""
    for rule in SEVERITY_RULES:
        if not rule.applies(category, origin, verification):
            continue
        capped = _cap(severity, rule.ceiling)
        if capped != severity:
            severity, decided, reason = capped, rule.id, rule.why
    return severity, decided, reason


# ── per-check defaults ───────────────────────────────────────────────────────

# A check whose id is not listed falls through to the prefix table below. Only
# checks whose kind differs from their family's default need an entry.
CATEGORY_BY_ID = {
    # Reading a specification cannot find a weakness, only a stated intention.
    "spec.oauth-implicit-flow": "hardening",
    "spec.oauth-password-grant": "hardening",
    "spec.no-security": "hardening",
    "spec.mass-assignment-surface": "informational",
    "spec.unbounded-collection": "hardening",
    "spec.sensitive-field": "informational",
    # The contract family is named for what it compares, and most of it is a
    # documentation defect. These are not.
    "contract.invalid-credentials-accepted": "security",
    "contract.error-detail-leak": "security",
    # A 500 on a request the contract calls valid is a defect in the
    # implementation, not a disagreement about what the document says.
    "contract.server-error": "reliability",
    # Cleartext is not a missing hardening control. Anything sent over that
    # connection, including the credential, is readable in transit.
    "transport.cleartext": "security",
    "transport.downgrade-redirect": "security",
    # schemathesis check kinds, by what the disagreement actually is.
    "schemathesis.ignored-auth": "security",
    "schemathesis.server-error": "reliability",
    "schemathesis.undocumented-status": "contract",
    "schemathesis.content-type": "contract",
    "schemathesis.response-schema": "contract",
    "schemathesis.accepted-invalid": "contract",
    "schemathesis.rejected-valid": "contract",
    # Discovering that a route exists is an inventory observation. Finding the
    # application's source or a live introspection endpoint on it is not.
    "inventory.undocumented-endpoint": "informational",
    "inventory.undocumented-methods": "informational",
    "inventory.version-sibling": "informational",
    "inventory.zombie-operation": "hardening",
    "inventory.docs-exposed": "hardening",
    "inventory.graphql-suggestions": "hardening",
    "inventory.graphql-introspection": "hardening",
    "inventory.source-exposed": "security",
}

CATEGORY_BY_PREFIX = (
    ("spec.", "hardening"),
    ("contract.", "contract"),
    ("transport.", "hardening"),
    ("posture.", "hardening"),
    ("passive.", "hardening"),
    ("schemathesis.", "contract"),
    ("nuclei.", "security"),
    ("zap.", "security"),
)

# The jwt family is deliberately absent. Some of it is offline analysis of a
# token the operator supplied and some of it is a probe that forged a token and
# watched the server accept it, which are opposite ends of the ladder. Those
# call sites pass origin= themselves rather than being guessed at here.
ORIGIN_BY_PREFIX = (
    ("spec.", "static-declaration"),
    ("schemathesis.", "external-report"),
    ("nuclei.", "external-report"),
    ("zap.", "external-report"),
)


def default_category(check_id: str) -> str:
    """What kind of defect this check reports, before the probe overrides it."""
    if check_id in CATEGORY_BY_ID:
        return CATEGORY_BY_ID[check_id]
    for prefix, category in CATEGORY_BY_PREFIX:
        if check_id.startswith(prefix):
            return category
    # Everything else is an active probe against the running target.
    return "security"


def default_origin(check_id: str) -> str:
    for prefix, origin in ORIGIN_BY_PREFIX:
        if check_id.startswith(prefix):
            return origin
    return "runtime-observation"


def default_verification(origin: str, *, has_exchanges: bool) -> str:
    """How far a finding has been taken, before a replay or a demonstration raises it.

    A static read is unverified by definition. A runtime finding carrying the
    exchange that produced it has at least been observed; one carrying no
    exchange has not, whatever its origin claims.
    """
    if origin == "static-declaration":
        return "unverified"
    if origin == "external-report":
        # Another tool observed it. Namazu did not, and without a captured
        # exchange there is nothing here that shows it happened.
        return "observed" if has_exchanges else "unverified"
    return "observed" if has_exchanges else "unverified"


# ── the assessment attached to a finding ─────────────────────────────────────

@dataclass
class SourceSeverity:
    """A severity another tool assigned, preserved rather than overwritten."""

    tool: str
    severity: str
    confidence: str = ""

    def to_dict(self) -> dict:
        return {"tool": self.tool, "severity": self.severity,
                **({"confidence": self.confidence} if self.confidence else {})}


@dataclass
class Assessment:
    """The four axes, the rule that set the severity, and the mapping's basis."""

    category: str
    origin: str
    verification: str
    confirmed_claim: str = ""
    severity_rule: str = "as-assessed"
    severity_reason: str = ""
    proposed_severity: str = ""
    # Why a CWE or OWASP category was attached. Required whenever one is, so a
    # reader can judge the mapping instead of trusting it.
    mapping_basis: str = ""
    source_severity: list = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {
            "category": self.category,
            "category_meaning": CATEGORIES.get(self.category, ""),
            "origin": self.origin,
            "origin_meaning": ORIGINS.get(self.origin, ""),
            "verification": self.verification,
            "verification_meaning": VERIFICATION_MEANING.get(self.verification, ""),
            "severity_rule": self.severity_rule,
        }
        if self.confirmed_claim:
            out["confirmed_claim"] = self.confirmed_claim
        if self.severity_reason:
            out["severity_reason"] = self.severity_reason
        if self.proposed_severity:
            out["proposed_severity"] = self.proposed_severity
        if self.mapping_basis:
            out["mapping_basis"] = self.mapping_basis
        if self.source_severity:
            out["source_severity"] = [
                item.to_dict() if isinstance(item, SourceSeverity) else item
                for item in self.source_severity]
        return out


# What "confirmed" means for each origin, when a probe does not say something
# more specific. Each of these is the whole of what that origin can establish,
# which is the distinction a single confidence field cannot carry: a confirmed
# static declaration and a confirmed cross-identity read are both confirmed,
# and they are not the same kind of claim.
CLAIM_BY_ORIGIN = {
    "static-declaration": "The imported document contains this declaration. Nothing about the "
                          "behaviour of the running implementation was established.",
    "runtime-observation": "The target returned the responses recorded in this finding's proof of "
                           "concept. The interpretation placed on them is stated in the detail.",
    "external-report": "The external tool reported this. Namazu normalised the report and did not "
                       "re-send the request.",
}


class AssessmentError(ValueError):
    """A finding's axes contradict each other."""


def build(check_id: str, *, severity: str, confidence: str, category: str = "",
          origin: str = "", verification: str = "", confirmed_claim: str = "",
          mapping_basis: str = "", source_severity=None,
          has_exchanges: bool = False, has_cwe: bool = False,
          has_owasp: bool = False) -> tuple[Assessment, str]:
    """Classify a finding and settle its security severity.

    Returns the assessment and the severity to use. Raises
    :class:`AssessmentError` when the axes cannot all be true at once, which is
    a programming error in the probe rather than something to report.
    """
    category = category or default_category(check_id)
    origin = origin or default_origin(check_id)
    if category not in CATEGORIES:
        raise AssessmentError(f"{check_id}: unknown category {category!r}")
    if origin not in ORIGINS:
        raise AssessmentError(f"{check_id}: unknown origin {origin!r}")
    verification = verification or default_verification(origin, has_exchanges=has_exchanges)
    if verification not in VERIFICATION_RANK:
        raise AssessmentError(f"{check_id}: unknown verification {verification!r}")

    if origin == "static-declaration" and at_least(verification, "observed"):
        raise AssessmentError(
            f"{check_id}: a static declaration cannot be observed behaviour. Send a request "
            "and record the exchange, or leave the verification unverified.")
    if at_least(verification, "observed") and not has_exchanges:
        raise AssessmentError(
            f"{check_id}: verification {verification!r} claims the behaviour was seen, but the "
            "finding carries no exchange that shows it.")
    if confidence == "confirmed" and not confirmed_claim:
        # The strongest claim on the ladder is the one that has to be spelled
        # out, because "a security consequence was demonstrated" is meaningless
        # without naming the consequence. Below that, what a given origin
        # establishes is the same sentence every time, and stating it is more
        # use to a reader than a probe-specific paraphrase of it.
        if verification == "impact-demonstrated":
            raise AssessmentError(
                f"{check_id}: a finding claiming demonstrated impact has to name the consequence "
                "it demonstrated. Pass confirmed_claim.")
        confirmed_claim = CLAIM_BY_ORIGIN[origin]
    # Where a mapping goes wrong is on a finding that names a mechanism nobody
    # saw. CWE-598 is "sensitive data in a query string"; a statically declared
    # implicit flow returns its token in a URL fragment, which is a different
    # weakness, and the finding that shipped that CWE stated in its own
    # limitations that it had not determined which of the two applied. The same
    # risk attaches to another tool's classification, which Namazu has not
    # re-derived. A probe that observed the behaviour itself is not asked for a
    # basis here: its catalogue entry is the reviewed record of the mapping,
    # which CONTRIBUTING.md already requires before the check is merged.
    needs_basis = origin == "static-declaration" or (
        origin == "external-report" and not at_least(verification, "reproduced"))
    if (has_cwe or has_owasp) and not mapping_basis and needs_basis:
        raise AssessmentError(
            f"{check_id}: this finding maps to a CWE or OWASP category on evidence it did not "
            "establish itself, so the mapping needs mapping_basis stating the relationship it "
            "claims. Drop the mapping if there is no defensible one.")

    settled, rule, reason = assign_severity(severity, category=category, origin=origin,
                                            verification=verification)
    assessment = Assessment(
        category=category, origin=origin, verification=verification,
        confirmed_claim=confirmed_claim, severity_rule=rule, severity_reason=reason,
        proposed_severity=severity if settled != severity else "",
        mapping_basis=mapping_basis,
        source_severity=list(source_severity or []),
    )
    return assessment, settled
