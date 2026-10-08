"""What was actually tested, and what only looked like it was.

A security report's most dangerous sentence is the one it does not contain. An
audit that ran forty probes against a denied baseline produces no findings for
them, and nothing in the result distinguishes that from forty probes that ran
and found the target sound. The reader draws the only available conclusion,
which is the wrong one.

So every probe family is declared here, and every one ends a run in exactly one
state:

``completed``      it ran and reached a conclusion.
``blocked``        a prerequisite was not met, so it could not run. Carries the
                   reason and what would unblock it.
``skipped``        deliberately not run: the profile excludes it, the method is
                   out of scope, or the operator turned it off.
``inconclusive``   it ran but the evidence does not support a conclusion either
                   way, which is not the same as finding nothing.
``not-applicable`` the operation has nothing for it to test.

There is no "passed". A probe that ran and found nothing is ``completed`` with
no findings, and the summary says so in those words, because "passed" is a
claim about the target and "completed" is a statement about the audit.
"""
from __future__ import annotations

from dataclasses import dataclass

STATES = ("completed", "blocked", "skipped", "inconclusive", "not-applicable", "attempted")

# Which state wins when two are recorded for one check. Most serious first, so
# a gap can never be overwritten by a later success: a check blocked on one
# endpoint and completed on another has a gap, and that is what the report has
# to show. The browser labels a check across endpoints with the same order.
PRECEDENCE = ("blocked", "inconclusive", "completed", "not-applicable", "skipped",
              "attempted")

# Every probe family the engine can run, with what it needs and what it means.
# ``needs_baseline`` marks the families whose conclusions are drawn by comparing
# a probe response against a working baseline; those are exactly the ones that
# go silent rather than wrong when the baseline is a refusal.
CHECKS: dict[str, dict] = {
    "contract-review": {
        "title": "Contract review",
        "what": "Reads the specification for weak declarations. Sends nothing.",
        "needs_baseline": False},
    "response-contract": {
        "title": "Response conformance",
        "what": "Compares the baseline response against the schema and media type the "
                "operation declares.",
        "needs_baseline": False,
        "needs_response": True},
    "passive-review": {
        "title": "Passive response review",
        "what": "Reads one response for leaked data, tokens and server detail.",
        "needs_baseline": False,
        "needs_response": True},
    "transport": {
        "title": "Transport and TLS",
        "what": "Certificate, protocol and transport security headers.",
        "needs_baseline": False},
    "authorization": {
        "title": "Object-level authorization",
        "what": "Replays the request with no credential and with a neighbouring object "
                "identifier, and compares what comes back.",
        "needs_baseline": True},
    # Separate from the family above, because it is the only part that needs a
    # second account. Blocking the whole family for want of one would lose the
    # anonymous replay, the identifier swap and the token battery, all of which
    # need a single identity and are where most real findings come from.
    "cross-identity": {
        "title": "Cross-identity access",
        "what": "Sends the first identity's exact request as a second identity and compares "
                "the resources that come back.",
        "needs_baseline": True,
        "needs_second_identity": True},
    "credential-handling": {
        "title": "Credential verification",
        "what": "Sends a deliberately invalid credential and checks it is refused.",
        "needs_baseline": True},
    # A denial-path test. It needs a baseline that was *refused*, because what
    # it looks for is a trivially different form of the same request getting
    # through where the original did not. A refused baseline is this check's
    # input, so it must never be blocked for one.
    "access-bypass": {
        "title": "Access-control bypass",
        "what": "Header, path and method variations that sometimes reach a protected route.",
        "denial_path": True},
    "cache": {
        "title": "Cache deception",
        "what": "Whether a private response can be made publicly cacheable.",
        "needs_baseline": True},
    "methods": {
        "title": "Undocumented methods",
        "what": "Which methods the route answers that the contract does not document.",
        "needs_baseline": False},
    "posture": {
        "title": "Security posture",
        "what": "Framing, CORS, rate limiting and resource limits.",
        "needs_baseline": False},
    "input-handling": {
        "title": "Input handling",
        "what": "Injection and traversal batteries over documented inputs.",
        "needs_baseline": True},
    "jwt": {
        "title": "Token handling",
        "what": "Offline analysis of the supplied token, and replay of forged variants.",
        "needs_baseline": True},
    # Sends an inert twin of each payload as its own control and compares the
    # two, so it concludes without reference to the baseline at all.
    "xml": {
        "title": "XML external entities",
        "what": "External entity resolution on an operation that accepts XML.",
        "needs_baseline": False},
    "mass-assignment": {
        "title": "Mass assignment",
        "what": "Whether a privileged property supplied by the client is stored.",
        "needs_baseline": True},
    "write-authorization": {
        "title": "Write authorization",
        "what": "Whether a second identity can complete a write on another's resource.",
        "needs_baseline": True,
        "needs_second_identity": True},
    "body-injection": {
        "title": "Request body injection",
        "what": "The injection battery over request body fields.",
        "needs_baseline": True},
    "inventory": {
        "title": "Surface inventory",
        "what": "Shadow routes, exposed documents and source around the documented surface.",
        "needs_baseline": False},
}


@dataclass
class Entry:
    """One probe family's outcome in one run."""

    check: str
    state: str
    reason: str = ""
    remediation: str = ""
    findings: int = 0
    requests: int = 0

    def to_dict(self) -> dict:
        meta = CHECKS.get(self.check, {})
        out = {
            "check": self.check,
            "title": meta.get("title", self.check),
            "what": meta.get("what", ""),
            "state": self.state,
            "findings": self.findings,
            "requests": self.requests,
        }
        if self.reason:
            out["reason"] = self.reason
        if self.remediation:
            out["remediation"] = self.remediation
        return out


class Ledger:
    """The coverage record for one operation, or for a sweep.

    A check can be recorded more than once, across endpoints or as a run
    narrows down what it could do. :data:`PRECEDENCE` decides which state
    survives, and it is ordered so that a gap always does: a family blocked on
    one operation cannot end the run looking completed because it ran on
    another.
    """

    def __init__(self) -> None:
        self._entries: dict[str, Entry] = {}
        self._order: list[str] = []

    def _record(self, check: str, state: str, reason: str = "",
                remediation: str = "") -> Entry:
        """Record a state, keeping whichever of the two is more serious.

        One precedence rule rather than a rule per method, so the outcome does
        not depend on the order the engine happens to call these in. It is the
        same order the browser uses to label a check across several endpoints:
        a gap must not be able to be overwritten by a later success.
        """
        entry = self._entries.get(check)
        if entry is None:
            self._order.append(check)
            self._entries[check] = Entry(check, state, reason, remediation)
            return self._entries[check]
        if PRECEDENCE.index(state) <= PRECEDENCE.index(entry.state):
            entry.state = state
            # Only overwrite the explanation when there is one, so a bare
            # complete() after a reasoned state does not blank the reason.
            if reason:
                entry.reason = reason
            if remediation:
                entry.remediation = remediation
        return entry

    def attempt(self, check: str) -> None:
        self._record(check, "attempted")

    def complete(self, check: str, *, findings: int = 0, requests: int = 0) -> None:
        entry = self._record(check, "completed")
        # Counted whatever the state settled on. A check blocked on one
        # endpoint and productive on another still found what it found.
        entry.findings += findings
        entry.requests += requests

    def block(self, check: str, reason: str, remediation: str = "") -> None:
        self._record(check, "blocked", reason, remediation)

    def skip(self, check: str, reason: str) -> None:
        self._record(check, "skipped", reason)

    def inconclusive(self, check: str, reason: str, remediation: str = "") -> None:
        self._record(check, "inconclusive", reason, remediation)

    def not_applicable(self, check: str, reason: str) -> None:
        self._record(check, "not-applicable", reason)

    def state(self, check: str) -> str:
        entry = self._entries.get(check)
        return entry.state if entry else ""

    def entries(self) -> list:
        return [self._entries[name] for name in self._order]

    def block_dependents(self, verdict, *, has_second_identity: bool = True) -> None:
        """Block every family whose conclusion depends on a baseline that did not work.

        This is the mechanism that turns a denied baseline into stated gaps
        instead of silence. Families that read the one response they already
        have, or that send their own independent requests, are left alone: a
        refusal is still a response, and the passive review, the contract
        comparison and the transport checks are all still worth running on it.
        """
        if not has_second_identity:
            for check, meta in CHECKS.items():
                if meta.get("needs_second_identity"):
                    self.block(
                        check,
                        "No second identity is configured, so cross-identity access was not "
                        "tested. Nothing in this result says the boundary holds.",
                        "Add a second identity on the Auth tab, ideally one that owns a "
                        "different object on the same operation, and record which object each "
                        "identity owns so a read can be checked by content.")
        if verdict.usable:
            return
        reason = f"The baseline did not succeed ({verdict.outcome}). {verdict.reason}"
        for check, meta in CHECKS.items():
            if not meta.get("needs_baseline"):
                continue
            self.block(check, reason, verdict.remediation)

    def summary(self) -> dict:
        counts = dict.fromkeys(STATES, 0)
        for entry in self._entries.values():
            counts[entry.state] = counts.get(entry.state, 0) + 1
        completed = [entry for entry in self._entries.values() if entry.state == "completed"]
        return {
            "checks_total": len(self._entries),
            "states": {name: value for name, value in counts.items() if value},
            # Said in these words on purpose. A completed check with no
            # findings is not a pass, it is a check that ran.
            "completed_without_findings": len([e for e in completed if not e.findings]),
            "blocked": [entry.to_dict() for entry in self._entries.values()
                        if entry.state == "blocked"],
        }

    def to_dict(self) -> dict:
        return {"checks": [entry.to_dict() for entry in self.entries()], **self.summary()}


def describe(ledger: Ledger, verdict=None) -> str:
    """One sentence for the notes list, naming what did not run."""
    blocked = [entry for entry in ledger.entries() if entry.state == "blocked"]
    if not blocked:
        return ""
    titles = ", ".join(CHECKS.get(entry.check, {}).get("title", entry.check)
                       for entry in blocked)
    lead = (f"The baseline was {verdict.outcome} rather than a success, so "
            if verdict is not None and not verdict.usable else "")
    return (f"{lead}{len(blocked)} check families did not run and are reported as blocked, not "
            f"as clean: {titles}. Nothing in this result says those areas are sound.")
