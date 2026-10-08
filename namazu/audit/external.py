"""Optional second-opinion tools, normalised into the same finding shape.

Namazu's own checks are deliberately narrow and evidence-first. Two mature
projects cover ground it does not, and both run locally:

``schemathesis``  property-based testing driven from the same OpenAPI document.
                  It generates inputs the contract permits and reports where the
                  implementation disagrees with its own schema: undeclared 500s,
                  responses that violate the declared type, malformed media
                  types. Pure Python, so it installs into the same environment.

``nuclei``        ProjectDiscovery's template engine. A large community corpus
                  of signatures for known CVEs, exposed panels, default
                  credentials and misconfigurations, which is a different kind
                  of knowledge from anything derived from a contract.

Neither is required. When a tool is absent the run says so and continues; it is
never a silent gap. Both are invoked as subprocesses with an explicit timeout,
read-only method filters unless writes are enabled, and no outbound callback
service.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .capture import CASE_BODY_CHARS, CapturedCase, correlation_ids
from .evidence import SourceSeverity
from .model import REDACTED_HEADERS, big_int, finding, mark, redact_headers, redact_url

TOOL_TIMEOUT = 600
MAX_FINDINGS = 60
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# Nuclei tags that probe destructively or generate traffic out of proportion to
# what they prove. Excluded always, not only in read-only mode.
# The full corpus is ~10k templates and takes far longer than an audit should.
# This set is the part that speaks to an HTTP API surface. "cve" is in it
# because leaving it out was the main reason a run added almost nothing: a
# known vulnerable version behind the API is exactly what this tool is here to
# find, and a CVE template is a read-only signature match. It costs minutes
# rather than seconds, which is why the panel says so before you start.
DEFAULT_NUCLEI_TAGS = "cve,exposure,misconfig,config,default-login,api,tech"
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force,bruteforce"
ANSI = re.compile(chr(27) + '\\[[0-9;]*m')
NUCLEI_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium",
                       "low": "low", "info": "info", "unknown": "info"}


def _schemathesis_command() -> list[str] | None:
    """How to invoke schemathesis, or None when it is not installed.

    Through the interpreter, not the ``st`` console script. That script is a
    generated wrapper, and where it is built wrong it fails in the worst
    possible way: it exits non-zero having written nothing at all, no report
    and no message, so the only thing the caller can report is that no report
    appeared. ``-m schemathesis.cli`` runs normally in the same environment.

    Going through the interpreter also pins which copy runs. The one installed
    beside Namazu is the one tested against, rather than whichever ``st``
    happens to come first on PATH.
    """
    try:
        if importlib.util.find_spec("schemathesis") is None:
            return None
    except (ImportError, ValueError):
        return None
    return [sys.executable, "-m", "schemathesis.cli"]


def _schemathesis_version() -> str | None:
    """Read it from package metadata; the CLI has no --version that prints one."""
    try:
        from importlib.metadata import version
        return version("schemathesis")
    except Exception:
        return None


def available() -> dict:
    """Which optional tools this machine can run."""
    tools = {}
    launcher = _schemathesis_command()
    tools["schemathesis"] = {
        "available": bool(launcher), "path": " ".join(launcher) if launcher else None,
        "version": _schemathesis_version() if launcher else None,
        "install": "pip install schemathesis",
        "role": "Property-based contract testing from the same OpenAPI document.",
    }
    tools["schemathesis"]["capabilities"] = SCHEMATHESIS_CAPABILITIES
    nuclei = shutil.which("nuclei")
    tools["nuclei"] = {
        "available": bool(nuclei), "path": nuclei,
        "version": _version([nuclei, "-version"]) if nuclei else None,
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "role": "Template signatures for known CVEs, exposed panels and misconfigurations.",
        "capabilities": NUCLEI_CAPABILITIES,
    }
    return tools


NUCLEI_CAPABILITIES = {
    "generates_inputs": False,
    "captures_exchanges": False,
    "reproducible_by_seed": False,
    "mutating_by_default": True,
    "write_policy":
        "Destructive, fuzzing and brute-force tags are excluded always, not only in read-only "
        "mode, and the callback service is off. A template's tag is not treated as a guarantee "
        "that it is non-mutating: the tag taxonomy describes the subject of a template, not its "
        "side effects, so a cve template is included for the signature match it performs and not "
        "because the tag makes it safe. Review the template set before pointing this at "
        "production.",
    "scope": "The target host, not only the documented operations. nuclei probes paths of its "
             "own choosing under that origin.",
    "evidence": "nuclei reports the matcher that fired and the URL it matched, not the request "
                "and response, so its findings carry no replayable case.",
}


def _version(command: list) -> str | None:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=30,
                              encoding="utf-8", errors="replace",
                              env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    except (OSError, subprocess.SubprocessError):
        return None
    # Tools colourise their banners even when told not to, and prefix the number
    # with a "v" that a word boundary would refuse to match.
    text = ANSI.sub("", (done.stdout or "") + (done.stderr or ""))
    match = re.search(r"(\d+\.\d+\.\d+[\w.+-]*)", text)
    return match.group(1) if match else (text.strip().splitlines() or [None])[0]


def _run(command: list, timeout: int) -> tuple[int, str, str, str]:
    # These tools print Unicode banners. On a Windows console the child inherits
    # a cp1252 stdout and dies encoding its own output, so force UTF-8 on both.
    child_env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", env=child_env)
    except subprocess.TimeoutExpired:
        return -1, "", "", f"The tool did not finish within {timeout}s and was stopped."
    except OSError as exc:
        return -1, "", "", f"The tool could not be started: {exc}."
    return done.returncode, done.stdout or "", done.stderr or "", ""


# ── schemathesis ─────────────────────────────────────────────────────────────

def run_schemathesis(*, schema: str, base_url: str, headers: dict | None = None,
                     allow_mutating: bool = False, max_examples: int = 20,
                     timeout: int = TOOL_TIMEOUT, verify_tls: bool = True,
                     identity_ref: str = "primary", schema_hash: str = "") -> dict:
    """Property-based testing over the documented operations.

    Two reports are asked for, because the two formats answer different
    questions and neither is sufficient. ``json`` is the verdict: how many
    operations were tested, which checks failed and how often. ``ndjson`` is
    the record: every scenario, the checks that ran inside it, and the actual
    request and response of each one. Without the second, a finding can only
    repeat what the tool concluded, which is how a medium-severity finding came
    to ship with a seed and no exchange behind it.
    """
    launcher = _schemathesis_command()
    if not launcher:
        return _missing("schemathesis", "pip install schemathesis")
    version = _schemathesis_version() or ""

    with tempfile.TemporaryDirectory(prefix="namazu-st-") as workspace:
        report = Path(workspace) / "report.json"
        record = Path(workspace) / "report.ndjson"
        command = [*launcher, "run", schema, "--url", base_url,
                   "--max-examples", str(max_examples),
                   "--report", "json", "--report-json-path", str(report),
                   "--report", "ndjson", "--report-ndjson-path", str(record),
                   "--no-color"]
        for name, value in (headers or {}).items():
            command += ["--header", f"{name}: {value}"]
        if not allow_mutating:
            # Only read-only methods, so a property test cannot create or delete.
            command += ["--exclude-method-regex", "^(POST|PUT|PATCH|DELETE)$"]
        if not verify_tls:
            command += ["--tls-verify", "false"]

        code, out, err, failure = _run(command, timeout)
        if failure:
            return _failed("schemathesis", failure, command)
        if not report.exists():
            detail = " ".join((err or out).strip().splitlines()[-3:])
            return _failed("schemathesis",
                           f"No report was produced (exit code {code}). "
                           f"{detail or 'The tool printed nothing.'}", command)
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _failed("schemathesis", f"The report could not be read: {exc}.", command)
        captured, capture_notes = _schemathesis_cases(
            record, version=version, identity_ref=identity_ref, schema_hash=schema_hash,
            schema_source=schema, seed=_seed_text(document))

    findings = _schemathesis_findings(document, captured, version=version)
    notes = list(capture_notes)
    coverage = _schemathesis_coverage(document)
    if coverage:
        notes.append(coverage)
    return {"tool": "schemathesis", "ran": True, "exit_code": code,
            "version": version,
            "command": _redact(command, headers),
            "summary": _schemathesis_summary(document),
            "capabilities": SCHEMATHESIS_CAPABILITIES,
            "findings": [item.to_dict() for item in findings[:MAX_FINDINGS]],
            "truncated": len(findings) > MAX_FINDINGS, "notes": notes}


SCHEMATHESIS_CAPABILITIES = {
    "generates_inputs": True,
    "captures_exchanges": True,
    "reproducible_by_seed": True,
    "mutating_by_default": True,
    "write_policy": "Namazu restricts it to read-only methods unless write requests are enabled "
                    "for the run, with --exclude-method-regex.",
    "scope": "Only the operations in the specification it was given.",
}


def _seed_text(document) -> str:
    """The run seed as a decimal string.

    A schemathesis seed is 128 bits wide. Carried as a JSON number it does not
    survive a JavaScript consumer: a real export held 2.315194611349191e+38
    where the seed had been 231519461134919091197611956279382553858.
    """
    if not isinstance(document, dict):
        return ""
    recovered = big_int(document.get("seed"))
    return str(recovered) if recovered is not None else ""


def _schemathesis_coverage(document) -> str:
    """What the run did not cover, in the tool's own numbers."""
    if not isinstance(document, dict):
        return ""
    operations = document.get("operations") or {}
    parts = []
    skipped = operations.get("skipped") or 0
    errored = operations.get("errored") or 0
    if skipped:
        reasons = operations.get("skip_reasons") or []
        detail = f" ({'; '.join(str(item) for item in reasons[:3])})" if reasons else ""
        parts.append(f"{skipped} operation(s) were skipped{detail}")
    if errored:
        parts.append(f"{errored} operation(s) errored before being tested")
    total, tested = operations.get("total"), operations.get("tested")
    if isinstance(total, int) and isinstance(tested, int) and tested < total:
        parts.append(f"{tested} of {total} documented operations were tested")
    if document.get("stop_reason") not in (None, "", "finished"):
        parts.append(f"the run stopped because: {document['stop_reason']}")
    if not parts:
        return ""
    return "schemathesis coverage: " + "; ".join(parts) + "."


# The ndjson record names checks in snake case and failures in camel case. One
# table maps the check that ran to the failure type, so a captured exchange can
# be attached to the finding built from the summary.
ST_CHECK_TO_FAILURE = {
    "status_code_conformance": ("UndefinedStatusCode", "UndocumentedStatusCode"),
    "content_type_conformance": ("UndefinedContentType", "MissingContentType",
                                 "MalformedMediaType"),
    "response_schema_conformance": ("ResponseConformance",),
    "not_a_server_error": ("ServerError",),
    "ignored_auth": ("IgnoredAuth",),
    "negative_data_rejection": ("AcceptedNegativeData",),
    "positive_data_acceptance": ("RejectedPositiveData",),
}


def _schemathesis_cases(record: Path, *, version: str, identity_ref: str, schema_hash: str,
                        schema_source: str, seed: str) -> tuple[dict, list]:
    """Failing request/response pairs from the ndjson record, keyed by failure type.

    Returns ``{(failure_type, operation): [CapturedCase, ...]}`` and any notes
    about evidence that could not be captured. A missing or unreadable record
    is reported rather than passed over: a finding with no exchange behind it
    should say that it has none and why.
    """
    if not record.exists():
        return {}, ["schemathesis produced no scenario record, so its findings carry the tool's "
                    "own summary but no captured request or response. Reproduce them with the "
                    "recorded seed before reporting them."]
    cases: dict = {}
    notes: list = []
    kept = 0
    try:
        lines = record.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {}, [f"schemathesis wrote a scenario record that could not be read: {exc}."]

    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        scenario = event.get("ScenarioFinished")
        if not isinstance(scenario, dict):
            continue
        recorder = scenario.get("recorder") or {}
        interactions = recorder.get("interactions") or {}
        case_values = recorder.get("cases") or {}
        for case_id, checks in (recorder.get("checks") or {}).items():
            for entry in checks if isinstance(checks, list) else []:
                failure = ((entry or {}).get("failure_info") or {}).get("failure") or {}
                if (entry or {}).get("status") != "failure" or not failure:
                    continue
                kind = str(failure.get("type") or "")
                operation = str(failure.get("operation") or "")
                interaction = interactions.get(case_id) or {}
                if not interaction:
                    continue
                if kept >= MAX_CASES:
                    notes.append(
                        f"schemathesis reported more failing cases than the {MAX_CASES} kept "
                        "here; the rest are summarised by count only.")
                    return cases, notes
                captured = _case_from_interaction(
                    interaction, case_values.get(case_id) or {}, kind=kind,
                    operation=operation, message=str(failure.get("message") or ""),
                    check_name=str((entry or {}).get("name") or ""),
                    version=version, identity_ref=identity_ref, schema_hash=schema_hash,
                    schema_source=schema_source, seed=seed)
                cases.setdefault((kind, operation), []).append(captured)
                kept += 1
    if not cases:
        notes.append("schemathesis recorded no failing exchange, so nothing was captured for "
                     "replay.")
    return cases, notes


MAX_CASES = 40


def _header_map(raw) -> dict:
    """ndjson stores every header value as a list; flatten to one string each."""
    out = {}
    for name, value in (raw or {}).items():
        if isinstance(value, list):
            out[str(name)] = ", ".join(str(item) for item in value)
        else:
            out[str(name)] = str(value)
    return out


def _content_text(content) -> tuple[str, int]:
    """The body text and its real length from an ndjson content field."""
    if isinstance(content, dict) and "$base64" in content:
        try:
            raw = base64.b64decode(str(content["$base64"]), validate=False)
        except (ValueError, TypeError):
            return "", 0
        text = raw.decode("utf-8", "replace")
        return text, len(text)
    if isinstance(content, str):
        return content, len(content)
    return "", 0


def _case_from_interaction(interaction: dict, case_value: dict, *, kind: str, operation: str,
                           message: str, check_name: str, version: str, identity_ref: str,
                           schema_hash: str, schema_source: str, seed: str) -> CapturedCase:
    request = interaction.get("request") or {}
    response = interaction.get("response") or {}
    body_text, body_length = _content_text(response.get("content"))
    value = (case_value or {}).get("value") or {}
    request_headers = _header_map(request.get("headers"))
    missing = []
    if body_length > CASE_BODY_CHARS:
        missing.append(f"The response body is {body_length} characters and the first "
                       f"{CASE_BODY_CHARS} are kept here.")
    # schemathesis sanitises its own report, so credential headers arrive as
    # "[Filtered]". That is the correct behaviour and the case says so, because
    # the placeholder must never be replayed as a token.
    filtered = sorted(name for name, item in request_headers.items()
                      if str(item).strip() == "[Filtered]")
    if filtered:
        missing.append("schemathesis filtered these request headers before writing its report, "
                       f"so their values were never available to capture: {', '.join(filtered)}. "
                       "Replay resolves them from the local identity instead.")
    if not request.get("body") and value.get("body") is None and request.get("method") in (
            "POST", "PUT", "PATCH"):
        missing.append("No request body was recorded for a method that normally carries one.")

    body_value = request.get("body")
    if isinstance(body_value, dict) and "$base64" in body_value:
        body_value, _ = _content_text(body_value)
    elif body_value is not None and not isinstance(body_value, str):
        body_value = json.dumps(body_value)

    timestamp = interaction.get("timestamp")
    recorded = ""
    if isinstance(timestamp, (int, float)):
        from datetime import datetime, timezone
        recorded = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z")

    case = CapturedCase(
        label=f"{check_name or kind} on {operation or 'an operation'}",
        method=str(request.get("method") or value.get("method") or "GET").upper(),
        url=redact_url(str(request.get("uri") or "")),
        request_headers=redact_headers(request_headers),
        request_body=body_value if isinstance(body_value, str) else None,
        status=int(response.get("status_code") or 0),
        response_headers=_header_map(response.get("headers")),
        body_excerpt=body_text[:CASE_BODY_CHARS] + ("…" if body_length > CASE_BODY_CHARS else ""),
        body_length=body_length,
        error="",
        mutating=str(request.get("method") or "GET").upper() in WRITE_METHODS,
        identity_ref=identity_ref,
        elapsed_ms=round(float(response.get("elapsed") or 0) * 1000, 2),
        correlation=correlation_ids(_header_map(response.get("headers"))),
        source="schemathesis",
        tool_version=version,
        config={"check": check_name, "failure_type": kind,
                "generation": (value.get("meta") or {}).get("generation"),
                "phase": ((value.get("meta") or {}).get("phase") or {}).get("name"),
                "schemathesis_message": message[:400]},
        seed=seed,
        schema_hash=schema_hash,
        schema_source=schema_source,
        assertions={"status": str(response.get("status_code") or ""),
                    "note": f"The recorded failure was {kind}: {message[:200]}"},
        missing=missing,
        redacted=sorted(set(filtered) | {name for name in request_headers
                                         if str(name).lower() in REDACTED_HEADERS}),
    )
    if recorded:
        case.recorded_at = recorded
    return case


def _schemathesis_summary(document) -> dict:
    if not isinstance(document, dict):
        return {}
    cases = document.get("test_cases") or {}
    return {
        "operations_tested": (document.get("operations") or {}).get("tested"),
        "test_cases": cases.get("generated"),
        "unique_failures": cases.get("unique_failures"),
        "errors": len(document.get("errors") or []),
        "running_time_seconds": round(document.get("running_time") or 0, 2),
        "seed": document.get("seed"),
    }


@dataclass(frozen=True)
class StCheck:
    """How one schemathesis check kind is reported, and why that mapping holds.

    ``category`` is the kind of defect, which for most of these is a
    documentation defect rather than a weakness: an undocumented status code is
    a real disagreement between an implementation and its contract, and calling
    it a security finding of medium severity is how a thin report comes to look
    alarming. ``basis`` justifies the OWASP mapping, which is required because
    Namazu did not observe any of this itself.
    """

    check: str
    severity: str
    owasp: str
    explanation: str
    category: str
    basis: str


# schemathesis failure types, mapped to how Namazu reports them. Severity comes
# from schemathesis itself where it supplies one; these are the fallbacks, and
# the evidence rules lower anything Namazu has not reproduced.
_CONTRACT_BASIS = (
    "API9:2023 covers inventory and documentation accuracy, which is what this check compares: the "
    "response the implementation gave against the response its own schema describes. It is not a "
    "claim that the mismatch is exploitable.")
ST_CHECKS = {
    "IgnoredAuth": StCheck(
        "ignored-auth", "high", "API2:2023 Broken Authentication",
        "The operation returned a success response to a request carrying invalid or missing "
        "credentials, although the contract marks it as authenticated.",
        "security",
        "API2:2023 is the authentication category and this check removes the credential and "
        "compares the outcome, which is an authentication test. schemathesis observed it; Namazu "
        "has not re-sent the request."),
    "ServerError": StCheck(
        "server-error", "medium", "API8:2023 Security Misconfiguration",
        "The operation returned a 5xx response to an input the contract describes as valid, so an "
        "unhandled path exists behind it.",
        "reliability",
        "API8:2023 covers error handling. The observation is an unhandled path, which is a "
        "reliability defect; nothing here establishes that anything is exposed through it."),
    "UndefinedStatusCode": StCheck(
        "undocumented-status", "low", "API9:2023 Improper Inventory Management",
        "The operation returned a status code its own schema does not document.",
        "contract", _CONTRACT_BASIS),
    "UndocumentedStatusCode": StCheck(
        "undocumented-status", "low", "API9:2023 Improper Inventory Management",
        "The operation returned a status code its own schema does not document.",
        "contract", _CONTRACT_BASIS),
    "UndefinedContentType": StCheck(
        "content-type", "low", "API9:2023 Improper Inventory Management",
        "A response arrived with a media type the operation does not document for that status.",
        "contract", _CONTRACT_BASIS),
    "AcceptedNegativeData": StCheck(
        "accepted-invalid", "low", "API3:2023 Broken Object Property Level Authorization",
        "The operation accepted a request body that violates its own schema, so input validation "
        "is weaker than the contract claims.",
        "contract",
        "API3:2023 covers property-level handling, and this check sends a body the schema forbids. "
        "Accepting it is a validation gap; whether any property reached anything that matters was "
        "not tested."),
    "RejectedPositiveData": StCheck(
        "rejected-valid", "low", "API9:2023 Improper Inventory Management",
        "The operation rejected a request the contract says is valid, so the schema and the "
        "implementation disagree.",
        "contract", _CONTRACT_BASIS),
    "MissingContentType": StCheck(
        "content-type", "low", "API9:2023 Improper Inventory Management",
        "A response arrived without a Content-Type the contract documents.",
        "contract", _CONTRACT_BASIS),
    "MalformedMediaType": StCheck(
        "content-type", "low", "API9:2023 Improper Inventory Management",
        "A response declared a media type that could not be parsed.",
        "contract", _CONTRACT_BASIS),
    "ResponseConformance": StCheck(
        "response-schema", "low", "API9:2023 Improper Inventory Management",
        "A response body did not match the schema the operation declares for it.",
        "contract", _CONTRACT_BASIS),
    "JsonSchemaError": StCheck(
        "response-schema", "low", "API9:2023 Improper Inventory Management",
        "A response body did not match the schema the operation declares for it.",
        "contract", _CONTRACT_BASIS),
    "MissingHeaders": StCheck(
        "missing-headers", "low", "API9:2023 Improper Inventory Management",
        "A response omitted headers its own schema declares as required.",
        "contract", _CONTRACT_BASIS),
    "MissingHeaderNotRejected": StCheck(
        "missing-header-accepted", "low", "API9:2023 Improper Inventory Management",
        "The operation accepted a request that omitted a header the contract marks required.",
        "contract", _CONTRACT_BASIS),
    "AllowHeaderMismatch": StCheck(
        "allow-header", "low", "API9:2023 Improper Inventory Management",
        "A 405 response carried an Allow header that disagrees with the documented methods.",
        "contract", _CONTRACT_BASIS),
    "UnsupportedMethodResponse": StCheck(
        "unsupported-method", "low", "API9:2023 Improper Inventory Management",
        "The route answered a method the contract does not document for it, without a 405.",
        "contract", _CONTRACT_BASIS),
    "ContentTypeServerError": StCheck(
        "server-error", "medium", "API8:2023 Security Misconfiguration",
        "The operation returned a 5xx response when sent a media type it documents.",
        "reliability",
        "API8:2023 covers error handling. An unhandled media type is a reliability defect until "
        "something is shown to come of it."),
    "ResponseTimeExceeded": StCheck(
        "slow-response", "low", "API4:2023 Unrestricted Resource Consumption",
        "A response took longer than the configured limit.",
        "reliability",
        "API4:2023 covers resource consumption, and a response time is the observation. It is not "
        "a demonstration that the operation can be made to exhaust anything."),
    # Stateful checks. These are about resource lifecycle rather than schema
    # agreement, and both are genuine authorization-adjacent observations.
    "UseAfterFree": StCheck(
        "use-after-free", "medium", "API1:2023 Broken Object Level Authorization",
        "A resource remained readable after the operation that deletes it reported success.",
        "security",
        "API1:2023 covers object-level access. The sequence deleted an object and then read it "
        "back successfully, which is an access-control observation, not a schema disagreement."),
    "EnsureResourceAvailability": StCheck(
        "resource-unavailable", "low", "API9:2023 Improper Inventory Management",
        "A resource was not readable immediately after the operation that creates it reported "
        "success.",
        "reliability",
        "API9:2023 covers contract accuracy, and this is the create-then-read sequence "
        "disagreeing with what the operations claim. It may equally be eventual consistency."),
}
ST_UNKNOWN = StCheck(
    "contract-violation", "low", "API9:2023 Improper Inventory Management",
    "schemathesis reported a disagreement between the implementation and its schema.",
    "contract", _CONTRACT_BASIS)
ST_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _schemathesis_findings(document, captured: dict | None = None,
                           *, version: str = "") -> list:
    """One finding per (failure type, operation) pair reported by schemathesis."""
    out = []
    captured = captured or {}
    seed = _seed_text(document)
    for record in (document.get("failures") or []) if isinstance(document, dict) else []:
        if not isinstance(record, dict):
            continue
        kind = str(record.get("type") or "Unknown")
        title = str(record.get("title") or kind)
        spec = ST_CHECKS.get(kind, ST_UNKNOWN)
        reported = str(record.get("severity") or "").lower()
        severity = ST_SEVERITY.get(reported, spec.severity)
        operations = [str(item) for item in (record.get("operations") or []) if item] or ["(not reported)"]
        for endpoint in operations[:12]:
            cases = captured.get((kind, endpoint)) or []
            evidence_note = (
                f"The failing exchange is captured: {cases[0].describe()}." if cases else
                "No failing exchange was captured for this report, so what is shown is "
                "schemathesis's own summary. Reproduce it before reporting it.")
            out.append(finding(
                f"schemathesis.{spec.check}", title, severity, "probable", owasp=spec.owasp,
                endpoint=endpoint,
                category=spec.category,
                origin="external-report",
                # One captured exchange means the behaviour was observed, by
                # schemathesis. Namazu has not re-sent it, so it stops there;
                # only a replay moves it to reproduced. Without an exchange it
                # cannot even claim that much.
                verification="observed" if cases else "unverified",
                mapping_basis=spec.basis,
                source_severity=[SourceSeverity("schemathesis", reported or "unrated")]
                                if reported else [],
                method=("Generated by schemathesis, which derives inputs from the same OpenAPI document "
                        "and compares every response against the schema the operation declares. The "
                        f"check that fired was {kind}."),
                detail=f"{spec.explanation} schemathesis recorded {record.get('count', 1)} case(s) for "
                       f"{endpoint}. {evidence_note}",
                background=(
                    "Property-based testing generates many inputs the contract permits, rather than the "
                    "one example a hand-written test uses. Failures land where the implementation and "
                    "its own published schema disagree, which is where undocumented error paths and "
                    "unhandled types tend to live."),
                impact=("A response the contract does not describe is a response no client is written to "
                        "handle. An input the server mishandles is frequently the first step of a more "
                        "serious bug."),
                limitations=(
                    "Reported by schemathesis and not re-verified by Namazu. The generated input may "
                    "not correspond to anything a real client would send."
                    + (" Use Replay on the captured case to establish whether it happens again."
                       if cases else
                       " No request or response was captured for it, so this finding rests entirely "
                       "on the tool's summary.")),
                remediation=("Handle the input explicitly and return a documented status, or correct the "
                             "schema so it describes what the operation actually accepts and returns."),
                cases=cases,
                evidence={"source": "schemathesis", "check": kind, "cases": record.get("count"),
                          "schemathesis_severity": record.get("severity"),
                          "schemathesis_version": version,
                          "captured_cases": len(cases),
                          # A decimal string. See _seed_text.
                          "seed": seed,
                          "reproduce": (f"st run <schema> --url <base> --seed {seed}"
                                        if seed else "st run <schema> --url <base>")},
                highlights=[mark("schemathesis", "proof",
                                 "Reported by the external tool, not by Namazu's own checks."),
                            mark(kind, "weak", "The schemathesis check that failed.")],
            ))
    return out


# ── nuclei ───────────────────────────────────────────────────────────────────

def run_nuclei(*, target: str, headers: dict | None = None, severities: str = "info,low,medium,high,critical",
               tags: str = DEFAULT_NUCLEI_TAGS, rate_limit: int = 50, timeout: int = TOOL_TIMEOUT,
               verify_tls: bool = True) -> dict:
    """Template signatures against the target host."""
    binary = shutil.which("nuclei")
    if not binary:
        return _missing("nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    with tempfile.TemporaryDirectory(prefix="namazu-nuclei-") as workspace:
        output = Path(workspace) / "findings.jsonl"
        command = [binary, "-target", target, "-jsonl", "-output", str(output),
                   "-severity", severities,
                   "-exclude-tags", NUCLEI_EXCLUDE_TAGS,
                   "-rate-limit", str(rate_limit),
                   "-timeout", "10", "-retries", "1",
                   "-no-interactsh",          # no outbound callback service
                   "-disable-update-check",
                   "-silent", "-no-color"]
        if tags:
            command += ["-tags", tags]
        for name, value in (headers or {}).items():
            command += ["-header", f"{name}: {value}"]
        if not verify_tls:
            command += ["-insecure"]

        code, out, err, failure = _run(command, timeout)
        # A timeout is not a reason to throw away what nuclei already wrote.
        # It streams matches to the output file as it finds them, so a run
        # stopped at the limit usually has real results on disk; discarding
        # them turns a partial result into no result, which reads as a clean
        # one. The findings are kept and the gap is stated.
        lines = output.read_text(encoding="utf-8").splitlines() if output.exists() else []
        if failure and not lines:
            return _failed("nuclei", failure, command)

    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    findings = _nuclei_findings(records)
    notes = []
    if failure:
        notes.append(
            f"{failure} {len(records)} match(es) had already been written and are reported "
            "here. The rest of the template set did not run, so this is a partial result.")
    if not records and code not in (0,):
        notes.append((err or out).strip().splitlines()[-1] if (err or out).strip() else
                     f"nuclei exited with code {code}.")
    return {"tool": "nuclei", "ran": True, "exit_code": code,
            "version": _version([binary, "-version"]),
            "command": _redact(command, headers),
            "capabilities": NUCLEI_CAPABILITIES,
            "complete": not failure,
            "summary": {"matches": len(records)},
            "findings": [item.to_dict() for item in findings[:MAX_FINDINGS]],
            "truncated": len(findings) > MAX_FINDINGS, "notes": notes}


def _nuclei_findings(records: list) -> list:
    out, seen = [], {}
    for record in records:
        info = record.get("info") or {}
        template = str(record.get("template-id") or record.get("templateID") or "template")
        name = str(info.get("name") or template)
        matched = str(record.get("matched-at") or record.get("host") or "")
        key = (template, matched)
        if key in seen:
            # Same template at the same URL, a different matcher. Record which
            # ones fired rather than emitting a finding per matcher.
            existing = seen[key]
            name_hit = record.get("matcher-name")
            if name_hit and name_hit not in existing.evidence["matchers"]:
                existing.evidence["matchers"].append(name_hit)
            continue
        severity = NUCLEI_SEVERITY_MAP.get(str(info.get("severity") or "info").lower(), "info")
        classification = info.get("classification") or {}
        cve = (classification.get("cve-id") or [None])
        cve_id = cve[0] if isinstance(cve, list) and cve else classification.get("cve-id")
        cwe_list = classification.get("cwe-id") or []
        cwe = (cwe_list[0] if isinstance(cwe_list, list) and cwe_list else cwe_list) or None
        references = [{"title": url, "url": url}
                      for url in (info.get("reference") or []) if isinstance(url, str)][:6]

        item = finding(
            f"nuclei.{template}", name, severity, "probable",
            owasp="API8:2023 Security Misconfiguration",
            endpoint=matched or "(host)",
            cwe=str(cwe).upper() if cwe else None,
            references=references,
            origin="external-report",
            verification="unverified",
            source_severity=[SourceSeverity("nuclei", str(info.get("severity") or "unrated"))],
            mapping_basis=(
                "The CWE and severity are the template author's own classification, carried through "
                "rather than re-derived: Namazu did not observe the mechanism either names. "
                "API8:2023 is the category nuclei's corpus largely addresses, which is known "
                "versions, exposed interfaces and misconfiguration."),
            method=(f"Matched by the nuclei template {template}. Namazu ran nuclei against the target "
                    "and normalised its output; it did not re-verify the match itself."),
            detail=((info.get("description") or name).strip()
                    + (f" Matched at {matched}." if matched else "")),
            background=("nuclei matches community-maintained templates describing known vulnerable "
                        "versions, exposed interfaces, default credentials and misconfigurations. The "
                        "knowledge comes from the template corpus rather than from this API's contract."),
            impact=str(info.get("impact") or "").strip()
                   or "Depends on the specific template; see the referenced material.",
            limitations=("Reported by nuclei, not confirmed by Namazu. Template matches can be "
                         "version-inferred rather than behaviour-proved, so confirm before reporting. "
                         "Template severity is the author's rating."),
            remediation=str(info.get("remediation") or "").strip()
                        or "Follow the guidance in the template references.",
            evidence={"source": "nuclei", "template": template, "matched_at": matched,
                      "cve": cve_id, "tags": info.get("tags"),
                      "matchers": [m for m in [record.get("matcher-name")] if m],
                      "extracted": record.get("extracted-results"),
                      "template_severity": info.get("severity")},
            highlights=[mark("nuclei", "proof", "Reported by the external tool, not by Namazu."),
                        *( [mark(cve_id, "weak", "The CVE the template matches.")] if cve_id else [] )],
        )
        seen[key] = item
        out.append(item)
    return out


# ── shared ───────────────────────────────────────────────────────────────────

def _missing(tool: str, install: str) -> dict:
    return {"tool": tool, "ran": False, "findings": [], "summary": {},
            "notes": [f"{tool} is not installed, so its checks did not run. Install it with: {install}"]}


def _failed(tool: str, reason: str, command: list) -> dict:
    return {"tool": tool, "ran": False, "findings": [], "summary": {},
            "command": _redact(command, {}), "notes": [f"{tool} did not complete. {reason}"]}


def _redact(command: list, headers: dict | None) -> list:
    """The command as run, with any header value replaced."""
    out, skip = [], False
    for part in command:
        if skip:
            skip = False
            name = str(part).split(":", 1)[0]
            out.append(f"{name}: <credential>")
            continue
        if part in ("--header", "-header", "-H"):
            skip = True
        out.append(part)
    return out
