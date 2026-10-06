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

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .model import finding, mark

TOOL_TIMEOUT = 600
MAX_FINDINGS = 60
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# Nuclei tags that probe destructively or generate traffic out of proportion to
# what they prove. Excluded always, not only in read-only mode.
# The full corpus is ~10k templates and takes far longer than an audit should.
# This set is the part that speaks to an HTTP API surface.
DEFAULT_NUCLEI_TAGS = "exposure,misconfig,config,default-login,api,tech"
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force,bruteforce"
ANSI = re.compile(chr(27) + '\\[[0-9;]*m')
NUCLEI_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium",
                       "low": "low", "info": "info", "unknown": "info"}


def _schemathesis_bin() -> str | None:
    """The st executable beside the running interpreter, or on PATH."""
    local = Path(sys.executable).parent / ("st.exe" if os.name == "nt" else "st")
    if local.exists():
        return str(local)
    return shutil.which("st") or shutil.which("schemathesis")


def _schemathesis_version() -> str | None:
    """Read it from package metadata; the CLI has no --version that prints one."""
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("schemathesis")
    except Exception:
        return None


def available() -> dict:
    """Which optional tools this machine can run."""
    tools = {}
    binary = _schemathesis_bin()
    tools["schemathesis"] = {
        "available": bool(binary), "path": binary,
        "version": _schemathesis_version() if binary else None,
        "install": "pip install schemathesis",
        "role": "Property-based contract testing from the same OpenAPI document.",
    }
    nuclei = shutil.which("nuclei")
    tools["nuclei"] = {
        "available": bool(nuclei), "path": nuclei,
        "version": _version([nuclei, "-version"]) if nuclei else None,
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "role": "Template signatures for known CVEs, exposed panels and misconfigurations.",
    }
    return tools


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
                     timeout: int = TOOL_TIMEOUT, verify_tls: bool = True) -> dict:
    """Property-based testing over the documented operations."""
    binary = _schemathesis_bin()
    if not binary:
        return _missing("schemathesis", "pip install schemathesis")

    with tempfile.TemporaryDirectory(prefix="namazu-st-") as workspace:
        report = Path(workspace) / "report.json"
        command = [binary, "run", schema, "--url", base_url,
                   "--max-examples", str(max_examples),
                   "--report", "json", "--report-json-path", str(report),
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
            detail = (err or out).strip().splitlines()[-3:]
            return _failed("schemathesis", "No report was produced. " + " ".join(detail), command)
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _failed("schemathesis", f"The report could not be read: {exc}.", command)

    findings = _schemathesis_findings(document)
    return {"tool": "schemathesis", "ran": True, "exit_code": code,
            "command": _redact(command, headers),
            "summary": _schemathesis_summary(document),
            "findings": [item.to_dict() for item in findings[:MAX_FINDINGS]],
            "truncated": len(findings) > MAX_FINDINGS, "notes": []}


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


# schemathesis failure types, mapped to how Namazu reports them. Severity comes
# from schemathesis itself where it supplies one; these are the fallbacks.
ST_CHECKS = {
    "IgnoredAuth": ("ignored-auth", "high", "API2:2023 Broken Authentication",
                    "The operation returned a success response to a request carrying invalid or "
                    "missing credentials, although the contract marks it as authenticated."),
    "ServerError": ("server-error", "medium", "API8:2023 Security Misconfiguration",
                    "The operation returned a 5xx response to an input the contract describes as "
                    "valid, so an unhandled path exists behind it."),
    "UndefinedStatusCode": ("undocumented-status", "low", "API9:2023 Improper Inventory Management",
                             "The operation returned a status code its own schema does not document."),
    "UndocumentedStatusCode": ("undocumented-status", "low", "API9:2023 Improper Inventory Management",
                               "The operation returned a status code its own schema does not document."),
    "AcceptedNegativeData": ("accepted-invalid", "low", "API3:2023 Broken Object Property Level Authorization",
                             "The operation accepted a request body that violates its own schema, so "
                             "input validation is weaker than the contract claims."),
    "RejectedPositiveData": ("rejected-valid", "low", "API9:2023 Improper Inventory Management",
                             "The operation rejected a request the contract says is valid, so the "
                             "schema and the implementation disagree."),
    "MissingContentType": ("content-type", "low", "API9:2023 Improper Inventory Management",
                           "A response arrived without a Content-Type the contract documents."),
    "MalformedMediaType": ("content-type", "low", "API9:2023 Improper Inventory Management",
                           "A response declared a media type that could not be parsed."),
    "ResponseConformance": ("response-schema", "low", "API9:2023 Improper Inventory Management",
                            "A response body did not match the schema the operation declares for it."),
}
ST_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _schemathesis_findings(document) -> list:
    """One finding per (failure type, operation) pair reported by schemathesis."""
    out = []
    for record in (document.get("failures") or []) if isinstance(document, dict) else []:
        if not isinstance(record, dict):
            continue
        kind = str(record.get("type") or "Unknown")
        title = str(record.get("title") or kind)
        check, fallback, owasp, explanation = ST_CHECKS.get(
            kind, (kind.lower() or "contract-violation", "low",
                   "API9:2023 Improper Inventory Management",
                   "schemathesis reported a disagreement between the implementation and its schema."))
        severity = ST_SEVERITY.get(str(record.get("severity") or "").lower(), fallback)
        operations = [str(item) for item in (record.get("operations") or []) if item] or ["(not reported)"]
        for endpoint in operations[:12]:
            out.append(finding(
                f"schemathesis.{check}", title, severity, "probable", owasp=owasp, endpoint=endpoint,
                method=("Generated by schemathesis, which derives inputs from the same OpenAPI document "
                        "and compares every response against the schema the operation declares. The "
                        f"check that fired was {kind}."),
                detail=f"{explanation} schemathesis recorded {record.get('count', 1)} case(s) for "
                       f"{endpoint}.",
                background=(
                    "Property-based testing generates many inputs the contract permits, rather than the "
                    "one example a hand-written test uses. Failures land where the implementation and "
                    "its own published schema disagree, which is where undocumented error paths and "
                    "unhandled types tend to live."),
                impact=("A response the contract does not describe is a response no client is written to "
                        "handle. An input the server mishandles is frequently the first step of a more "
                        "serious bug."),
                limitations=("Reported by schemathesis and not re-verified by Namazu. The generated "
                             "input may not correspond to anything a real client would send, so "
                             "reproduce it before reporting it. Re-run with the recorded seed to get "
                             "the same inputs."),
                remediation=("Handle the input explicitly and return a documented status, or correct the "
                             "schema so it describes what the operation actually accepts and returns."),
                evidence={"source": "schemathesis", "check": kind, "cases": record.get("count"),
                          "schemathesis_severity": record.get("severity"),
                          "seed": document.get("seed"),
                          "reproduce": "st run <schema> --url <base> --seed "
                                       f"{document.get('seed')}"},
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
        if failure:
            return _failed("nuclei", failure, command)
        lines = output.read_text(encoding="utf-8").splitlines() if output.exists() else []

    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    findings = _nuclei_findings(records)
    notes = []
    if not records and code not in (0,):
        notes.append((err or out).strip().splitlines()[-1] if (err or out).strip() else
                     f"nuclei exited with code {code}.")
    return {"tool": "nuclei", "ran": True, "exit_code": code,
            "command": _redact(command, headers),
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
    for index, part in enumerate(command):
        if skip:
            skip = False
            name = str(part).split(":", 1)[0]
            out.append(f"{name}: <credential>")
            continue
        if part in ("--header", "-header", "-H"):
            skip = True
        out.append(part)
    return out
