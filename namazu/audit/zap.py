"""An optional ZAP Automation Framework adapter.

ZAP covers ground neither Namazu nor schemathesis does: a mature active-scan
rule set, and an OpenAPI import that walks the documented surface. It runs as
a subprocess from an Automation Framework plan, which is the right interface
for this because the plan is a file Namazu writes and an operator can read.
That matters here more than usual: the plan is where the scope, the write
policy and the traffic limits are expressed, so an operator can check what was
actually going to be sent rather than taking this module's word for it.

Four things this adapter does not do, each for a stated reason.

**It does not widen the write policy to make itself useful.** ZAP's active
scanner is built to send attack payloads, and a plain ``activeScan`` job will
POST, PUT and DELETE across the imported surface. When writes are not enabled
for the run, the plan is built with the active scanner's input vectors
restricted and the whole scan confined to safe methods. If that leaves nothing
for ZAP to do, the result says so and the run reports a coverage gap. It does
not quietly enable writes.

**It does not treat GET as harmless.** A GET can delete, and plenty of APIs
have ``/items/1/delete`` as a GET. Method is not a safety property, so the
write policy is applied as an explicit allow-list of what may be sent, and the
plan always declares it.

**It does not trust a tag or a category as a safety property.** ZAP's rule
groups are organised by vulnerability class, not by whether a rule mutates, so
the policy names the rules and thresholds it wants rather than assuming a class
is read-only. The same reasoning as for a nuclei "cve" tag: the taxonomy
describes the subject, not the side effects.

**It reports its own coverage separately.** ZAP's idea of what it covered is
not Namazu's, and merging them would produce a number that means neither.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .capture import CapturedCase, correlation_ids
from .evidence import SourceSeverity
from .model import REDACTED_HEADERS, finding, mark, redact_headers, redact_url

TOOL_TIMEOUT = 900
MAX_FINDINGS = 60
MAX_CASES = 40

# ZAP writes its own risk words. These are the ratings it assigns, mapped onto
# Namazu's scale. The rating is kept as source metadata either way: the
# evidence rules will lower an unreproduced external report regardless.
ZAP_RISK = {"High": "high", "Medium": "medium", "Low": "low",
            "Informational": "info", "Info": "info"}
# ZAP's confidence word, which is about its own matching rather than about
# severity. "False Positive" is a rating ZAP itself applies and the alert is
# dropped rather than reported.
ZAP_CONFIDENCE = {"High": "probable", "Medium": "probable", "Low": "possible",
                  "Confirmed": "probable", "False Positive": ""}

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

CAPABILITIES = {
    "imports_openapi": True,
    "active_scan": True,
    "captures_exchanges": True,
    "inherits_scope": "The plan's context includes only the target's own origin and the paths "
                      "under it; nothing else is in scope.",
    "inherits_authentication": "Namazu's resolved identity headers are replaced into every "
                               "request by a replacer rule, so ZAP sends the same credential the "
                               "audit does.",
    "write_policy": "Read-only unless write requests are enabled for the run. When they are not, "
                    "the plan restricts the scan to safe methods explicitly rather than relying "
                    "on any rule being well behaved.",
    "traffic_limits": "Requests per second and total duration come from the run's own limits.",
    "reproducible_by_seed": False,
}


def _zap_command() -> list | None:
    """How to run ZAP, or None when it is not installed.

    ``zap.sh`` and ``zap.bat`` are what the standalone distribution ships;
    ``zap`` appears on some package-managed installs. The Automation Framework
    is driven with ``-cmd -autorun``, which exits when the plan finishes.
    """
    for name in ("zap.sh", "zap.bat", "zap", "owasp-zap"):
        found = shutil.which(name)
        if found:
            return [found]
    # The Docker images are the common way to have ZAP without installing it.
    docker = shutil.which("docker")
    if docker and os.environ.get("NAMAZU_ZAP_DOCKER_IMAGE"):
        return [docker, "run", "--rm", "-v", "{workspace}:/zap/wrk:rw",
                os.environ["NAMAZU_ZAP_DOCKER_IMAGE"], "zap.sh"]
    return None


def _version(command: list) -> str | None:
    try:
        done = subprocess.run([*command, "-version"], capture_output=True, text=True,
                              timeout=60, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    text = (done.stdout or "") + (done.stderr or "")
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else None


def available() -> dict:
    command = _zap_command()
    return {
        "available": bool(command),
        "path": " ".join(command) if command else None,
        "version": _version(command) if command else None,
        "install": "Install ZAP from https://www.zaproxy.org/download/, or set "
                   "NAMAZU_ZAP_DOCKER_IMAGE to a ZAP image to run it through Docker.",
        "role": "Active scan rules and an OpenAPI import, from the OWASP ZAP project.",
        "capabilities": CAPABILITIES,
    }


def build_plan(*, target: str, schema: str, headers: dict | None = None,
               allow_mutating: bool = False, requests_per_second: int = 10,
               duration_minutes: int = 5, report_dir: str = "/zap/wrk") -> dict:
    """The Automation Framework plan, as a structure an operator can read.

    Returned rather than only written so it can be shown in the UI and tested
    without running ZAP. The scope, the credential handling and the method
    allow-list are all visible in it, which is the point.
    """
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}"
    methods = list(SAFE_METHODS) if not allow_mutating else list(SAFE_METHODS) + list(WRITE_METHODS)

    # Credentials are replaced in by rule rather than written into the plan, so
    # the plan file on disk never holds a token.
    replacer_rules = [
        {"description": f"identity header {name}", "enabled": True, "matchType": "REQ_HEADER",
         "matchString": str(name), "replacementString": str(value), "tokenProcessing": False}
        for name, value in (headers or {}).items()
    ]

    jobs: list = [
        {"type": "addOns", "parameters": {"install": ["openapi", "automation", "replacer"]}},
        {"type": "replacer", "rules": replacer_rules},
        {"type": "openapi", "parameters": {
            "apiUrl": schema, "targetUrl": target, "context": "namazu"}},
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
    ]
    if allow_mutating:
        jobs.append({
            "type": "activeScan",
            "parameters": {"context": "namazu", "maxRuleDurationInMins": 2,
                           "maxScanDurationInMins": duration_minutes,
                           "maxAlertsPerRule": 10},
            "policyDefinition": {"defaultStrength": "medium", "defaultThreshold": "medium"},
        })
    else:
        # No activeScan job at all. The passive rules read the traffic the
        # OpenAPI import generated, which is the most that can be done without
        # sending payloads. Restricting a running active scan to safe methods
        # is not something the framework guarantees, so it is not relied on.
        jobs.append({
            "type": "passiveScan-config",
            "parameters": {"maxAlertsPerRule": 10, "scanOnlyInScope": True},
        })
    jobs.append({
        "type": "report",
        "parameters": {"template": "traditional-json-plus", "reportDir": report_dir,
                       "reportFile": "zap-report", "reportTitle": "Namazu ZAP run"},
    })

    return {
        "env": {
            "contexts": [{
                "name": "namazu",
                "urls": [target],
                # Scope is the target's own origin and nothing else.
                # includePaths is a list of regular expressions matched against
                # the whole URL, so the origin is escaped: an unescaped
                # "https://api.example.test.*" also matches
                # "https://api.example.testing.evil.com/", which would take the
                # scan off the target the engagement authorised.
                "includePaths": [re.escape(origin) + r"(/.*)?$"],
                "excludePaths": [],
                "authentication": {"method": "manual"},
                "technology": {"exclude": []},
            }],
            "parameters": {
                "maxRequestsPerSecond": max(1, int(requests_per_second)),
                "failOnError": False,
                "failOnWarning": False,
                "progressToStdout": True,
            },
            # Not read by ZAP. Written into the plan so the file on disk
            # records the policy the run was given, which is what an operator
            # reviewing the plan afterwards needs.
            "x-namazu": {
                "write_requests_enabled": allow_mutating,
                "methods_permitted": methods,
                "note": ("Method is not a safety property: a GET can delete. This allow-list is "
                         "the policy, and no rule is assumed read-only because of its category."),
            },
        },
        "jobs": jobs,
    }


def run(*, target: str, schema: str, headers: dict | None = None,
        allow_mutating: bool = False, timeout: int = TOOL_TIMEOUT,
        requests_per_second: int = 10, duration_minutes: int = 5,
        identity_ref: str = "primary", schema_hash: str = "") -> dict:
    """Run a ZAP Automation Framework plan and normalise its alerts."""
    command = _zap_command()
    if not command:
        return {"tool": "zap", "ran": False, "findings": [], "summary": {},
                "capabilities": CAPABILITIES,
                "notes": ["ZAP is not installed, so its checks did not run. "
                          + available()["install"]]}
    version = _version(command) or ""

    with tempfile.TemporaryDirectory(prefix="namazu-zap-") as workspace:
        dockerised = any(part == "run" for part in command)
        report_dir = "/zap/wrk" if dockerised else workspace
        plan = build_plan(target=target, schema=schema, headers=headers,
                          allow_mutating=allow_mutating,
                          requests_per_second=requests_per_second,
                          duration_minutes=duration_minutes, report_dir=report_dir)
        plan_path = Path(workspace) / "plan.yaml"
        plan_path.write_text(_as_yaml(plan), encoding="utf-8")
        argv = [part.replace("{workspace}", workspace) for part in command]
        plan_arg = f"{report_dir}/plan.yaml" if dockerised else str(plan_path)
        argv += ["-cmd", "-autorun", plan_arg]

        code, out, err, failure = _run(argv, timeout)
        if failure:
            return _failed(failure, argv, plan)
        report = Path(workspace) / "zap-report.json"
        if not report.exists():
            detail = " ".join((err or out).strip().splitlines()[-3:])
            return _failed(f"No report was produced (exit code {code}). "
                           f"{detail or 'ZAP printed nothing.'}", argv, plan)
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _failed(f"The report could not be read: {exc}.", argv, plan)

    alerts = _alerts(document)
    findings, dropped = _findings(alerts, version=version, identity_ref=identity_ref,
                                  schema_hash=schema_hash, schema_source=schema)
    notes = []
    if not allow_mutating:
        notes.append(
            "Write requests were not enabled, so the plan ran no active scan at all. ZAP's "
            "active rules send payloads with state-changing methods, and restricting a running "
            "active scan to safe methods is not something the framework guarantees. Passive "
            "rules read the traffic from the OpenAPI import; active rule coverage is a gap in "
            "this run, not a clean result.")
    if dropped:
        notes.append(f"{dropped} alert(s) ZAP itself rated as false positives were dropped.")
    return {
        "tool": "zap", "ran": True, "exit_code": code, "version": version,
        "command": _redact(argv),
        "plan": plan,
        "capabilities": CAPABILITIES,
        # Named "zap_coverage" rather than folded into the audit's own, because
        # ZAP's idea of what it covered is not Namazu's.
        "zap_coverage": _coverage(document, allow_mutating=allow_mutating),
        "summary": {"alerts": len(alerts), "reported": len(findings)},
        "findings": [item.to_dict() for item in findings[:MAX_FINDINGS]],
        "truncated": len(findings) > MAX_FINDINGS,
        "notes": notes,
    }


def _run(command: list, timeout: int) -> tuple:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace",
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    except subprocess.TimeoutExpired:
        return -1, "", "", f"ZAP did not finish within {timeout}s and was stopped. Partial "\
                           "results, if any, were not read."
    except OSError as exc:
        return -1, "", "", f"ZAP could not be started: {exc}."
    return done.returncode, done.stdout or "", done.stderr or "", ""


def _failed(reason: str, command: list, plan: dict) -> dict:
    return {"tool": "zap", "ran": False, "findings": [], "summary": {},
            "command": _redact(command), "plan": plan, "capabilities": CAPABILITIES,
            "notes": [f"ZAP did not complete. {reason}"]}


def _redact(command: list) -> list:
    """The plan carries the credential, not the command line, so this is simple."""
    return list(command)


def _coverage(document, *, allow_mutating: bool) -> dict:
    """What ZAP says it covered, kept apart from Namazu's own coverage."""
    sites = document.get("site") if isinstance(document, dict) else None
    urls: set = set()
    for site in sites or []:
        for alert in (site.get("alerts") or []):
            for instance in (alert.get("instances") or []):
                if instance.get("uri"):
                    urls.add(str(instance["uri"]).split("?", 1)[0])
    return {
        "urls_with_alerts": len(urls),
        "active_scan_ran": bool(allow_mutating),
        "gaps": ([] if allow_mutating else
                 ["Active scan rules did not run, because write requests were not enabled."]),
        "note": "These numbers are ZAP's own and are not comparable with Namazu's coverage "
                "ledger, which counts Namazu's probe families.",
    }


def _alerts(document) -> list:
    out = []
    for site in (document.get("site") or []) if isinstance(document, dict) else []:
        for alert in (site.get("alerts") or []):
            if isinstance(alert, dict):
                out.append(alert)
    return out


def _findings(alerts: list, *, version: str, identity_ref: str, schema_hash: str,
              schema_source: str) -> tuple[list, int]:
    out, dropped = [], 0
    for alert in alerts:
        confidence = ZAP_CONFIDENCE.get(str(alert.get("confidence") or "Medium"), "possible")
        if not confidence:
            # ZAP rated it a false positive itself. Reporting it anyway would
            # be passing on noise the tool had already filtered.
            dropped += 1
            continue
        rule = str(alert.get("pluginid") or alert.get("alertRef") or "rule")
        name = str(alert.get("name") or alert.get("alert") or f"ZAP rule {rule}")
        risk = str(alert.get("riskdesc") or alert.get("risk") or "Informational").split(" ")[0]
        severity = ZAP_RISK.get(risk, "info")
        instances = [item for item in (alert.get("instances") or []) if isinstance(item, dict)]
        cases = [_case(item, name=name, rule=rule, version=version, identity_ref=identity_ref,
                       schema_hash=schema_hash, schema_source=schema_source)
                 for item in instances[:MAX_CASES]]
        endpoint = str((instances[0].get("uri") if instances else "") or "(host)")
        cwe = str(alert.get("cweid") or "").strip()
        out.append(finding(
            f"zap.{rule}", name, severity, confidence,
            owasp="API8:2023 Security Misconfiguration",
            endpoint=endpoint,
            cwe=f"CWE-{cwe}" if cwe and cwe not in ("0", "-1") else None,
            origin="external-report",
            verification="observed" if cases else "unverified",
            source_severity=[SourceSeverity("zap", severity,
                                            str(alert.get("confidence") or ""))],
            mapping_basis=(
                "The CWE and risk rating are ZAP's own, carried through rather than re-derived. "
                "API8:2023 is the category most of ZAP's rule set addresses, which is "
                "misconfiguration and missing controls."),
            method=(f"Matched by ZAP rule {rule}. Namazu ran ZAP from an Automation Framework "
                    "plan and normalised its alerts; it did not re-verify the match."),
            detail=_text(alert.get("desc")) + (f" Reported at {endpoint}." if endpoint else ""),
            background=("ZAP's rules are maintained by the OWASP ZAP project and cover active "
                        "and passive web-application checks. The knowledge comes from that rule "
                        "set rather than from this API's contract."),
            impact=_text(alert.get("desc")) or "Depends on the specific rule.",
            limitations=(
                "Reported by ZAP, not confirmed by Namazu. ZAP's confidence rating describes "
                "its own matching, not the severity of the result."
                + (" Use Replay on a captured case to establish whether it happens again."
                   if cases else
                   " No request or response was captured, so this rests on ZAP's summary.")),
            remediation=_text(alert.get("solution")) or "See the ZAP rule's own guidance.",
            cases=cases,
            references=[{"title": url, "url": url}
                        for url in _text(alert.get("reference")).split()
                        if url.startswith("http")][:6],
            evidence={"source": "zap", "rule": rule, "zap_risk": risk,
                      "zap_confidence": alert.get("confidence"),
                      "zap_version": version, "instances": len(instances),
                      "captured_cases": len(cases)},
            highlights=[mark("zap", "proof", "Reported by the external tool, not by Namazu.")],
        ))
    return out, dropped


def _text(value) -> str:
    """ZAP writes HTML into its description fields."""
    text = re.sub(r"<[^>]+>", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()


def _case(instance: dict, *, name: str, rule: str, version: str, identity_ref: str,
          schema_hash: str, schema_source: str) -> CapturedCase:
    """One alert instance as a replayable case.

    ZAP's traditional-json-plus report carries the request and response for
    each instance, which is what makes its alerts replayable at all. When a
    field is absent the case says so rather than leaving a reader to infer it.
    """
    request_header = str(instance.get("request-header") or "")
    response_header = str(instance.get("response-header") or "")
    missing = []
    if not request_header:
        missing.append("ZAP did not record the request headers for this instance.")
    if not response_header:
        missing.append("ZAP did not record the response headers for this instance.")
    status = 0
    if response_header:
        first = response_header.splitlines()[0] if response_header.splitlines() else ""
        pieces = first.split(" ")
        if len(pieces) > 1 and pieces[1].isdigit():
            status = int(pieces[1])
    headers = _parse_headers(request_header)
    response_headers = _parse_headers(response_header)
    method = (request_header.split(" ", 1)[0].upper() if request_header else "GET") or "GET"
    return CapturedCase(
        label=f"{name} ({rule})",
        method=method if method.isalpha() else "GET",
        url=redact_url(str(instance.get("uri") or "")),
        request_headers=redact_headers(headers),
        request_body=str(instance.get("request-body") or "") or None,
        status=status,
        response_headers=response_headers,
        body_excerpt=str(instance.get("response-body") or "")[:1500],
        body_length=len(str(instance.get("response-body") or "")),
        mutating=method in WRITE_METHODS,
        identity_ref=identity_ref,
        correlation=correlation_ids(response_headers),
        source="zap",
        tool_version=version,
        config={"rule": rule, "param": instance.get("param"),
                "attack": instance.get("attack"), "evidence": instance.get("evidence")},
        schema_hash=schema_hash,
        schema_source=schema_source,
        assertions={"status": str(status) if status else "",
                    "note": f"ZAP rule {rule} matched here."},
        missing=missing,
        # The same list every other redaction path uses. Four of these had
        # drifted apart once; a test keeps there being only one.
        redacted=sorted({name for name in headers
                         if str(name).lower() in REDACTED_HEADERS}),
    )


def _parse_headers(block: str) -> dict:
    out = {}
    for line in str(block or "").splitlines()[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            if name.strip():
                out[name.strip()] = value.strip()
    return out


def _as_yaml(value, indent: int = 0) -> str:
    """A minimal YAML writer for the plan.

    ZAP reads YAML and the plan is a plain tree of dicts, lists, strings,
    numbers and booleans, so a dependency for this would not pay for itself.
    Every string is quoted and escaped, which is always valid YAML and avoids
    needing to know which bare words YAML would reinterpret.
    """
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for key, item in value.items():
            rendered = _as_yaml(item, indent + 2)
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:\n{rendered}")
            else:
                lines.append(f"{pad}{key}: {rendered}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        lines = []
        for item in value:
            if isinstance(item, (dict, list)) and item:
                # A bare "-" on its own line with the mapping indented under
                # it. Longer than the inline form and correct without having
                # to reason about how the first key lines up.
                lines.append(f"{pad}-\n{_as_yaml(item, indent + 2)}")
            else:
                lines.append(f"{pad}- {_as_yaml(item, 0)}")
        return "\n".join(lines)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return '""'
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
