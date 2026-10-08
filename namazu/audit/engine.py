"""Audit orchestration.

Two entry points, both driven one step at a time by the client so progress is
visible and a run can be stopped between units of work:

* :func:`audit_operation`: the full battery against one documented operation.
* :func:`audit_inventory`:  the contract-wide surface sweep.

Profiles decide how much traffic is allowed:

``passive``   one baseline request per operation, then analysis only.
``readonly``  adds authorization, CORS, method and input probes on safe methods.
``writes``    adds mass-assignment and write-authorization probes. Requires the
              caller to pass ``allow_mutating``; the transport refuses otherwise.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..discovery import connection_for
from ..runner import normalize_spec
from ..signature import Signature
from ..spec import build_request
from . import (
    authz,
    bypass,
    catalogue,
    contract,
    inputs,
    inventory,
    jwtlab,
    passive,
    posture,
    specscan,
    xmllab,
)
from . import identity as identity_resolver
from .model import Finding, finding
from .transport import (
    MAX_CONCURRENCY,
    Budget,
    BudgetExhausted,
    Executor,
    MutationRefused,
    build_client,
)

PROFILES = {
    "passive": {"requests_per_operation": 1, "authz": False, "inputs": False,
                "posture": False, "writes": False, "rate_limit": False, "concurrency": 1},
    "readonly": {"requests_per_operation": 90, "authz": True, "inputs": True, "max_fields": 4,
                 "posture": True, "writes": False, "rate_limit": False, "concurrency": 4},
    # Timing is thorough only. A sleep payload holds a database thread, which
    # is the one probe in the read-only battery that costs the target
    # something, so it stays out of passive and readonly entirely.
    "thorough": {"time_based": True, "requests_per_operation": 160, "authz": True, "inputs": True, "max_fields": 6,
                 "posture": True, "writes": False, "rate_limit": True, "concurrency": 6},
    "writes": {"requests_per_operation": 220, "authz": True, "inputs": True, "max_fields": 6,
               "posture": True, "writes": True, "rate_limit": True, "concurrency": 4,
               "body_fields": 3},
}
DEFAULT_PROFILE = "readonly"


def _profile(name: str) -> dict:
    return PROFILES.get(name or DEFAULT_PROFILE, PROFILES[DEFAULT_PROFILE])


def _workers(settings: dict, override) -> int:
    """How many probes may be in flight at once.

    The profile picks a default; an operator who needs the target left alone
    can force it down to one, and the transport caps the top end.
    """
    if override is None:
        return int(settings.get("concurrency", 1))
    return max(1, min(int(override), MAX_CONCURRENCY))


def _declared(operation: dict, location: str) -> list:
    """The parameters an operation documents in one place, with their examples.

    Cookie parameters are included for the same reason header ones are: the
    contract names them as inputs, so they are inputs, whether or not the
    generated request happened to carry them.
    """
    out = []
    for item in (operation.get("parameters") or []):
        if item.get("in") != location or not item.get("name"):
            continue
        schema = item.get("schema") or {}
        out.append({"name": item["name"],
                    "example": item.get("example", schema.get("example")),
                    "default": schema.get("default"),
                    "type": schema.get("type")})
    return out


def _attach_commands(findings: list, source_url: str) -> list:
    """Give contract-only findings a way to be re-derived from a console."""
    for item in findings:
        if item.exchanges or item.commands:
            continue
        pointer = (item.evidence or {}).get("json_pointer")
        commands = catalogue.pointer_commands(source_url, pointer) if pointer else None
        if commands:
            item.commands = commands
    return findings


def _dedupe(findings: list) -> list:
    """One finding per (id, endpoint, parameter); keep the strongest."""
    best: dict = {}
    for item in findings:
        key = (item.id, item.endpoint, item.parameter)
        current = best.get(key)
        if current is None or item.sort_key() < current.sort_key():
            best[key] = item
    return sorted(best.values(), key=Finding.sort_key)


def summarize(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confidence = {"confirmed": 0, "probable": 0, "possible": 0}
    owasp: dict = {}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        confidence[item.confidence] = confidence.get(item.confidence, 0) + 1
        if item.owasp:
            owasp[item.owasp] = owasp.get(item.owasp, 0) + 1
    return {"total": len(findings), "severity": counts, "confidence": confidence, "owasp": owasp}


def audit_operation(spec: dict, operation_id: str, *, base_url: str | None = None,
                    identities: dict | None = None, profile: str = DEFAULT_PROFILE,
                    allow_mutating: bool = False, verify_tls: bool = True,
                    timeout: float = 15.0, concurrency: int | None = None,
                    user_agent: str | None = None, connection=None, client=None) -> dict:
    """Run the audit battery against one documented operation."""
    parsed = normalize_spec(spec)
    operation = next((op for op in parsed["operations"] if op["id"] == operation_id), None)
    if operation is None:
        raise ValueError(f"Unknown operation: {operation_id}")

    settings = _profile(profile)
    if settings["writes"] and not allow_mutating:
        raise ValueError("Write probes need allow_mutating; enable write requests first.")

    # The token summaries are deliberately dropped: an access token must not
    # travel into a report, and the summary is only useful to the Auth panel.
    link = connection_for(connection, verify_tls, user_agent)
    identity_a, _token_a, note_a = identity_resolver.resolve(
        identities, "primary", verify_tls=verify_tls, timeout=timeout, user_agent=user_agent,
        connection=link)
    identity_b, _token_b, note_b = identity_resolver.resolve(
        identities, "secondary", verify_tls=verify_tls, timeout=timeout, user_agent=user_agent,
        connection=link)
    credential_notes = [note for note in (note_a, note_b) if note]
    endpoint = f"{operation['method']} {operation['path']}"

    findings: list = list(specscan.review_operation(parsed, operation))

    built = build_request(parsed, operation_id, base_url=base_url, headers=identity_a)
    budget = Budget(settings["requests_per_operation"])
    owns_client = client is None
    http = client or build_client(connection=link)
    workers = _workers(settings, concurrency)
    executor = Executor(http, budget, timeout=timeout, allow_mutating=allow_mutating,
                        concurrency=workers, signature=Signature(quiet=link.quiet))
    notes: list[str] = list(credential_notes)
    # Said before anything else, because a run whose requests do not name the
    # tool has to be attributable from the report instead.
    if (quiet_note := executor.signature.describe()):
        notes.insert(0, quiet_note)
    # Whatever went wrong building the documented request. An unresolved schema
    # reference puts null where a field should be, which the target rejects or
    # answers wrongly, and then most probes stop at the baseline. The audit used
    # to discard these, so a report could be thin for a stated reason nobody
    # was ever shown.
    for warning in built.get("warnings") or []:
        notes.append(f"Building the documented request: {warning}")

    try:
        baseline = executor.send(
            built["method"], built["url"], label="baseline",
            headers=built["headers"],
            body=_body_text(built), content_type=built.get("content_type"),
            identity="identity A" if identity_a else "anonymous",
            mutating=built["method"] not in ("GET", "HEAD", "OPTIONS", "TRACE"),
        )
    except MutationRefused:
        if owns_client:
            http.close()
        return _skipped(endpoint, operation, findings, budget, profile,
                        source_url=parsed.get("source_url") or "", executor=executor, reason=(
            f"{operation['method']} requests change server state, so this operation was reviewed from "
            "its contract only. Choose the write profile and enable Allow writes to probe it."))
    except BudgetExhausted as exc:
        if owns_client:
            http.close()
        return _skipped(endpoint, operation, findings, budget, profile,
                        source_url=parsed.get("source_url") or "", executor=executor,
                        reason=str(exc))

    if not baseline.ok:
        result = _result(endpoint, operation, _dedupe(findings), budget, profile,
                         notes=[f"The baseline request failed: {baseline.error}"], baseline=baseline,
                         source_url=parsed.get("source_url") or "", executor=executor)
        if owns_client:
            http.close()
        return result

    tls_findings = posture.inspect_tls(built["url"], timeout=min(timeout, 10.0))
    findings += tls_findings
    notes += _route_notes(link, url=built["url"], tls_inspected=bool(tls_findings))
    findings += contract.review(parsed, operation, baseline, endpoint)
    findings += inventory.zombie_check(baseline, endpoint)
    findings += passive.review(baseline, endpoint=endpoint, operation=operation,
                               document=parsed.get("document") or {})

    if identity_a:
        for weakness_finding in _supplied_token_findings(identity_a, endpoint):
            findings.append(weakness_finding)

    try:
        if settings["authz"]:
            findings += authz.probe(
                executor, baseline=baseline, endpoint=endpoint, operation=operation,
                identity_a=identity_a, identity_b=identity_b, base_headers=built["headers"],
                notes=notes,
            )
            findings += contract.invalid_credentials(
                executor, baseline=baseline, endpoint=endpoint, operation=operation,
                identity=identity_a, headers=built["headers"])
            findings += bypass.probe(executor, baseline=baseline, endpoint=endpoint,
                                     headers=built["headers"])
            findings += bypass.cache_deception(executor, baseline=baseline, endpoint=endpoint,
                                               headers=built["headers"])
            documented = {op["method"] for op in parsed["operations"] if op["path"] == operation["path"]}
            findings += inventory.allowed_methods(
                executor, url=built["url"], endpoint=endpoint,
                headers=built["headers"], documented=documented,
            )
        if settings.get("posture"):
            findings += posture.review(
                executor, baseline=baseline, endpoint=endpoint, headers=built["headers"],
                operation=operation, base_url=built["url"],
                do_rate_limit=settings.get("rate_limit", False),
            )
        if settings["inputs"]:
            documented_query = [
                {"name": p.get("name"),
                 "example": p.get("example", (p.get("schema") or {}).get("example")),
                 "default": (p.get("schema") or {}).get("default"),
                 "type": (p.get("schema") or {}).get("type")}
                for p in (operation.get("parameters") or [])
                if p.get("in") == "query" and p.get("name")
            ]
            findings += inputs.probe(executor, baseline=baseline, endpoint=endpoint,
                                     base_headers=built["headers"],
                                     documented_query=documented_query,
                                     documented_header=_declared(operation, "header"),
                                     documented_cookie=_declared(operation, "cookie"),
                                     documented_path=_declared(operation, "path"),
                                     path_template=operation["path"],
                                     max_fields=settings.get("max_fields", 3),
                                     time_based=settings.get("time_based", False))
        if settings["writes"]:
            findings += _write_probes(executor, parsed, operation, built, endpoint,
                                      built["headers"], identity_b, notes, baseline,
                                      settings.get("body_fields", 3))
    except BudgetExhausted:
        notes.append(f"Request budget of {budget.limit} reached; some probes did not run.")
    except MutationRefused as exc:
        notes.append(str(exc))
    finally:
        if owns_client:
            http.close()

    if settings["writes"] is False and operation["method"] not in ("GET", "HEAD", "OPTIONS", "TRACE"):
        notes.append("Active probes are limited to read-only methods, so this operation received the "
                     "contract review and its baseline response only.")

    if budget.declined or budget.refused:
        notes.append(f"The request budget of {budget.limit} was reached, so some probes did not run. "
                     "Choose a profile with a larger budget to finish this operation.")
    return _result(endpoint, operation, _dedupe(findings), budget, profile, notes=notes,
                   baseline=baseline, source_url=parsed.get("source_url") or "", executor=executor)


def _body_text(built: dict):
    import json
    if not built.get("has_body"):
        return None
    body = built.get("body")
    if isinstance(body, str):
        return body
    media = str(built.get("content_type") or "")
    if "json" in media:
        return json.dumps(body)
    return json.dumps(body) if body is not None else None


def _supplied_token_findings(identity_a: dict, endpoint: str) -> list:
    """Offline weaknesses in the credential the operator supplied."""
    token = jwtlab.bearer_token(identity_a)
    if not token:
        return []
    report = jwtlab.analyze(token)
    if not report.get("valid"):
        return []
    out = []
    for weakness in report["weaknesses"]:
        if weakness["id"] in ("expired",):
            continue
        out.append(finding(
            f"jwt.{weakness['id']}", f"Supplied JWT: {weakness['id'].replace('-', ' ')}",
            weakness["severity"], "confirmed", owasp="API2:2023 Broken Authentication",
            endpoint=endpoint,
            detail=weakness["detail"] + " Determined offline from the token you supplied; no request was sent.",
            impact=("The signing key is recoverable, so a token can be minted for any user."
                    if weakness["id"] == "weak-secret"
                    else "Reduces the guarantees the token is meant to provide."),
            remediation=("Rotate to a high-entropy secret of at least 256 bits or asymmetric signing."
                         if weakness["id"] == "weak-secret"
                         else "Set a short exp, pin the key source, and keep sensitive data out of the payload."),
            evidence={"algorithm": report["algorithm"], "key_id": report.get("key_id"),
                      "cracked_secret": report.get("cracked_secret"),
                      "privilege_claims": report.get("privilege_claims")},
        ))
    return out


def _write_probes(executor, parsed, operation, built, endpoint, headers, identity_b, notes,
                  baseline=None, body_fields: int = 3) -> list:
    """The probes that change state, cheapest and most conclusive first.

    Mass assignment and write authorization go first because each is a couple
    of requests and either can be confirmed outright. The body injection
    battery runs last: it is the one that costs tens of requests, so if the
    budget runs out it should be the probe that gets cut.
    """
    out: list = []
    method = operation["method"]
    if method not in ("POST", "PUT", "PATCH"):
        return out

    # An operation that takes XML gets the external entity probes. Three
    # requests, run before the injection battery because that one costs tens
    # and is the right thing to lose if the budget runs out.
    xml_media = xmllab.request_media(operation)
    if xml_media and baseline is not None:
        probes = xmllab.probe(executor, baseline=baseline, operation=operation,
                              endpoint=endpoint, base_headers=headers, media=xml_media)
        out += probes
        if not probes:
            notes.append(f"The XML body for this operation ({xml_media}) was probed for external "
                         "entity processing and nothing was found.")
    privileged = [
        item.parameter for item in specscan.review_operation(parsed, operation)
        if item.id == "spec.mass-assignment-surface" and item.parameter
    ]
    properties = [name.strip() for entry in privileged for name in entry.split(",") if name.strip()]
    if properties:
        read_back = built["url"] if method in ("PUT", "PATCH") else None
        out += inputs.mass_assignment(executor, built=built, endpoint=endpoint, base_headers=headers,
                                      properties=properties, read_back_url=read_back)
    else:
        notes.append("No privileged properties in the request schema, so no mass-assignment probe ran.")
    if identity_b:
        out += inputs.write_authorization(executor, built=built, endpoint=endpoint,
                                          base_headers=headers, identity_b=identity_b,
                                          notes=notes)
    if baseline is not None:
        out += _body_probes(executor, baseline, endpoint, headers, method, body_fields, notes)
    return out


def _body_probes(executor, baseline, endpoint, headers, method, body_fields, notes) -> list:
    """The injection battery over request body fields, with its cost disclosed."""
    before = len([item for item in executor.exchanges if item.mutating])
    findings, probed = inputs.body_injection(
        executor, baseline=baseline, endpoint=endpoint, base_headers=headers,
        max_fields=body_fields)
    sent = len([item for item in executor.exchanges if item.mutating]) - before
    if not probed:
        notes.append("The request body has no scalar fields to probe, so no body injection "
                     "probe ran.")
    elif sent:
        # Each of these wrote to the target. Saying so is the difference between
        # a disclosed side effect and a surprise in someone else's data.
        notes.append(
            f"The body injection battery probed {', '.join(probed)} and sent {sent} "
            f"state-changing {method} requests, each carrying a probe value. Review the "
            "objects this created or modified on the target and remove them.")
    return findings


def _skipped(endpoint, operation, findings, budget, profile, *, reason: str,
             source_url: str = "", executor=None) -> dict:
    return _result(endpoint, operation, _dedupe(findings), budget, profile, notes=[reason],
                   source_url=source_url, executor=executor)


MAX_LOG_ENTRIES = 200
# How much of a response body each log entry carries. Wider than the excerpt in
# a finding's proof, because the traffic view is the only place an operator
# reads a request that produced no finding, and narrow enough that two hundred
# of them do not turn one operation's result into a download.
LOG_BODY_CHARS = 2000


def _log(executor, endpoint: str) -> list:
    """Every request the audit made, in order, whether or not it produced a finding."""
    if executor is None:
        return []
    entries = []
    for index, exchange in enumerate(executor.exchanges[:MAX_LOG_ENTRIES]):
        record = exchange.to_dict()
        # body_length stays the real length, so the UI can say how much of the
        # body it is showing rather than implying this is all of it.
        record["body_excerpt"] = exchange.excerpt(LOG_BODY_CHARS)
        entries.append({**record, "endpoint": endpoint, "seq": index + 1})
    return entries


def _route_notes(link, *, url: str = "", tls_inspected: bool = False) -> list[str]:
    """What the report should say about how the requests left.

    Empty for a direct connection, because a report that states the default
    tells the reader nothing.
    """
    described = link.describe()
    notes = [described] if described else []
    # The certificate inspection opens its own TLS socket rather than going
    # through the proxy, on purpose: a proxy that intercepts TLS presents its
    # own certificate, so routing this would inspect the proxy, not the target.
    if link.routed and tls_inspected and url.lower().startswith("https://"):
        notes.append("The certificate inspection connected to the host directly, not through the "
                     "proxy, so that it read the target's own certificate rather than the proxy's.")
    return notes


def _result(endpoint, operation, findings, budget, profile, *, notes=None, baseline=None,
            source_url: str = "", executor=None) -> dict:
    _attach_commands(findings, source_url)
    log = _log(executor, endpoint)
    if executor is not None and len(executor.exchanges) > MAX_LOG_ENTRIES:
        (notes := list(notes or [])).append(
            f"The request log keeps the first {MAX_LOG_ENTRIES} of {len(executor.exchanges)} requests.")
    return {
        "endpoint": endpoint,
        "operation_id": operation["id"],
        "method": operation["method"],
        "path": operation["path"],
        "profile": profile,
        "requests_sent": budget.spent,
        "request_budget": budget.limit,
        "concurrency": executor.concurrency if executor is not None else 1,
        "baseline_status": baseline.status if baseline is not None else None,
        "notes": [note for note in (notes or []) if note],
        "baseline": baseline.to_dict() if baseline is not None else None,
        "log": log,
        "findings": [item.to_dict() for item in findings],
        "summary": summarize(findings),
    }


def audit_inventory(spec: dict, *, base_url: str | None = None, identities: dict | None = None,
                    verify_tls: bool = True, timeout: float = 15.0, budget: int = 60,
                    connection=None,
                    concurrency: int | None = None, user_agent: str | None = None,
                    client=None) -> dict:
    """Sweep the host around the documented surface. Read-only."""
    parsed = normalize_spec(spec)
    target = base_url or parsed.get("base_url") or ""
    if not target:
        raise ValueError("Set a base URL before running the inventory sweep.")
    if urlsplit(target).scheme not in ("http", "https"):
        raise ValueError("The base URL must begin with http:// or https://.")

    link = connection_for(connection, verify_tls, user_agent)
    identity_a, _token, credential_note = identity_resolver.resolve(
        identities, "primary", verify_tls=verify_tls, timeout=timeout, user_agent=user_agent,
        connection=link)
    findings = list(specscan.review_document(parsed))
    documented_paths = {op["path"] for op in parsed["operations"]}

    tracker = Budget(budget)
    owns_client = client is None
    http = client or build_client(connection=link)
    signature = Signature(quiet=link.quiet)
    executor = Executor(http, tracker, timeout=timeout, allow_mutating=False,
                        concurrency=_workers(PROFILES["readonly"], concurrency),
                        signature=signature)
    try:
        probe_findings, summary = inventory.run(
            executor, spec=parsed, base_url=target, headers=identity_a,
            documented_paths=documented_paths,
        )
        findings += probe_findings
    finally:
        if owns_client:
            http.close()

    deduped = _dedupe(_attach_commands(findings, parsed.get("source_url") or ""))
    return {
        "scope": "inventory",
        "base_url": target,
        "profile": "readonly",
        "requests_sent": tracker.spent,
        "request_budget": tracker.limit,
        "concurrency": executor.concurrency,
        "discovery": summary,
        "log": _log(executor, "surface sweep"),
        "notes": ([credential_note] if credential_note else [])
                 + ([signature.describe()] if signature.describe() else [])
                 + _route_notes(link)
                 + (["Request budget reached; the sweep stopped early."] if summary.get("budget_exhausted") else []),
        "findings": [item.to_dict() for item in deduped],
        "summary": summarize(deduped),
    }
