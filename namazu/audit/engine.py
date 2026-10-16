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
from ..runner import credential_names_for, normalize_spec, redact_evidence
from ..signature import Signature
from ..spec import build_request
from . import (
    authz,
    bypass,
    campaign,
    catalogue,
    contract,
    coverage,
    inputs,
    inventory,
    jwtlab,
    passive,
    posture,
    specscan,
    xmllab,
)
from . import (
    baseline as baseline_module,
)
from . import identity as identity_resolver
from .model import Exchange, Finding, finding
from .response_compare import comparison_facts, normalize_policy
from .transport import (
    MAX_CONCURRENCY,
    Budget,
    BudgetExhausted,
    Cancelled,
    Executor,
    MutationRefused,
    RateLimited,
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


def _limit(settings, request_budget=None):
    ceiling = settings["requests_per_operation"]
    return min(ceiling, max(1, int(request_budget))) if request_budget is not None else ceiling


def _check_example_scope(built, target):
    original, saved = urlsplit(target), urlsplit(built["url"])
    if ((original.scheme, original.hostname, original.port) != (saved.scheme, saved.hostname, saved.port)
            or saved.username or saved.password):
        raise ValueError("Saved request URL must remain within the selected target origin.")
    prefix = original.path.rstrip("/")
    if prefix and saved.path != prefix and not saved.path.startswith(prefix + "/"):
        raise ValueError("Saved request URL must remain within the selected base URL path.")


def _schema_plan(parsed, operation, built, settings, allow_mutating, request_budget, credential_names=()):
    return campaign.plan_campaign(parsed, operation, built, enabled=settings["inputs"],
                                  allow_mutating=bool(settings["writes"] and allow_mutating),
                                  budget=max(0, request_budget - 1), credential_names=credential_names)


def _supplemental_plan(operation, built, settings, budget, credential_names=(), writable_body_pointers=None):
    baseline = Exchange(label="planned baseline", method=built["method"], url=built["url"],
                        request_headers=built["headers"], request_body=_body_text(built))
    fields = []
    if settings["inputs"] and baseline.method in ("GET", "HEAD"):
        fields += inputs.points(baseline, documented_query=_declared(operation, "query"),
                                documented_header=_declared(operation, "header"),
                                documented_cookie=_declared(operation, "cookie"),
                                documented_path=_declared(operation, "path"),
                                path_template=operation["path"], max_fields=settings.get("max_fields", 3),
                                credential_names=credential_names)
    if settings["writes"] and baseline.method in ("POST", "PUT", "PATCH"):
        fields += inputs._body_points(baseline, settings.get("body_fields", 3), credential_names=credential_names,
                                      allowed_body_pointers=writable_body_pointers)
    fields = [point for point in fields if str(point).lower() not in credential_names]
    return inputs.battery_plan(baseline, endpoint=f"{operation['method']} {operation['path']}",
                               fields=fields, budget=budget, time_based=settings.get("time_based", False))


def _credential_names(parsed, configured=()):
    return credential_names_for(parsed, configured)


def _writable_pointers(fields):
    return {item["field_pointer"] for item in fields
            if item["location"] == "body" and item["category"] == "writable-input"}


def _family_permitted(name, settings):
    if name in ("mass-assignment", "write-authorization", "body-injection", "xml"):
        return settings["writes"]
    if name == "input-handling":
        return settings["inputs"]
    if name == "posture":
        return settings["posture"]
    return settings["authz"]


def audit_plan(spec: dict, operation_id: str, *, base_url=None, identities=None,
               profile=DEFAULT_PROFILE, allow_mutating=False, example=None,
               request_budget=None, response_comparison=None, credential_names=(), **_unused) -> dict:
    """Build a deterministic reviewable plan without target or OAuth requests."""
    comparison_policy = normalize_policy(response_comparison)
    parsed = normalize_spec(spec)
    names = _credential_names(parsed, credential_names)
    operation = next((op for op in parsed["operations"] if op["id"] == operation_id), None)
    if operation is None:
        raise ValueError(f"Unknown operation: {operation_id}")
    settings = _profile(profile)
    identity = (identities or {}).get("primary") or {}
    headers = identity.get("headers", {}) if "oauth" in identity or "headers" in identity else identity
    headers = {str(key): str(value) for key, value in headers.items()
               if isinstance(value, (str, int, float))}
    built = build_request(parsed, operation_id, base_url=base_url, headers=headers)
    if example:
        built, _note = _apply_example(built, example, headers)
    _check_example_scope(built, base_url or parsed.get("base_url") or built["url"])
    limit = _limit(settings, request_budget)
    plan = _schema_plan(parsed, operation, built, settings, allow_mutating, limit, names).to_dict()
    baseline_count = int(built["method"] in ("GET", "HEAD", "OPTIONS", "TRACE")
                         or (settings["writes"] and allow_mutating))
    plan["baseline_requests"] = baseline_count
    plan["request_budget"] = limit
    plan["supplemental_probes"] = _supplemental_plan(
        operation, built, settings, limit, names, _writable_pointers(plan["fields"]))
    plan["supplemental_checks"] = [
        {"check": name, "title": meta["title"], "operation": operation_id,
         "prerequisite": (("Successful positive control" if meta.get("needs_baseline")
                           else "Applicable method and probe-specific controls")
                          + ("; distinct second identity" if meta.get("needs_second_identity") else "")),
         "missing_prerequisites": ((["second-identity"] if meta.get("needs_second_identity")
                                    and not (identities or {}).get("secondary") else [])
                                   + ([] if _family_permitted(name, settings) else ["profile-disallows-check"])),
         "planned_requests": None if _family_permitted(name, settings) else 0,
         "conditional": bool(_family_permitted(name, settings)),
         "request_ceiling": max(0, limit - baseline_count - plan.get("planned_requests", 0))}
        for name, meta in coverage.CHECKS.items()
        if name not in ("schema-inputs", "inventory", "contract-review", "passive-review",
                        "response-contract", "transport", "jwt-offline")]
    return redact_evidence({"endpoint": f"{operation['method']} {operation['path']}",
            "operation_id": operation_id, "profile": profile, "request_budget": limit,
            "test_plan": plan, "target_requests_sent": 0, "response_comparison": comparison_policy,
            "request_breakdown": {"inventory": 0, "baseline": baseline_count,
                                  "schema_inputs": plan.get("planned_requests", 0),
                                  "other_endpoint_tests": 0,
                                  "total": baseline_count + plan.get("planned_requests", 0)},
            "credential_names": sorted(names)}, sources=[built], credential_names=names)


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
    # Tallied here as well as in the browser, so a caller using the API gets
    # the same breakdown. A count by severity alone invites the reading this
    # whole structure exists to prevent: five findings is not five weaknesses.
    category: dict = {}
    verification: dict = {}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        confidence[item.confidence] = confidence.get(item.confidence, 0) + 1
        if item.owasp:
            owasp[item.owasp] = owasp.get(item.owasp, 0) + 1
        if item.category:
            category[item.category] = category.get(item.category, 0) + 1
        if item.verification:
            verification[item.verification] = verification.get(item.verification, 0) + 1
    return {"total": len(findings), "severity": counts, "confidence": confidence,
            "owasp": owasp, "category": category, "verification": verification}


def audit_operation(spec: dict, operation_id: str, *, base_url: str | None = None,
                    identities: dict | None = None, profile: str = DEFAULT_PROFILE,
                    allow_mutating: bool = False, verify_tls: bool = True,
                    timeout: float = 15.0, concurrency: int | None = None,
                    user_agent: str | None = None, connection=None, client=None,
                    expectation: dict | None = None, example: dict | None = None,
                    request_budget: int | None = None,
                    requests_per_second: float | None = None,
                    response_comparison: dict | None = None, credential_names=(),
                    control=None) -> dict:
    """Run the audit battery against one documented operation.

    ``control`` is a :class:`namazu.audit.control.RunControl` when this
    operation is one case in a server-owned run. It supplies the ONE request
    budget, pacer, stop signal and write-authorisation shared across the whole
    run, plus the receipt sink that persists each request durably. Left as
    ``None`` (the standalone ``/api/audit`` path), the operation builds its own
    per-operation budget and pacer exactly as before.

    ``example`` is a saved request for this operation, which replaces the one
    generated from the schema. A generated request carries the literal "string"
    wherever the contract documents no example, which usually names nothing
    that exists, and an audit whose baseline never reached a resource cannot
    conclude anything about access to it.

    ``expectation`` is what the operator says a successful response looks like
    for this operation, including the case where the expected answer is a
    refusal. See :mod:`namazu.audit.baseline`.
    """
    comparison_policy = normalize_policy(response_comparison)
    parsed = normalize_spec(spec)
    names = _credential_names(parsed, credential_names)
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

    ledger = coverage.Ledger()
    findings: list = list(specscan.review_operation(parsed, operation))
    ledger.complete("contract-review", findings=len(findings))

    built = build_request(parsed, operation_id, base_url=base_url, headers=identity_a)
    expected = baseline_module.Expectation.from_dict(expectation or {})
    example_note = ""
    if example:
        built, example_note = _apply_example(built, example, identity_a)
    target = base_url or parsed.get("base_url") or built["url"]
    _check_example_scope(built, target)
    per_operation_limit = _limit(settings, request_budget)
    # In a run, this operation's budget is a child of the one run-wide budget,
    # so the operation keeps its own ceiling while the run total holds across
    # every operation, the inventory sweep and every worker.
    budget = control.per_operation_budget(per_operation_limit) if control is not None else Budget(per_operation_limit)
    input_plan = _schema_plan(parsed, operation, built, settings, allow_mutating, budget.limit, names)
    owns_client = client is None
    http = client or build_client(connection=link)
    workers = _workers(settings, concurrency)
    executor = Executor(http, budget, timeout=timeout, allow_mutating=bool(settings["writes"] and allow_mutating),
                        concurrency=workers, signature=Signature(quiet=link.quiet),
                        scope_url=target, requests_per_second=requests_per_second,
                        pace=control.pace if control is not None else None,
                        cancel=control.cancel if control is not None else None,
                        write_withdrawn=control.write_withdrawn if control is not None else None,
                        receipts=control.receipts if control is not None else None)
    executor.test_plan = input_plan.to_dict()
    executor.comparison_policy = comparison_policy
    executor.contract_snapshot = contract.snapshot(parsed, operation, request_url=built["url"])
    executor.test_plan["baseline_requests"] = 1
    executor.test_plan["request_budget"] = budget.limit
    executor.redacted_names = names
    executor.credential_sources = [built, {"headers": identity_a}, {"headers": identity_b}]
    executor.writable_body_pointers = _writable_pointers(input_plan.fields)
    executor.test_plan["supplemental_probes"] = _supplemental_plan(
        operation, built, settings, budget.limit, executor.redacted_names, executor.writable_body_pointers)
    executor.campaign_plan = input_plan
    executor.campaign_result = {}
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
    if example_note:
        notes.append(example_note)
    if expected.asserted():
        notes.append(f"Baseline assertions for this operation: {expected.describe()}.")
    elif (invented := baseline_module.placeholder_inputs(operation)):
        # Said before the run rather than after it, because this is the single
        # most common reason an audit never reaches the resource it is pointed
        # at, and it is fixable in the contract or with a saved example.
        notes.append(
            f"The contract documents no example for {', '.join(invented)}, so the baseline "
            "request carries generated placeholder values for them. If the operation refuses "
            "the request because of that, save a known-good example request for it instead.")

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
        return _skipped(endpoint, operation, findings, budget, profile, ledger=ledger,
                        source_url=parsed.get("source_url") or "", executor=executor, reason=(
            f"{operation['method']} requests change server state, so this operation was reviewed from "
            "its contract only. Choose the write profile and enable Allow writes to probe it."))
    except BudgetExhausted as exc:
        if owns_client:
            http.close()
        return _skipped(endpoint, operation, findings, budget, profile, ledger=ledger,
                        source_url=parsed.get("source_url") or "", executor=executor,
                        reason=str(exc))
    except Cancelled:
        # Stopped before the baseline left: no request was dispatched for this
        # operation, so it is reviewed from its contract only, not reported as
        # tested. The run loop will mark the remaining operations not-started.
        if owns_client:
            http.close()
        return _skipped(endpoint, operation, findings, budget, profile, ledger=ledger,
                        source_url=parsed.get("source_url") or "", executor=executor, reason=(
            "The run was stopped before this operation's baseline request was sent, so it "
            "was reviewed from its contract only. No target request was dispatched for it."))

    verdict = baseline_module.classify(
        baseline, operation=operation, expectation=expected,
        identity="identity A" if identity_a else "an anonymous caller")
    baseline.positive_control = verdict.positive_control
    token = jwtlab.bearer_token(identity_a)
    if token:
        token_findings = _supplied_token_findings(identity_a, endpoint)
        findings += token_findings
        ledger.complete("jwt-offline", findings=len(token_findings))
    else:
        ledger.not_applicable("jwt-offline", "No supplied JWT to inspect offline.")
    if not baseline.ok:
        ledger.block_dependents(verdict, has_second_identity=bool(identity_b))
        executor.campaign_result = campaign.execute_campaign(executor, input_plan, baseline)
        for name in ("response-contract", "passive-review", "methods", "posture", "transport"):
            ledger.block(name, verdict.reason, verdict.remediation)
        result = _result(endpoint, operation, _dedupe(findings), budget, profile,
                         notes=[verdict.reason], baseline=baseline, verdict=verdict,
                         ledger=ledger,
                         source_url=parsed.get("source_url") or "", executor=executor)
        if owns_client:
            http.close()
        return result

    # The gate. Probes that conclude by comparing against a working baseline
    # are blocked here, with the reason recorded, rather than running against
    # a refusal and reporting nothing. Probes that read the one response
    # already in hand, or that send their own independent requests, still run:
    # a refusal is still a response, and its headers, media type and body are
    # worth reviewing whatever it says.
    ledger.block_dependents(verdict, has_second_identity=bool(identity_b))
    if not verdict.usable:
        notes.append(verdict.reason)
        if verdict.remediation:
            notes.append(f"To get coverage of this operation: {verdict.remediation}")

    def family(name: str, run, *, run_when_blocked=False):
        """Run one probe family, or record why it did not run."""
        if ledger.state(name) == "blocked" and not run_when_blocked:
            return []
        ledger.attempt(name)
        before = len(executor.exchanges)
        declined = budget.declined + budget.refused
        try:
            produced = list(run() or [])
        except BudgetExhausted:
            ledger.budget_exhausted(name)
            return []
        except MutationRefused as exc:
            ledger.block(name, str(exc))
            return []
        except Exception as exc:
            ledger.execution_error(name)
            notes.append(f"{name}: {type(exc).__name__}; no conclusion was reached.")
            return []
        sent = executor.exchanges[before:]
        if name in ("response-contract", "passive-review") or sent:
            ledger.complete(name, findings=len(produced), requests=len(sent))
            if any(item.error for item in sent):
                ledger.execution_error(name)
        else:
            ledger.not_applicable(name, "No applicable probe sent a request; see individual prerequisites.")
        if budget.declined + budget.refused > declined:
            ledger.budget_exhausted(name)
        return produced

    tls_findings = posture.inspect_tls(built["url"], timeout=min(timeout, 10.0))
    findings += tls_findings
    ledger.complete("transport", findings=len(tls_findings))
    notes += _route_notes(link, url=built["url"], tls_inspected=bool(tls_findings))
    # Response conformance and implementation disclosure are reviewed once,
    # after every probe has settled, so non-baseline evidence is included.
    findings += inventory.zombie_check(baseline, endpoint)
    findings += family("passive-review",
                       lambda: passive.review(baseline, endpoint=endpoint, operation=operation,
                                              document=parsed.get("document") or {}))

    try:
        executor.campaign_result = campaign.execute_campaign(executor, input_plan, baseline)
        if settings["authz"]:
            before = len(notes)
            authz_findings = family("authorization", lambda: authz.probe(
                executor, baseline=baseline, endpoint=endpoint, operation=operation,
                identity_a=identity_a, identity_b=identity_b, base_headers=built["headers"],
                notes=notes,
            ), run_when_blocked=True)
            findings += authz_findings
            # The cross-identity read is tracked apart from the rest of the
            # family, so "no second identity" does not read as "the whole of
            # authorization went untested" and, as here, a probe that did run
            # does not end the run recorded as skipped.
            if ledger.state("cross-identity") != "blocked":
                refusal = next((note for note in notes[before:]
                                if "cross-identity read did not run" in note), "")
                if refusal:
                    ledger.inconclusive(
                        "cross-identity", refusal,
                        "Supply a second identity that holds a different object on this "
                        "operation, and give it a resource marker so the read can be checked "
                        "by content rather than by status code.")
            findings += family("credential-handling", lambda: contract.invalid_credentials(
                executor, baseline=baseline, endpoint=endpoint, operation=operation,
                identity=identity_a, headers=built["headers"]))
            if baseline.status in (401, 403):
                findings += family("access-bypass", lambda: bypass.probe(
                    executor, baseline=baseline, endpoint=endpoint, headers=built["headers"]))
            else:
                # It ran nothing, and saying "completed with no findings" would
                # imply the route was tested for bypasses. There was nothing to
                # bypass: the baseline was not refused.
                ledger.not_applicable(
                    "access-bypass",
                    f"The baseline returned HTTP {baseline.status} rather than being refused, so "
                    "there was no access decision for a bypass variant to get around.")
            findings += family("cache", lambda: bypass.cache_deception(
                executor, baseline=baseline, endpoint=endpoint, headers=built["headers"]))
            documented = {op["method"] for op in parsed["operations"] if op["path"] == operation["path"]}
            findings += family("methods", lambda: inventory.allowed_methods(
                executor, url=built["url"], endpoint=endpoint,
                headers=built["headers"], documented=documented,
            ))
        else:
            for name in ("authorization", "credential-handling", "access-bypass", "cache",
                         "methods"):
                ledger.skip(name, f"The {profile} profile does not run this.")
        if settings.get("posture"):
            findings += family("posture", lambda: posture.review(
                executor, baseline=baseline, endpoint=endpoint, headers=built["headers"],
                operation=operation, base_url=built["url"],
                do_rate_limit=settings.get("rate_limit", False),
            ))
        else:
            ledger.skip("posture", f"The {profile} profile does not run this.")
        if settings["inputs"]:
            documented_query = [
                {"name": p.get("name"),
                 "example": p.get("example", (p.get("schema") or {}).get("example")),
                 "default": (p.get("schema") or {}).get("default"),
                 "type": (p.get("schema") or {}).get("type")}
                for p in (operation.get("parameters") or [])
                if p.get("in") == "query" and p.get("name")
            ]
            findings += family("input-handling", lambda: inputs.probe(
                executor, baseline=baseline, endpoint=endpoint,
                base_headers=built["headers"],
                documented_query=documented_query,
                documented_header=_declared(operation, "header"),
                documented_cookie=_declared(operation, "cookie"),
                documented_path=_declared(operation, "path"),
                path_template=operation["path"],
                max_fields=settings.get("max_fields", 3),
                time_based=settings.get("time_based", False)))
        else:
            ledger.skip("input-handling", f"The {profile} profile does not run this.")
        if settings["writes"]:
            findings += _write_probes(executor, parsed, operation, built, endpoint,
                                      built["headers"], identity_b, notes, baseline,
                                      settings.get("body_fields", 3), ledger)
        else:
            reason = (f"The {profile} profile sends no state-changing requests."
                      if operation["method"] in ("GET", "HEAD", "OPTIONS", "TRACE")
                      else "Write probes need the write profile and Allow writes.")
            for name in ("mass-assignment", "write-authorization", "body-injection", "xml"):
                ledger.skip(name, reason)
    except BudgetExhausted:
        notes.append(f"Request budget of {budget.limit} reached; some probes did not run.")
        for name in coverage.CHECKS:
            if not ledger.state(name):
                ledger.budget_exhausted(name)
    except Cancelled:
        # Stopped part-way through this operation. Everything already captured
        # is kept and reported; the probes that had not run are recorded as
        # blocked by the stop, not as clean.
        notes.append("The run was stopped during this operation. No further probes were "
                     "dispatched for it; the evidence already captured is retained.")
        for name in coverage.CHECKS:
            if not ledger.state(name):
                ledger.block(name, "The run was stopped before this check ran.", code="run-stopped")
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
                   baseline=baseline, verdict=verdict, ledger=ledger,
                   source_url=parsed.get("source_url") or "", executor=executor)


def _apply_example(built: dict, example: dict, identity_headers: dict) -> tuple[dict, str]:
    """Replace a generated request with a saved one the operator knows works.

    Only the parts a saved example is allowed to set are taken: the URL, the
    body, the content type and non-credential headers. The identity's headers
    are reapplied afterwards, so a saved example cannot smuggle in a stale
    credential and cannot override the identity the run is auditing as.
    """
    from .identity import strip_credentials

    out = dict(built)
    changed = []
    if isinstance(example.get("url"), str) and example["url"].strip():
        out["url"] = example["url"].strip()
        changed.append("URL")
    if "body" in example:
        body = example["body"]
        out["body"] = body
        out["has_body"] = body is not None
        changed.append("body")
    if isinstance(example.get("content_type"), str) and example["content_type"]:
        out["content_type"] = example["content_type"]
    headers = dict(built.get("headers") or {})
    supplied = example.get("headers")
    if isinstance(supplied, dict) and supplied:
        safe = strip_credentials({str(k): str(v) for k, v in supplied.items()})
        dropped = len(supplied) - len(safe)
        headers.update(safe)
        if dropped:
            changed.append(f"headers (ignoring {dropped} credential header(s))")
        else:
            changed.append("headers")
    # The audited identity always wins, whatever the example carried.
    for name, value in (identity_headers or {}).items():
        for existing in list(headers):
            if existing.lower() == str(name).lower():
                del headers[existing]
        headers[str(name)] = str(value)
    if out.get("content_type") and out.get("has_body"):
        headers["Content-Type"] = out["content_type"]
    out["headers"] = headers
    if not changed:
        return out, ""
    label = example.get("label") or "a saved example"
    return out, (f"The baseline used {label} rather than a request generated from the schema, "
                 f"replacing its {', '.join(changed)}. The audited identity's credentials were "
                 "applied over it.")


def _body_text(built: dict):
    return campaign._body_text(built)


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
            detail=("The HMAC signature validates under a recovered weak secret; its value is redacted."
                    if weakness["id"] == "weak-secret" else weakness["detail"])
                    + " Determined offline from the token you supplied; no request was sent.",
            impact=("The signing key is recoverable, so a token can be minted for any user."
                    if weakness["id"] == "weak-secret"
                    else "Reduces the guarantees the token is meant to provide."),
            remediation=("Rotate to a high-entropy secret of at least 256 bits or asymmetric signing."
                         if weakness["id"] == "weak-secret"
                         else "Set a short exp, pin the key source, and keep sensitive data out of the payload."),
            evidence={"algorithm": report["algorithm"], "key_id": report.get("key_id"),
                      "cracked_secret": "<credential>" if report.get("cracked_secret") else None,
                      "privilege_claims": report.get("privilege_claims")},
        ))
    return out


def _write_probes(executor, parsed, operation, built, endpoint, headers, identity_b, notes,
                  baseline=None, body_fields: int = 3, ledger=None) -> list:
    """The probes that change state, cheapest and most conclusive first.

    Mass assignment and write authorization go first because each is a couple
    of requests and either can be confirmed outright. The body injection
    battery runs last: it is the one that costs tens of requests, so if the
    budget runs out it should be the probe that gets cut.
    """
    out: list = []
    method = operation["method"]
    def blocked(name: str) -> bool:
        return ledger is not None and ledger.state(name) == "blocked"

    def record(name: str, found: int, before: int) -> None:
        if ledger is not None:
            sent = executor.exchanges[before:]
            if sent:
                ledger.complete(name, findings=found, requests=len(sent))
                if any(item.error for item in sent):
                    ledger.execution_error(name)
            elif executor.budget.remaining <= 0:
                ledger.budget_exhausted(name)
            else:
                ledger.not_applicable(name, "No applicable probe sent a request; see individual prerequisites.")

    if method not in ("POST", "PUT", "PATCH"):
        if ledger is not None:
            for name in ("mass-assignment", "write-authorization", "body-injection", "xml"):
                ledger.not_applicable(name, f"{method} does not carry a request body to probe.")
        return out

    # An operation that takes XML gets the external entity probes. Three
    # requests, run before the injection battery because that one costs tens
    # and is the right thing to lose if the budget runs out.
    xml_media = xmllab.request_media(operation)
    if not xml_media and ledger is not None:
        ledger.not_applicable("xml", "The operation does not accept an XML request body.")
    elif xml_media and baseline is not None and not blocked("xml"):
        before = len(executor.exchanges)
        probes = xmllab.probe(executor, baseline=baseline, operation=operation,
                              endpoint=endpoint, base_headers=headers, media=xml_media)
        out += probes
        record("xml", len(probes), before)
        if not probes:
            notes.append(f"The XML body for this operation ({xml_media}) was probed for external "
                         "entity processing and nothing was found.")
    privileged = [
        item.parameter for item in specscan.review_operation(parsed, operation)
        if item.id == "spec.mass-assignment-surface" and item.parameter
    ]
    properties = [name.strip() for entry in privileged for name in entry.split(",") if name.strip()]
    if not properties:
        notes.append("No privileged properties in the request schema, so no mass-assignment probe ran.")
        if ledger is not None:
            ledger.not_applicable("mass-assignment",
                                  "The request schema declares no property that names a privilege "
                                  "or an owner, so there was nothing to try to set.")
    elif not blocked("mass-assignment"):
        before = len(executor.exchanges)
        read_back = built["url"] if method in ("PUT", "PATCH") else None
        probes = inputs.mass_assignment(executor, built=built, endpoint=endpoint,
                                        base_headers=headers, properties=properties,
                                        read_back_url=read_back)
        out += probes
        record("mass-assignment", len(probes), before)
    if not identity_b:
        if ledger is not None and ledger.state("write-authorization") != "blocked":
            ledger.block("write-authorization",
                         "No second identity is configured, so there was nothing to attempt the "
                         "write as.",
                         "Add a second identity on the Auth tab that owns a different object on "
                         "this operation.")
    elif not blocked("write-authorization"):
        before = len(executor.exchanges)
        probes = inputs.write_authorization(executor, built=built, endpoint=endpoint,
                                            base_headers=headers, identity_b=identity_b,
                                            notes=notes)
        out += probes
        record("write-authorization", len(probes), before)
    if baseline is not None and not blocked("body-injection"):
        before = len(executor.exchanges)
        probes = _body_probes(executor, baseline, endpoint, headers, method, body_fields, notes)
        out += probes
        record("body-injection", len(probes), before)
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
             source_url: str = "", executor=None, ledger=None) -> dict:
    """No baseline was sent at all, so every active check is blocked, not clean."""
    if ledger is not None:
        for name in coverage.CHECKS:
            if not ledger.state(name):
                ledger.block(name, reason)
    if executor is not None and hasattr(executor, "campaign_plan"):
        executor.test_plan["baseline_requests"] = 0
        executor.campaign_result = campaign.execute_campaign(
            executor, executor.campaign_plan,
            Exchange(label="baseline not sent", method=operation["method"], url="", error=reason))
    return _result(endpoint, operation, _dedupe(findings), budget, profile, notes=[reason],
                   source_url=source_url, executor=executor, ledger=ledger)


MAX_LOG_ENTRIES = 220
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
            source_url: str = "", executor=None, verdict=None, ledger=None) -> dict:
    response_review = None
    if executor is not None:
        response_review, observed = contract.review_captured(
            getattr(executor, "contract_snapshot", None), executor.exchanges, endpoint)
        findings = _dedupe(list(findings) + observed)
        if ledger is not None and response_review["responses_received"]:
            if response_review["contract"]["reviewed_responses"]:
                ledger.complete("response-contract", findings=len(response_review["contract"]["findings"]))
                partial = [row for row in response_review["contract"]["exchanges"]
                           if row["state"] in ("incomplete", "not-reviewed", "edge-block")]
                if partial:
                    ledger.inconclusive("response-contract", "All captured responses were considered; some lack a complete matching application contract or are explicit edge block pages. See the response review for individual reasons.")
            else:
                ledger.inconclusive("response-contract", "No captured response could be reviewed against a matching application contract. Edge blocks do not establish downstream application behaviour.")
    _attach_commands(findings, source_url)
    log = _log(executor, endpoint)
    if executor is not None and baseline is not None:
        for exchange, row in zip(executor.exchanges, log, strict=False):
            if exchange is not baseline:
                row["comparison_before_import_redaction"] = comparison_facts(
                    exchange, baseline, policy=getattr(executor, "comparison_policy", None),
                    protected_keys={part.replace("~1", "/").replace("~0", "~")
                                    for pointer in getattr(executor, "writable_body_pointers", set())
                                    for part in pointer.split("/") if part})
    if executor is not None and len(executor.exchanges) > MAX_LOG_ENTRIES:
        (notes := list(notes or [])).append(
            f"The request log keeps the first {MAX_LOG_ENTRIES} of {len(executor.exchanges)} requests.")
    if ledger is not None:
        _probe_coverage(ledger, executor)
        # Anything never reached gets a state too. A check with no state at all
        # is indistinguishable from one that ran clean, which is the whole
        # failure this ledger exists to prevent.
        for name in coverage.CHECKS:
            if not ledger.state(name):
                if name == "inventory":
                    ledger.not_applicable(name, "Inventory is a separate host sweep, not an endpoint check.")
                elif executor is not None and executor.pace.stopped:
                    ledger.block(name, "Target rate limit stopped further requests.", code="rate-limit-observed")
                elif budget.remaining <= 0 and _family_permitted(name, _profile(profile)):
                    ledger.budget_exhausted(name)
                else:
                    ledger.skip(name, "This check did not run in this profile.")
        # Summarise only after individual receipts and unreached families have
        # settled the ledger. An earlier summary could say seven families were
        # blocked while the final receipts correctly say nine.
        gap = coverage.describe(ledger, verdict)
        if gap and gap not in (notes or []):
            notes = list(notes or []) + [gap]
    campaign_result = getattr(executor, "campaign_result", {})
    individual = campaign_result.get("probes", []) + getattr(executor, "probe_results", [])
    # Probe copies reference the same redacted wire data as their log entry.
    # Keep name-only pre-mask facts with those copies too, for field drill-down.
    if executor is not None and baseline is not None:
        for probe in individual:
            for entry in ([probe["exchange"]] if probe.get("exchange") else probe.get("exchanges", [])):
                match = next((row for row in log if row.get("comparison_before_import_redaction") and all(row.get(key) == entry.get(key) for key in
                             ("label", "method", "url", "request_body", "status", "response_body", "request_headers", "response_headers"))), None)
                if match and match.get("comparison_before_import_redaction"):
                    entry["comparison_before_import_redaction"] = match["comparison_before_import_redaction"]
    represented = {item.get("family") for item in individual}
    if ledger is not None:
        for entry in ledger.entries():
            if entry.check not in represented and entry.check != "schema-inputs":
                individual.append({"check": entry.check, "family": entry.check,
                                   "operation": endpoint, "field_pointer": "",
                                   "status": "blocked-prerequisite" if entry.state == "blocked" else entry.state,
                                   "reason_code": ("all-captured-response-review" if entry.check == "response-contract"
                                                   and response_review and response_review["responses_received"]
                                                   else entry.reason_codes[0] if entry.reason_codes else entry.state),
                                   "reason": entry.reason, "requests": entry.requests,
                                   "request_sent": bool(entry.requests),
                                   "missing_prerequisites": entry.missing_prerequisites})
    schema_sent = sum(item.get("request_sent", False) for item in campaign_result.get("probes", []))
    baseline_sent = int(baseline is not None)
    result = {
        "endpoint": endpoint,
        "operation_id": operation["id"],
        "method": operation["method"],
        "path": operation["path"],
        "profile": profile,
        "requests_sent": budget.spent,
        "request_budget": budget.limit,
        "response_comparison": normalize_policy(getattr(executor, "comparison_policy", None)),
        "contract_snapshot": getattr(executor, "contract_snapshot", None),
        "response_review": response_review,
        "concurrency": executor.concurrency if executor is not None else 1,
        "baseline_status": baseline.status if baseline is not None else None,
        "baseline_outcome": verdict.outcome if verdict is not None else None,
        "baseline_verdict": verdict.to_dict() if verdict is not None else None,
        "coverage": ledger.to_dict() if ledger is not None else None,
        "test_plan": getattr(executor, "test_plan", None),
        "field_coverage": campaign_result.get("field_coverage", []),
        "probes": individual,
        "request_breakdown": {"inventory": 0, "baseline": baseline_sent,
                              "schema_inputs": schema_sent,
                              "other_endpoint_tests": max(0, budget.spent - baseline_sent - schema_sent),
                              "total": budget.spent},
        "notes": [note for note in (notes or []) if note],
        "baseline": baseline.to_dict() if baseline is not None else None,
        "log": log,
        "findings": [item.to_dict() for item in findings],
        "summary": summarize(findings),
    }
    # Findings may quote a target response outside their exchanges. Redact
    # known baseline credentials there as well, including custom scheme names.
    if baseline is not None:
        # Redact string values, not serialized JSON structure. A credential
        # such as "true" must not corrupt Boolean coverage/assertion values.
        def redact_values(value):
            if isinstance(value, dict):
                return {key: redact_values(item) for key, item in value.items()}
            if isinstance(value, list):
                return [redact_values(item) for item in value]
            return baseline.safe_text(value, redact_properties=False) if isinstance(value, str) else value
        result = redact_values(result)
    # The checksum identifies the evidence actually exported after redaction.
    if executor is not None:
        result["credential_names"] = sorted(executor.redacted_names)
        sources = [*getattr(executor, "credential_sources", []),
                   *[{"response_headers": exchange.headers} for exchange in executor.exchanges]]
        result = redact_evidence(result, sources=sources, credential_names=executor.redacted_names)
    result["contract_snapshot"] = contract.attach_snapshot_integrity(result["contract_snapshot"])
    return result


def _probe_coverage(ledger, executor):
    """Aggregate individual receipts; no function return is evidence of completion."""
    if executor is None:
        return
    campaign_result = getattr(executor, "campaign_result", {})
    reports = list(executor.probe_results)
    reports += [{**probe, "family": "schema-inputs", "requests": int(probe.get("request_sent", False))}
                for probe in campaign_result.get("probes", [])]
    families = {item.get("family") for item in reports if item.get("family") in coverage.CHECKS}
    for name in families:
        rows = [item for item in reports if item.get("family") == name]
        sent = sum(row.get("requests", 0) for row in rows)
        meaningful_headers = set()
        states = {row.get("status") for row in rows}
        if sent:
            ledger.complete(name)
        elif states <= {"not-sent", "not-applicable"}:
            ledger.not_applicable(name, "No distinct applicable request was needed.")
        for row in rows:
            status = row.get("status")
            comparisons = list(row.get("comparisons", []))
            if isinstance(row.get("comparison"), dict):
                comparisons.append(row["comparison"])
            meaningful_headers.update(change["name"] for comparison in comparisons
                                      for change in comparison.get("meaningful_header_differences", [])
                                      if change.get("name"))
            if status == "budget-exhausted":
                ledger.budget_exhausted(name)
            elif status == "execution-error":
                ledger.execution_error(name)
            elif status == "blocked-prerequisite":
                missing = row.get("missing_prerequisites") or [row.get("reason") or "Probe prerequisite not met."]
                for reason in missing:
                    if sent and ledger.state(name) != "blocked":
                        ledger.inconclusive(name, "Some probes ran, but others lack prerequisites: " + reason)
                    else:
                        ledger.block(name, reason, code=row.get("reason_code") or "blocked-prerequisite")
            elif status in ("same-denial", "same-denial-as-baseline"):
                ledger.inconclusive(name, "Same denial as baseline; downstream handling unknown.")
            elif status == "edge-block-observed":
                ledger.inconclusive(name, "An explicit edge block page was observed; downstream handling is unknown.")
            elif row.get("reason_code") == "field-validation-observed":
                ledger.inconclusive(name, "A field-specific validation rejection was observed; this alone does not demonstrate security impact or the processing layer.")
            elif status in ("field-response-observed", "field-specific-response-observed") or "lead" in row.get("reason_code", ""):
                ledger.inconclusive(name, "A response difference is a lead; validation and security impact are not established.")
        entry = next((entry for entry in ledger.entries() if entry.check == name), None)
        if entry is not None:
            entry.requests = sent
            entry.reason_codes = sorted(set(entry.reason_codes) | {row.get("reason_code", "") for row in rows} - {""})
            if meaningful_headers:
                entry.reason_codes = sorted(set(entry.reason_codes) | {"meaningful-response-header-difference"})
                header_note = ("Meaningful response-header changes were also observed: "
                               + ", ".join(sorted(meaningful_headers))
                               + ". Review the exact exchanges; these changes alone do not establish security impact.")
                if header_note not in entry.reason:
                    entry.reason = (entry.reason + " " + header_note).strip()
            entry.missing_prerequisites = sorted(set(entry.missing_prerequisites)
                                                | {reason for row in rows for reason in row.get("missing_prerequisites", [])})


def audit_inventory(spec: dict, *, base_url: str | None = None, identities: dict | None = None,
                    verify_tls: bool = True, timeout: float = 15.0, budget: int = 60,
                    connection=None,
                    concurrency: int | None = None, user_agent: str | None = None,
                    requests_per_second: float | None = None, credential_names=(), client=None,
                    control=None) -> dict:
    """Sweep the host around the documented surface. Read-only.

    ``control`` binds the sweep to a server-owned run: its request budget is a
    child of the run-wide budget, and it shares the run's pacer, stop signal and
    receipt sink, so the sweep draws on the same total as the operations and a
    429 during the sweep stops the rest of the run too.
    """
    parsed = normalize_spec(spec)
    names = _credential_names(parsed, credential_names)
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

    tracker = control.per_operation_budget(budget) if control is not None else Budget(budget)
    owns_client = client is None
    http = client or build_client(connection=link)
    signature = Signature(quiet=link.quiet)
    executor = Executor(http, tracker, timeout=timeout, allow_mutating=False,
                        concurrency=_workers(PROFILES["readonly"], concurrency),
                        signature=signature, scope_url=target, requests_per_second=requests_per_second,
                        pace=control.pace if control is not None else None,
                        cancel=control.cancel if control is not None else None,
                        write_withdrawn=control.write_withdrawn if control is not None else None,
                        receipts=control.receipts if control is not None else None)
    executor.redacted_names = names
    rate_note = ""
    stopped = False
    try:
        probe_findings, summary = inventory.run(
            executor, spec=parsed, base_url=target, headers=identity_a,
            documented_paths=documented_paths,
        )
        findings += probe_findings
    except RateLimited:
        probe_findings, summary = [], {"rate_limited": True}
        rate_note = "The target returned HTTP 429; remaining inventory probes were stopped."
    except Cancelled:
        probe_findings, summary = [], {"stopped": True}
        rate_note = "The run was stopped during the inventory sweep; remaining sweep probes were not sent."
        stopped = True
    finally:
        if owns_client:
            http.close()

    deduped = _dedupe(_attach_commands(findings, parsed.get("source_url") or ""))
    # The sweep gets a ledger entry of its own, so the report says whether it
    # ran rather than leaving its absence to be read as nothing found.
    ledger = coverage.Ledger()
    ledger.complete("contract-review", findings=len(list(specscan.review_document(parsed))))
    if stopped:
        ledger.block("inventory", rate_note, code="run-stopped")
    elif rate_note:
        ledger.block("inventory", rate_note, code="rate-limit-observed")
    elif summary.get("budget_exhausted"):
        ledger.inconclusive(
            "inventory",
            f"The sweep's request budget of {tracker.limit} was spent before it finished, so "
            "the surface around the documented routes was only partly probed.",
            "Raise the sweep budget to cover the whole surface.")
    else:
        ledger.complete("inventory", findings=len(probe_findings), requests=tracker.spent)
    result = {
        "scope": "inventory",
        "coverage": ledger.to_dict(),
        "base_url": target,
        "profile": "readonly",
        "requests_sent": tracker.spent,
        "request_breakdown": {"inventory": tracker.spent, "baseline": 0, "schema_inputs": 0,
                              "other_endpoint_tests": 0, "total": tracker.spent},
        "request_budget": tracker.limit,
        "concurrency": executor.concurrency,
        "discovery": summary,
        "log": _log(executor, "surface sweep"),
        "notes": ([credential_note] if credential_note else [])
                 + ([rate_note] if rate_note else [])
                 + ([signature.describe()] if signature.describe() else [])
                 + _route_notes(link)
                 + (["Request budget reached; the sweep stopped early."] if summary.get("budget_exhausted") else []),
        "findings": [item.to_dict() for item in deduped],
        "summary": summarize(deduped),
    }
    result["credential_names"] = sorted(executor.redacted_names)
    sources = [{"headers": identity_a}, *[{"response_headers": exchange.headers} for exchange in executor.exchanges]]
    return redact_evidence(result, sources=sources, credential_names=executor.redacted_names)
