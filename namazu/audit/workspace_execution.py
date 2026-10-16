"""Contract-scoped sequencing over the existing audit engine and run control.

This module does no importing or identity acquisition. A reviewed workspace
hands it immutable contract snapshots and already assigned bearer credentials.
Only those in-memory credentials reach the existing engine; retained metadata
uses identity references, revisions and explicitly allowed API scopes.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import posixpath
from urllib.parse import unquote, urlsplit

from ..runner import credential_names_for, normalize_spec, redact_evidence
from ..spec import build_request
from . import engine
from .control import RunControl
from .identity import CREDENTIAL_HEADERS
from .model import redact_url
from .transport import Budget, MutationRefused, build_client


def _scope(url: str) -> tuple:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("An API scope must be an HTTP(S) URL without embedded credentials.")
    # Decode before normalising: encoded slashes and dot segments cannot widen
    # a bearer assignment. Reject double encoding as ambiguous.
    path = unquote(parsed.path or "/")
    if unquote(path) != path or "\\" in path or ("%" in parsed.path and any(
            segment in {".", ".."} for segment in path.split("/"))):
        raise ValueError("Ambiguous encoded API scope path.")
    path = posixpath.normpath("/" + path.lstrip("/")).rstrip("/") or "/"
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80), path


def in_scope(url: str, allowed: str) -> bool:
    try:
        request, scope = _scope(url), _scope(allowed)
    except ValueError:
        return False
    return request[:3] == scope[:3] and (scope[3] == "/" or request[3] == scope[3]
                                        or request[3].startswith(scope[3] + "/"))


class ScopedClient:
    """One raw run client, with a separate immutable guard per contract.

    Redirects are evidence of a redirect, never an extra hidden dispatch.
    Credential checks also happen before the executor charges its budget.
    """

    def __init__(self, client, target: str, allowed_scopes=(), credential_names=(), scope_guard=None):
        self.client = client
        self.target = target
        self.allowed_scopes = tuple(allowed_scopes)
        self.credential_names = CREDENTIAL_HEADERS | {str(name).lower() for name in credential_names}
        self.headers = client.headers
        self.scope_guard = scope_guard

    def check_request_scope(self, url, headers, *, review=True):
        if review and self.scope_guard is not None and self.scope_guard() is False:
            raise MutationRefused("Reviewed contract target or identity changed; review the plan again.")
        try:
            request_scope, target_scope = _scope(url), _scope(self.target)
        except ValueError as exc:
            raise MutationRefused("Request has an ambiguous or invalid API scope path.") from exc
        if request_scope[:3] != target_scope[:3]:
            raise MutationRefused("Request is outside the reviewed API origin.")
        if any(str(name).lower() in self.credential_names for name in headers) and not any(
                in_scope(url, scope) for scope in self.allowed_scopes):
            raise MutationRefused("Credential dispatch is outside the explicitly assigned API base paths; review scope.")

    def send(self, request, **kwargs):
        self.check_request_scope(str(request.url), request.headers, review=False)
        kwargs["follow_redirects"] = False
        return self.client.send(request, **kwargs)


class ContractControl(RunControl):
    """A contract ceiling chained to the one run budget, pacer and stop."""

    def __init__(self, parent, limit):
        self.run_budget = Budget(limit, parent=parent.run_budget)
        self.cancel = parent.cancel
        self.write_withdrawn = parent.write_withdrawn
        self.pace = parent.pace
        self.receipts = parent.receipts


def _credential_sources(config):
    sources = []
    for item in config.get("operations") or []:
        for identity in (item.get("identities") or {}).values():
            if isinstance(identity, dict):
                sources.append({"headers": identity.get("headers", identity)})
    return sources


def _safe(value, config):
    names = set(config.get("credential_names") or [])
    for item in config.get("operations") or []:
        names.update(credential_names_for(item.get("spec") or {}, names))
    return redact_evidence(copy.deepcopy(value), sources=_credential_sources(config),
                           credential_names=names)


def redact_run_value(value, config):
    """Redact every run-assigned credential, including other contracts' secrets."""
    return _safe(value, config)


def safe_workspace(config):
    return _safe(config.get("workspace") or {}, config)


def operation_context(item, workspace_id):
    return {"workspace_id": workspace_id, "contract_id": item["contract_id"],
            "operation_key": item["operation_key"], "snapshot_hash": item["snapshot_hash"],
            "target": redact_url(item["base_url"]), "identity_ref": item.get("identity_ref"),
            "identity_revision": item.get("identity_revision"),
            "identity_source": item.get("identity_source") or "no identity configured"}


def stored_config(config):
    keys = ("profile", "budget", "requests_per_second", "concurrency", "timeout", "inventory",
            "response_comparison", "per_contract_limits")
    stored = {key: copy.deepcopy(config.get(key)) for key in keys}
    stored["workspace"] = safe_workspace(config)
    stored["operations"] = [
        {**operation_context(item, stored["workspace"].get("id")),
         "operation_id": item.get("operation_id"),
         "allow_mutating": bool(item.get("allow_mutating")),
         "request_budget": item.get("request_budget"), "excluded": bool(item.get("excluded")),
         "reuse_from": item.get("reuse_from"), "allowed_scopes": item.get("allowed_scopes") or []}
        for item in config.get("operations") or []]
    return _safe(stored, config)


def validate_config(config):
    """Fail closed before any thread or request if a reviewed scope is missing."""
    seen = set()
    for item in config.get("operations") or []:
        for required in ("contract_id", "operation_key", "snapshot_hash", "base_url", "operation_id", "spec"):
            if not item.get(required):
                raise ValueError(f"A workspace operation is missing its reviewed {required}.")
        if item["operation_key"] in seen:
            raise ValueError("A workspace plan contains the same operation key twice.")
        seen.add(item["operation_key"])
        _scope(item["base_url"])
        for identity in (item.get("identities") or {}).values():
            if not isinstance(identity, dict) or "oauth" in identity:
                raise ValueError("Workspace runs accept assigned bearer/header identities; token acquisition is separate.")
            headers = identity.get("headers", identity)
            if headers and not any(in_scope(item["base_url"], scope) for scope in item.get("allowed_scopes") or []):
                raise ValueError("The target has no explicit identity scope assignment; review the target and identity.")
        if item.get("identities") and not item.get("identity_ref"):
            raise ValueError("A credential needs its reviewed identity reference.")
    for limit in (config.get("per_contract_limits") or {}).values():
        if int(limit) < 1:
            raise ValueError("Per-contract request limits must be positive.")


def _fingerprint(item, config):
    # Intentionally conservative: two whole resolved documents must agree,
    # including response assertions and security declarations. Source locations
    # and workspace identities differ but do not alter an already built request.
    parsed = copy.deepcopy(normalize_spec(item["spec"]))
    primary = (item.get("identities") or {}).get("primary") or {}
    headers = primary.get("headers", primary)
    built = build_request(parsed, item["operation_id"], base_url=item["base_url"], headers=headers)
    if item.get("example"):
        built, _ = engine._apply_example(built, item["example"], headers)
    parsed.pop("source_url", None)
    parsed.pop("title", None)
    (parsed.get("document", {}).get("info") or {}).pop("title", None)
    material = {"spec": parsed, "operation": item["operation_id"], "target": item["base_url"],
                # Mapping insertion order selects media/examples/default samples
                # in the existing builder; a sorted JSON document hash alone
                # cannot prove that the resulting requests are identical.
                "built_request": {key: built.get(key) for key in
                                  ("method", "url", "body", "has_body", "headers", "content_type")},
                "identities": item.get("identities") or {}, "identity_ref": item.get("identity_ref"),
                "identity_revision": item.get("identity_revision"),
                "allowed_scopes": item.get("allowed_scopes") or [],
                "example": item.get("example"), "expectation": item.get("expectation"),
                "assertions": item.get("assertions"), "baseline": item.get("baseline"),
                "allow_mutating": bool(item.get("allow_mutating")),
                "request_budget": item.get("request_budget"),
                "contract_limit": (config.get("per_contract_limits") or {}).get(item["contract_id"])}
    for key in ("profile", "timeout", "concurrency", "response_comparison", "verify_tls", "user_agent",
                "proxy", "quiet", "ca_bundle", "client_cert", "client_key", "credential_names"):
        material[key] = config.get(key)
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


def _attach(result, context, *, reused_from=None):
    result = copy.deepcopy(result)
    result.update(context)
    result["assessment_status"] = "reused" if reused_from else result.get("assessment_status", "assessed")
    result["evidence_reused"] = bool(reused_from)
    result["evidence_owner_operation_key"] = reused_from or context["operation_key"]
    refs = [entry["exchange_id"] for entry in result.get("log") or [] if entry.get("exchange_id")]
    result["evidence_refs"] = refs
    if reused_from:
        result["requests_sent"] = 0
        result["request_breakdown"] = dict.fromkeys(("inventory", "baseline", "schema_inputs", "other_endpoint_tests", "total"), 0)
        result["log"] = []
        result.setdefault("notes", []).append(
            "Reused the explicitly reviewed identical assessment's recorded exchanges; no independent request was sent.")
    result["network_attempts"] = int(result.get("requests_sent") or 0)
    for key in ("log", "findings", "probes", "field_coverage"):
        for child in result.get(key) or []:
            if isinstance(child, dict):
                child.update(context)
                if reused_from:
                    child["evidence_reused"] = True
    for key in ("baseline", "test_plan"):
        if isinstance(result.get(key), dict):
            result[key].update(context)
    return result


def _retain_receipt_counts(manager, run_id, case_id, result):
    """Even an exception after dispatch cannot erase a known network attempt."""
    rows = [row for row in manager.store.exchanges(run_id) if row["case_id"] == case_id]
    result["requests_sent"] = len(rows)
    result["network_attempts"] = len(rows)
    result["evidence_refs"] = [row["exchange_id"] for row in rows]
    return result


def execute_workspace(manager, run_id, config, control, receipts):
    """Sequence each contract's engine calls without sharing contract state."""
    from .run_service import _now

    operations = config["operations"]
    workspace_id = config["workspace"].get("id")
    link = manager._connection(config)
    http = build_client(connection=link)
    controls, prior, inventory_done = {}, {}, set()
    done, stop_reason = 0, ""
    try:
        manager._set_status(run_id, "running", "workspace", control)
        for index, item in enumerate(operations):
            if control.cancelled or control.rate_limited:
                stop_reason = "cancelled" if control.cancelled else "rate-limited"
                break
            contract_id = item["contract_id"]
            context = operation_context(item, workspace_id)
            case_id = f"op-{index:03d}"
            receipts.current_case, receipts.current_context = case_id, context
            stale = item.get("scope_guard") is not None and item["scope_guard"]() is False
            if item.get("excluded") or stale:
                result = _attach({"operation_id": item["operation_id"], "requests_sent": 0,
                                  "assessment_status": "stale-plan" if stale else "excluded", "log": [], "findings": [],
                                  "notes": ["Contract target, configuration or identity changed; review a new plan before testing."
                                            if stale else "Excluded by the reviewed overlap decision; not independently tested."]}, context)
            else:
                fingerprint = _fingerprint(item, config)
                owner = prior.get(item.get("reuse_from"))
                if owner and owner[0] == fingerprint:
                    result = _attach(owner[1], context, reused_from=item["reuse_from"])
                else:
                    if control.remaining <= 0:
                        stop_reason = "budget"
                        break
                    limit = (config.get("per_contract_limits") or {}).get(contract_id) or control.limit
                    child = controls.setdefault(contract_id, ContractControl(control, limit))
                    client = ScopedClient(http, item["base_url"], item.get("allowed_scopes") or [],
                                          credential_names_for(item["spec"], config.get("credential_names") or []),
                                          item.get("scope_guard"))
                    if config.get("inventory") and contract_id not in inventory_done and child.remaining:
                        inventory_done.add(contract_id)
                        receipts.current_case = f"inventory-{contract_id}"
                        receipts.current_context = {**context, "operation_key": None, "identity_ref": None,
                                                    "identity_revision": None, "identity_source": "no identity configured",
                                                    "scope": "inventory"}
                        try:
                            inv = engine.audit_inventory(item["spec"], base_url=item["base_url"], identities={},
                                timeout=float(config.get("timeout") or 15), budget=min(60, child.remaining),
                                connection=link, concurrency=config.get("concurrency"),
                                requests_per_second=config.get("requests_per_second"), client=client, control=child)
                        except Exception as exc:
                            inv = {"error": type(exc).__name__, "notes": ["The inventory sweep could not finish."]}
                        inv = _attach(inv, receipts.current_context)
                        _retain_receipt_counts(manager, run_id, receipts.current_case, inv)
                        manager._save_case(run_id, receipts.current_case, index * 2, "surface sweep", "inventory", inv, control)
                        receipts.current_case, receipts.current_context = case_id, context
                    manager._set_status(run_id, "running", item["operation_key"], control)
                    expectation = copy.deepcopy(item.get("expectation") or {})
                    if item.get("assertions"):
                        expectation["business_assertions"] = copy.deepcopy(item["assertions"])
                    profile = config.get("profile") or "readonly"
                    if profile == "writes" and not item.get("allow_mutating"):
                        profile = "readonly"
                    if child.remaining <= 0:
                        result = {"operation_id": item["operation_id"], "assessment_status": "budget-excluded",
                                  "requests_sent": 0, "notes": ["Contract request limit exhausted; operation not tested."]}
                    else:
                        try:
                            result = engine.audit_operation(item["spec"], item["operation_id"],
                                base_url=item["base_url"], identities=item.get("identities") or {}, profile=profile,
                                allow_mutating=bool(item.get("allow_mutating")), timeout=float(config.get("timeout") or 15),
                                concurrency=config.get("concurrency"), connection=link,
                                requests_per_second=config.get("requests_per_second"),
                                credential_names=config.get("credential_names") or [],
                                response_comparison=config.get("response_comparison"), client=client, control=child,
                                example=item.get("example"), expectation=expectation,
                                request_budget=item.get("request_budget"))
                        except Exception as exc:
                            result = {"operation_id": item["operation_id"], "error": type(exc).__name__,
                                      "notes": [f"This operation could not be audited: {type(exc).__name__}."]}
                    result = _attach(result, context)
                    _retain_receipt_counts(manager, run_id, case_id, result)
                    if item.get("reuse_from"):
                        result.setdefault("notes", []).append(
                            "Reviewed reuse did not match the full request, identity, assertions and execution context; assessed separately.")
                if not result.get("error") and result.get("assessment_status") == "assessed":
                    prior[item["operation_key"]] = (fingerprint, result)
            manager._save_case(run_id, case_id, index * 2 + 1, item["operation_key"], "operation", _safe(result, config), control)
            done += 1
    except BaseException as exc:
        stop_reason = stop_reason or f"error:{type(exc).__name__}"
    finally:
        with contextlib.suppress(Exception):
            http.close()
        run = manager.store.get_run(run_id)
        if run:
            snapshot = dict(run.get("snapshot") or {})
            snapshot["contract_requests"] = {key: value.spent for key, value in controls.items()}
            manager.store.update_run(run_id, updated_at=_now(), snapshot=snapshot)
        manager._finalise(run_id, config, control, done, stop_reason)
        with manager._lock:
            manager._threads.pop(run_id, None)
            manager._controls.pop(run_id, None)


def build_export(run, cases, exchanges):
    """Portable workspace boundary and assessment links, one row per exchange."""
    snapshot, config = run.get("snapshot") or {}, run.get("config") or {}
    workspace = copy.deepcopy(config["workspace"])
    assessments = [{"case_id": row["case_id"], "scope": row["scope"], **row["result"]} for row in cases]
    attempts = [{**row["record"], "exchange_id": row["exchange_id"], "seq": row["seq"], "state": row["state"]}
                for row in exchanges]
    snapshots, plans, links, exclusions = {}, [], [], []
    findings, finding_index = [], {}
    for result in assessments:
        key = result.get("operation_key")
        context = {name: result.get(name) for name in ("contract_id", "operation_key", "snapshot_hash", "target", "identity_ref", "identity_revision")}
        if result.get("assessment_status") == "excluded":
            exclusions.append(context)
        if result.get("contract_snapshot") and key:
            snapshots[key] = result["contract_snapshot"]
        if result.get("test_plan"):
            plans.append(result["test_plan"])
        links.append({**context, "evidence_refs": result.get("evidence_refs") or [],
                      "evidence_reused": bool(result.get("evidence_reused")),
                      "assessment_status": result.get("assessment_status")})
        for finding in result.get("findings") or []:
            # Only assessments explicitly reusing the very same evidence share
            # a top-level finding. Distinct operation evidence remains distinct.
            owner = result.get("evidence_owner_operation_key") or result.get("contract_id")
            assessment_metadata = {*context, "workspace_id", "identity_source", "evidence_reused", "assessment_links"}
            material = {name: value for name, value in finding.items() if name not in assessment_metadata}
            marker = (owner, hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest())
            if marker not in finding_index:
                saved = copy.deepcopy(finding)
                saved["assessment_links"] = []
                finding_index[marker] = saved
                findings.append(saved)
            finding_index[marker]["assessment_links"].append(context)
    contracts = []
    for contract in workspace.get("contracts") or []:
        saved = copy.deepcopy(contract)
        cid = saved.get("id") or saved.get("contract_id")
        saved["assessments"] = [item for item in assessments if item.get("contract_id") == cid]
        contracts.append(saved)
    operation_results = [item for item in assessments if item.get("scope") == "operation"]
    independently_dispatched = sum(bool(item.get("network_attempts")) for item in operation_results)
    return {
        "application": "Namazu", "export": "security-audit", "export_version": 2,
        "exported_at": snapshot.get("finished_at") or snapshot.get("started_at"),
        "started_at": snapshot.get("started_at"),
        "run": {"status": snapshot.get("run_status"), "cancelled": bool(snapshot.get("cancelled")),
                "rate_limited": bool(snapshot.get("rate_limited")), "interrupted": bool(run.get("interrupted")),
                "writes_withdrawn": bool(snapshot.get("writes_withdrawn")), "finished_at": snapshot.get("finished_at")},
        "api": {"title": workspace.get("title") or "Multi-contract workspace", "version": "", "base_url": ""},
        "provenance": {"kind": "interrupted-run" if run.get("interrupted") else "live-run",
                       "requests_sent_during_current_action": 0},
        "scope": {"profile": config.get("profile"), "requests_sent": len(attempts),
                  "unique_network_attempts": len(attempts), "request_budget": snapshot.get("budget"),
                  "inventory_requests": sum(item.get("scope") == "inventory" for item in attempts),
                  "endpoints_audited": independently_dispatched,
                  "independently_dispatched_operations": independently_dispatched,
                  "endpoints_in_scope": snapshot.get("total"), "contract_assessments": len(operation_results) - len(exclusions),
                  "assessments_without_network_evidence": sum(not item.get("evidence_refs") and item.get("assessment_status") != "excluded"
                                                               for item in operation_results),
                  "reused_assessments": sum(bool(item.get("evidence_reused")) for item in operation_results),
                  "overlap_exclusions": len(exclusions), "inventory_planned": bool(config.get("inventory"))},
        "workspace": workspace, "contracts": contracts, "assessments": assessments,
        "assessment_links": links, "overlap_exclusions": exclusions,
        "contract_snapshots": snapshots, "test_plans": plans, "requests": attempts,
        "network_attempts": attempts, "findings": findings, "notes": snapshot.get("notes") or [],
        "response_comparison": config.get("response_comparison"),
    }
