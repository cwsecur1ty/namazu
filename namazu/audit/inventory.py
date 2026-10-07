"""Inventory checks: what exists on the host that the contract does not describe.

Three questions, all answered with read-only requests inside a hard cap:

* **Zombies**: documented operations that no longer answer.
* **Shadows**: version siblings and conventional paths that answer but appear
  in no contract, so nobody reviews their authorization.
* **Exposure**: specification documents, interactive docs, debug surfaces and
  GraphQL introspection served to anonymous callers.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

from .model import Exchange, finding, mark
from .transport import BudgetExhausted, Executor

VERSION_IN_PATH = re.compile(r"(?i)(^|/)(v|version)(\d+)(?=/|$)")

DOC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/swagger-ui/",
    "/docs", "/redoc", "/.well-known/openapi.json",
)
OPS_PATHS = (
    "/actuator", "/actuator/env", "/actuator/health", "/metrics", "/debug/vars",
    "/health", "/healthz", "/status", "/server-status", "/.env", "/config.json",
    "/admin", "/internal", "/_debug", "/trace", "/console",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")
# Files that should never be served, and that disclose source or configuration.
# Each needs a content fingerprint: a 200 alone proves nothing on a host that
# rewrites unknown paths to an application shell.
SOURCE_PATHS = (
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/requires",
    "/web.config", "/appsettings.json", "/package.json", "/composer.lock",
    "/Dockerfile", "/docker-compose.yml", "/.npmrc",
)
SOURCE_MARKERS = {
    "/.git/HEAD": re.compile(r"^ref:\s+refs/"),
    "/.git/config": re.compile(r"(?m)^\s*\[core\]"),
    "/.svn/entries": re.compile(r"^\d+\s"),
    "/.hg/requires": re.compile(r"(?m)^(revlogv1|dotencode|store|fncache)"),
    "/web.config": re.compile(r"(?i)<configuration[\s>]"),
    "/appsettings.json": re.compile(r'(?s)\{.*"(?:ConnectionStrings|Logging|AllowedHosts)"'),
    "/package.json": re.compile(r'(?s)\{.*"(?:dependencies|devDependencies|name)"\s*:'),
    "/composer.lock": re.compile(r'(?s)\{.*"(?:packages|content-hash)"'),
    "/Dockerfile": re.compile(r"(?mi)^\s*FROM\s+\S"),
    "/docker-compose.yml": re.compile(r"(?m)^\s*(services|version)\s*:"),
    "/.npmrc": re.compile(r"(?m)^(//|_auth|registry=)"),
}
SOURCE_SEVERITY = {"/.git/HEAD": "high", "/.git/config": "high", "/.svn/entries": "high",
                   "/.hg/requires": "high", "/.npmrc": "high", "/appsettings.json": "high",
                   "/web.config": "medium", "/composer.lock": "low", "/package.json": "low",
                   "/Dockerfile": "medium", "/docker-compose.yml": "medium"}
INTROSPECTION = json.dumps({"query": "{__schema{queryType{name} types{name}}}"})

SENSITIVE_OPS = re.compile(r"(?i)/(actuator/env|\.env|debug|trace|console|server-status|config\.json|admin|internal)")
DOC_MARKERS = re.compile(r"(?i)(\"openapi\"\s*:|\"swagger\"\s*:|swagger-ui|redoc|<title>[^<]*api[^<]*docs)")
SUGGESTION = re.compile('(?i)did you mean[^\n}]{0,120}')
SOFT_404 = re.compile(r"(?i)(not found|does not exist|no such|404|unknown (route|endpoint|path))")


def _origin(base_url: str) -> str:
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _join(origin: str, path: str) -> str:
    return origin.rstrip("/") + "/" + path.lstrip("/")


def _live(exchange: Exchange) -> bool:
    return exchange.ok and exchange.status not in (0, 404, 410, 501, 502, 503, 504)


def _calibrate(executor: Executor, origin: str, headers: dict) -> dict:
    """Learn how the host answers a path that certainly does not exist."""
    probe = executor.send("GET", _join(origin, "/namazu-does-not-exist-9d2f41"),
                          label="404 calibration", headers=headers)
    return {"status": probe.status, "length": len(probe.body), "ok": probe.ok,
            "catch_all": probe.ok and probe.status < 400}


def _is_real_hit(exchange: Exchange, calibration: dict) -> bool:
    if not _live(exchange):
        return False
    if calibration.get("catch_all"):
        # The host answers everything. Only a clearly different body counts.
        if exchange.status == calibration["status"] and abs(len(exchange.body) - calibration["length"]) < 48:
            return False
    if exchange.status == 200 and SOFT_404.search(exchange.body[:400] or ""):
        return False
    return True


def run(executor: Executor, *, spec: dict, base_url: str, headers: dict,
        documented_paths: set[str], check_zombies: bool = True) -> tuple[list, dict]:
    """Probe around the documented surface. Returns (findings, summary)."""
    findings: list = []
    origin = _origin(base_url)
    summary = {"calibrated": False, "probed": 0, "shadow": [], "zombie": [], "exposed": []}

    try:
        calibration = _calibrate(executor, origin, headers)
        summary["calibrated"] = True
        summary["catch_all"] = calibration.get("catch_all", False)

        findings += _documents(executor, origin, headers, calibration, summary)
        findings += _operations(executor, origin, headers, calibration, summary)
        findings += _source_files(executor, origin, headers, calibration, summary)
        findings += _graphql(executor, origin, headers, calibration, summary)
        findings += _graphql_suggestions(executor, origin, headers, calibration, summary)
        findings += _versions(executor, base_url, headers, calibration, documented_paths, summary)
    except BudgetExhausted:
        summary["budget_exhausted"] = True
    summary["probed"] = len([e for e in executor.exchanges if e.label.startswith(("inventory", "404"))])
    return findings, summary


def _documents(executor, origin, headers, calibration, summary) -> list:
    out = []
    for path in DOC_PATHS:
        if not executor.affordable(1):
            break
        exchange = executor.send("GET", _join(origin, path), label=f"inventory {path}", headers=headers)
        if not _is_real_hit(exchange, calibration) or exchange.status >= 400:
            continue
        if not DOC_MARKERS.search(exchange.body[:4000] or ""):
            continue
        summary["exposed"].append(path)
        out.append(finding(
            "inventory.docs-exposed", "API documentation is served to anonymous callers",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management",
            endpoint=f"GET {path}",
            method=("Requested well-known specification and documentation paths with no credentials, and "
                    "required the body to match a specification or documentation marker rather than just "
                    "a 200."),
            detail=(f"{path} returned HTTP {exchange.status} with a specification or documentation page "
                    "to a request carrying no credentials."),
            impact="Publishes the full route, parameter and schema inventory to anyone who asks.",
            remediation="Serve the specification only to authenticated internal users, or accept it as "
                        "public and make sure every route is secured on its own merits.",
            evidence={"path": path, "status": exchange.status, "length": len(exchange.body)},
            exchanges=[exchange],
        ))
        break  # One documentation finding per host is enough.
    return out


def _operations(executor, origin, headers, calibration, summary) -> list:
    out = []
    for path in OPS_PATHS:
        if not executor.affordable(1):
            break
        exchange = executor.send("GET", _join(origin, path), label=f"inventory {path}", headers=headers)
        if not _is_real_hit(exchange, calibration) or exchange.status >= 400:
            continue
        summary["shadow"].append(path)
        sensitive = bool(SENSITIVE_OPS.search(path))
        out.append(finding(
            "inventory.undocumented-endpoint",
            f"Undocumented endpoint {path} answers requests",
            "medium" if sensitive else "low", "confirmed",
            owasp="API9:2023 Improper Inventory Management", endpoint=f"GET {path}",
            method=("Requested conventional operational paths with no credentials, after first "
                    "calibrating against a path that certainly does not exist so a catch-all host cannot "
                    "produce hits."),
            detail=(f"{path} returned HTTP {exchange.status} but appears in no imported contract. "
                    + ("This path commonly exposes configuration, environment variables or internal "
                       "administration." if sensitive else "Undocumented routes are rarely covered by "
                       "review or testing.")),
            impact=("Operational and debug endpoints frequently disclose secrets and internal topology."
                    if sensitive else "Shadow routes drift outside the controls applied to documented ones."),
            remediation="Remove the route, restrict it to an internal network, or document and secure it.",
            evidence={"path": path, "status": exchange.status, "length": len(exchange.body),
                      "content_type": exchange.content_type},
            exchanges=[exchange],
        ))
    return out


def _graphql(executor, origin, headers, calibration, summary) -> list:
    """Introspection is a read-only GraphQL query, so it runs without write consent."""
    out = []
    for path in GRAPHQL_PATHS:
        if not executor.affordable(1):
            break
        url = _join(origin, path)
        exchange = executor.send(
            "POST", url, label=f"inventory {path} introspection", headers=headers,
            body=INTROSPECTION, content_type="application/json", mutating=False,
        )
        if not exchange.ok or exchange.status >= 400:
            continue
        if '"__schema"' not in (exchange.body or "") and '"types"' not in (exchange.body or ""):
            continue
        summary["exposed"].append(path)
        out.append(finding(
            "inventory.graphql-introspection", "GraphQL introspection is enabled",
            "medium", "confirmed", owasp="API9:2023 Improper Inventory Management",
            endpoint=f"POST {path}",
            method=("Posted a standard introspection query, which is a read-only GraphQL query rather than a mutation, "
                    "and checked whether the schema came back."),
            detail=(f"An introspection query to {path} returned the schema (HTTP {exchange.status}). "
                    "Introspection publishes every type, field, mutation and argument the API exposes."),
            impact="Hands an attacker the complete map of the API, including fields no client uses.",
            remediation="Disable introspection in production, or restrict it to authenticated internal "
                        "clients. Pair it with query depth and cost limits.",
            evidence={"path": path, "status": exchange.status,
                      "excerpt": (exchange.body or "")[:300]},
            exchanges=[exchange],
        ))
        break
    return out


def _versions(executor, base_url, headers, calibration, documented_paths, summary) -> list:
    """If the contract covers /v2, is /v1 still answering?"""
    out = []
    parts = urlsplit(base_url)
    match = VERSION_IN_PATH.search(parts.path or "")
    sample = next(iter(sorted(documented_paths)), "")
    if not match:
        match = VERSION_IN_PATH.search(sample)
        if not match:
            return out
        container, template = sample, "path"
    else:
        container, template = parts.path, "base"

    current = int(match.group(3))
    candidates = sorted({n for n in (current - 1, current - 2, current + 1) if n >= 0 and n != current})
    for version in candidates:
        if not executor.affordable(1):
            break
        replaced = container[:match.start(3)] + str(version) + container[match.end(3):]
        url = (urlunsplit((parts.scheme, parts.netloc, replaced, "", "")) if template == "base"
               else _join(_origin(base_url), replaced))
        exchange = executor.send("GET", url, label=f"inventory version sibling v{version}", headers=headers)
        if not _is_real_hit(exchange, calibration) or exchange.status >= 400:
            continue
        summary["shadow"].append(url)
        older = version < current
        out.append(finding(
            "inventory.version-sibling",
            f"Undocumented API version v{version} is reachable",
            "medium" if older else "low", "confirmed",
            owasp="API9:2023 Improper Inventory Management", endpoint=f"GET {url}",
            method=("Replaced the version number in the documented path with its neighbours and kept only "
                    "responses that differ from the calibrated not-found response."),
            detail=(f"The contract describes v{current}, but v{version} answered with HTTP "
                    f"{exchange.status}. "
                    + ("A superseded version usually keeps its original authorization and validation rules."
                       if older else "A newer, undocumented version may still be under development.")),
            impact="Old versions are the classic way to reach data the current version protects.",
            remediation="Retire superseded versions, or bring them under the same contract, controls and "
                        "review as the current one.",
            evidence={"documented_version": current, "reachable_version": version,
                      "status": exchange.status, "url": url},
            exchanges=[exchange],
        ))
    return out


def zombie_check(baseline: Exchange, endpoint: str) -> list:
    """A documented operation that no longer exists."""
    if baseline.ok and baseline.status in (404, 410):
        return [finding(
            "inventory.zombie-operation", "Documented operation is not implemented",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management", endpoint=endpoint,
            detail=f"The contract documents {endpoint}, but the server answered HTTP {baseline.status}.",
            impact="The contract no longer describes the running service, so reviews based on it are "
                   "incomplete.",
            remediation="Remove the operation from the contract, or restore the route.",
            evidence={"status": baseline.status}, exchanges=[baseline],
        )]
    return []


def allowed_methods(executor: Executor, *, url: str, endpoint: str, headers: dict,
                    documented: set[str]) -> list:
    """OPTIONS reveals verbs the contract never mentions."""
    if not executor.affordable(1):
        return []
    exchange = executor.send("OPTIONS", url, label="OPTIONS method enumeration", headers=headers)
    allow = exchange.header("allow") or exchange.header("access-control-allow-methods")
    if not allow:
        return []
    advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
    extra = sorted(advertised - documented - {"OPTIONS", "HEAD", "TRACE"})
    writes = sorted(set(extra) & {"PUT", "PATCH", "DELETE", "POST"})
    if not writes:
        return []
    return [finding(
        "inventory.undocumented-methods", "Server advertises methods the contract does not document",
        "medium", "confirmed", owasp="API9:2023 Improper Inventory Management", endpoint=endpoint,
        method=("Sent OPTIONS to the documented path and compared the advertised Allow header with "
                "the methods the contract declares for it."),
        detail=(f"OPTIONS returned Allow: {allow}. The contract documents {', '.join(sorted(documented)) or 'none'} "
                f"for this path, leaving {', '.join(writes)} undocumented."),
        impact="Undocumented write verbs are rarely covered by the authorization review the documented "
               "ones receive.",
        remediation="Document every supported method, and reject the ones the route does not implement.",
        evidence={"allow": allow, "documented": sorted(documented), "undocumented": writes},
        exchanges=[exchange],
    )]


def _source_files(executor, origin, headers, calibration, summary) -> list:
    """Version-control metadata and configuration files served to the public.

    Each path carries its own content fingerprint, so a host that answers 200
    for everything cannot turn this into a page of findings.
    """
    out = []
    for path in SOURCE_PATHS:
        if not executor.affordable(1):
            break
        exchange = executor.send("GET", _join(origin, path), label=f"inventory {path}", headers=headers)
        if not _is_real_hit(exchange, calibration) or exchange.status >= 400:
            continue
        marker = SOURCE_MARKERS.get(path)
        if not marker or not marker.search(exchange.body or ""):
            continue
        summary["exposed"].append(path)
        severity = SOURCE_SEVERITY.get(path, "medium")
        vcs = path.startswith(("/.git", "/.svn", "/.hg"))
        out.append(finding(
            "inventory.source-exposed", f"{path} is served to anonymous callers",
            severity, "confirmed", owasp="API9:2023 Improper Inventory Management",
            endpoint=f"GET {path}",
            method=(f"Requested {path} with no credentials and matched the body against a fingerprint "
                    "specific to that file, so a catch-all response cannot satisfy the check."),
            detail=(f"{path} returned HTTP {exchange.status} with content matching the expected format "
                    f"for that file ({len(exchange.body)} bytes)."),
            background=(
                "Deployments that copy a working directory rather than a build artefact ship the files "
                "around the application as well as the application. Version-control metadata is the "
                "worst case: with the object store reachable, the full source history can usually be "
                "reconstructed, including secrets that were committed and later removed."
                if vcs else
                "Build and configuration files are not meant to be reachable over HTTP. They disclose "
                "dependency versions, internal hostnames and sometimes credentials."),
            impact=("The repository can likely be reconstructed, exposing source and any secret ever "
                    "committed to it." if vcs else
                    "Discloses dependencies, configuration and internal details that narrow an attack."),
            remediation=("Serve a build artefact rather than a working directory, and block dotfile and "
                         "configuration paths at the web server or CDN. Rotate any credential that was "
                         "reachable." if vcs else
                         "Remove the file from the served root and block it at the web server."),
            highlights=[mark(path, "leak", "The path that answered, with content matching its format.")],
            evidence={"path": path, "status": exchange.status, "length": len(exchange.body),
                      "content_type": exchange.content_type,
                      "excerpt": (exchange.body or "")[:200]},
            exchanges=[exchange],
        ))
    return out


def _graphql_suggestions(executor, origin, headers, calibration, summary) -> list:
    """Introspection off is not the whole story: field suggestions leak the schema too.

    Asking for a field that does not exist makes several GraphQL servers reply
    with "Did you mean ...", which walks the schema one guess at a time. The
    probe sends one deliberately wrong field name and looks for that response.
    """
    out = []
    probe_field = "namazuProbeFieldZz"
    query = json.dumps({"query": "{ " + probe_field + " }"})
    for path in GRAPHQL_PATHS:
        if not executor.affordable(1):
            break
        exchange = executor.send(
            "POST", _join(origin, path), label=f"inventory {path} field suggestion",
            headers=headers, body=query, content_type="application/json", mutating=False,
        )
        if not exchange.ok or exchange.status >= 500:
            continue
        body = exchange.body or ""
        if '"errors"' not in body:
            continue
        match = SUGGESTION.search(body)
        if not match:
            continue
        summary["exposed"].append(f"{path} (suggestions)")
        return [finding(
            "inventory.graphql-suggestions", "GraphQL field suggestions are enabled",
            "low", "confirmed", owasp="API9:2023 Improper Inventory Management",
            endpoint=f"POST {path}",
            method=(f"Sent a query for the non-existent field {probe_field} and looked for a "
                    "suggestion phrase in the error response."),
            detail=(f"Querying an unknown field returned a suggestion: \"{match.group(0)[:120]}\". "
                    "The server is proposing real field names in its error messages."),
            background=(
                "Disabling introspection is the usual hardening step, but suggestions defeat it. A "
                "server that answers an unknown field with \"Did you mean ...\" lets an attacker "
                "recover the schema name by name, which is slower than introspection and just as "
                "complete."),
            impact=("The schema can be reconstructed despite introspection being off, revealing types, "
                    "fields and mutations that no client uses."),
            remediation=("Disable field suggestions in production. In graphql-js set "
                         "`didYouMean: false` or strip suggestion text in a custom error formatter; "
                         "most other server libraries expose an equivalent switch. Pair it with "
                         "disabled introspection and a persisted-query allow-list."),
            highlights=[mark(probe_field, "attacker", "The field name KAPI invented; it exists nowhere."),
                        mark(match.group(0)[:80], "leak", "A real field name the server offered back.")],
            evidence={"path": path, "probe_field": probe_field, "status": exchange.status,
                      "suggestion": match.group(0)[:200]},
            exchanges=[exchange],
        )]
    return out
