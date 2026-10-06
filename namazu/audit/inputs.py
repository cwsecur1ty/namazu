"""Input-handling probes built from detection canaries, not exploits.

Every payload here is chosen so that a *positive* result is unambiguous and a
*negative* one costs nothing: arithmetic that only a template engine evaluates,
a redirect target on a reserved domain, a quote that only an unparameterised
query complains about. No payload sleeps, writes, reads a real file, or runs a
command.

Each probe carries its own oracle, so none of them fire on mere reflection:

* **Paired control**: the error-based probes send a structurally identical but
  inert twin (``''`` against ``'``, ``[xne]`` against ``[$ne]``). A field that
  rejects every quote therefore reads as strict validation, not injection.
* **Two-value evaluation**: template injection must return two different
  products from two different sums, with the expression itself absent.
* **Nonce binding**: reflection is matched on a per-probe random token, so a
  string already present in the response cannot satisfy the check.
* **Side-channel oracle**: the redirect probe reads the ``Location`` header for
  a reserved host, and traversal matches a system-file signature; neither
  depends on the body echoing anything back.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .model import Exchange, finding, mark, similarity
from .transport import BudgetExhausted, Executor

MAX_FIELDS = 4
REDIRECT_HOST = "namazu-probe.invalid"

SQL_ERRORS = re.compile(
    r"(?i)(SQL syntax.{0,40}MySQL|Warning.{0,20}\bmysqli?_|valid MySQL result|"
    r"PostgreSQL.{0,30}ERROR|pg_query\(\)|PG::SyntaxError|"
    r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|"
    r"SQLite3?::SQLException|sqlite3.OperationalError|near \"[^\"]+\": syntax error|"
    r"ORA-0[0-9]{4}|Oracle error|quoted string not properly terminated|"
    r"SQLSTATE\[[0-9A-Z]{5}\]|System\.Data\.SqlClient\.SqlException)"
)
NOSQL_ERRORS = re.compile(
    r"(?i)(MongoError|MongoServerError|CastError|BSONTypeError|E11000 duplicate key|"
    r"\$where.{0,30}not allowed|unknown operator: \$)"
)
TRAVERSAL_HITS = re.compile(r"root:[x*!]?:0:0:|\[(?:boot loader|fonts)\]|; for 16-bit app support")


def _nonce() -> str:
    return "k" + secrets.token_hex(4)


def _replace_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = [(name, value if name == key else existing) for name, existing in pairs]
    if not any(name == key for name, _ in pairs):
        replaced.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(replaced), parts.fragment))


# Names worth spending budget on first: they carry the highest-signal probes.
INTERESTING = re.compile(
    r"(?i)^(redirect|redirect_?uri|redirect_?url|return|return_?url|next|url|uri|target|dest|"
    r"destination|continue|goto|callback|file|filename|path|filepath|dir|folder|doc|document|"
    r"template|page|view|include|load|read|download|attachment|resource|q|query|search|filter|"
    r"name|sort|order|order_?by|where|id)$")


def _documented_value(field: str, documented: list | None):
    """The example or default the contract gives for a query parameter."""
    for entry in documented or []:
        if isinstance(entry, dict) and entry.get("name") == field:
            for key in ("example", "default"):
                if entry.get(key) is not None:
                    return str(entry[key])
            return "1" if entry.get("type") in ("integer", "number") else "namazu"
    return None


def _seed_value(baseline: Exchange, field: str, documented: list | None):
    """A plausible value for `field`: whatever the request carried, else the contract's."""
    present = dict(parse_qsl(urlsplit(baseline.url).query, keep_blank_values=True))
    return present.get(field) or _documented_value(field, documented)


def _names_of(documented: list | None) -> list[str]:
    return [entry["name"] for entry in (documented or [])
            if isinstance(entry, dict) and entry.get("name")]


def _query_fields(url: str, documented: list | None = None, limit: int = MAX_FIELDS) -> list[str]:
    """Query parameters to probe: those in the request, plus documented optional ones.

    An optional parameter the generated request omitted is exactly where a
    redirect or file argument tends to live, so the audit has to add it rather
    than only testing what the baseline happened to send.
    """
    present, out = [], []
    for key, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key not in present:
            present.append(key)
    candidates = present + [name for name in _names_of(documented) if name not in present]
    # Rank by signal: named-for-a-sink first, then parameters the request already carried.
    candidates.sort(key=lambda name: (0 if INTERESTING.match(name) else 1,
                                      0 if name in present else 1))
    for name in candidates:
        if name not in out:
            out.append(name)
    return out[:limit]



def probe(executor: Executor, *, baseline: Exchange, endpoint: str, base_headers: dict,
          documented_query: list | None = None, documented_header: list | None = None,
          max_fields: int = MAX_FIELDS) -> list:
    """Run read-only input probes over the request's query fields."""
    findings: list = []
    if baseline.method not in ("GET", "HEAD") or not baseline.ok:
        return findings
    # No query parameters does not mean nothing to probe: header parameters and
    # forwarding headers are tested either way.
    fields = _query_fields(baseline.url, documented_query, max_fields)
    try:
        for field in fields:
            if not executor.affordable(4):
                break
            findings += _sql_error(executor, baseline, endpoint, field, base_headers)
            findings += _template_injection(executor, baseline, endpoint, field, base_headers)
            findings += _reflection(executor, baseline, endpoint, field, base_headers)
            findings += _open_redirect(executor, baseline, endpoint, field, base_headers)
            findings += _traversal(executor, baseline, endpoint, field, base_headers)
            findings += _nosql(executor, baseline, endpoint, field, base_headers)
            findings += _ldap_error(executor, baseline, endpoint, field, base_headers)
            findings += _sql_boolean(executor, baseline, endpoint, field, base_headers, documented_query)
            findings += _ssrf(executor, baseline, endpoint, field, base_headers)
            findings += _crlf(executor, baseline, endpoint, field, base_headers)
            findings += _parameter_pollution(executor, baseline, endpoint, field, base_headers, documented_query)
        findings += header_reflection(executor, baseline=baseline, endpoint=endpoint,
                                      base_headers=base_headers)
        findings += _header_parameters(executor, baseline, endpoint, base_headers, documented_header)
    except BudgetExhausted:
        pass
    return findings


def _send(executor, baseline, field, value, label, base_headers) -> Exchange:
    return executor.send(baseline.method, _replace_query(baseline.url, field, value),
                         label=label, headers=base_headers, identity="identity A")


def _sql_error(executor, baseline, endpoint, field, base_headers) -> list:
    if SQL_ERRORS.search(baseline.body or ""):
        return []  # Already erroring without us; nothing we send would be attributable.
    if not executor.affordable(2):
        return []
    broken = _send(executor, baseline, field, "'", f"{field}=' (unbalanced quote)", base_headers)
    if not broken.ok or not SQL_ERRORS.search(broken.body or ""):
        return []
    # A balanced pair must NOT error; otherwise the field rejects quotes generally.
    balanced = _send(executor, baseline, field, "''", f"{field}='' (balanced control)", base_headers)
    if balanced.ok and SQL_ERRORS.search(balanced.body or ""):
        return []
    match = SQL_ERRORS.search(broken.body)
    return [finding(
        "input.sql-error", "Unbalanced quote produces a database error",
        "high", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Sent a single unbalanced quote, then a balanced pair as a control. The finding "
                "requires a database error on the first and none on the second."),
        detail=(f"Setting “{field}” to a single quote returned a database engine error, while the balanced "
                "control value did not. The parameter reaches a query that is assembled as a string rather "
                "than parameterised."),
        impact="Indicates the field is concatenated into SQL. Confirm manually before claiming data access.",
        remediation="Use parameterised queries or a prepared statement for this input, and return a generic "
                    "error to the client.",
        evidence={"parameter": field, "payload": "'", "control": "''",
                  "error_excerpt": broken.body[max(0, match.start() - 60):match.end() + 120],
                  "payload_status": broken.status, "control_status": balanced.status},
        exchanges=[baseline, broken, balanced],
    )]


def _nosql(executor, baseline, endpoint, field, base_headers) -> list:
    if NOSQL_ERRORS.search(baseline.body or "") or not executor.affordable(2):
        return []
    operator = _send(executor, baseline, field, "[$ne]", f"{field}[$ne] operator", base_headers)
    if not operator.ok or not NOSQL_ERRORS.search(operator.body or ""):
        return []
    control = _send(executor, baseline, field, "[xne]", f"{field}[xne] control", base_headers)
    if control.ok and NOSQL_ERRORS.search(control.body or ""):
        return []
    match = NOSQL_ERRORS.search(operator.body)
    return [finding(
        "input.nosql-operator", "Document-database operator is interpreted in a parameter",
        "high", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Sent a MongoDB-style operator, then a structurally identical inert key as a control. "
                "The finding requires a driver error on the first and none on the second."),
        detail=(f"A MongoDB-style operator in “{field}” produced a driver error that the inert control value "
                "did not. The parameter is passed into a query document without sanitisation."),
        impact="Operator injection can bypass filters and authentication predicates.",
        remediation="Cast query parameters to their expected scalar type and reject keys beginning with $.",
        evidence={"parameter": field, "payload": "[$ne]", "control": "[xne]",
                  "error_excerpt": operator.body[max(0, match.start() - 60):match.end() + 120]},
        exchanges=[baseline, operator, control],
    )]


def _template_injection(executor, baseline, endpoint, field, base_headers) -> list:
    """Two different sums must both evaluate; one match could be a coincidence.

    Four delimiter families are tried, because the engine decides the syntax:
    ``{{ }}`` for Jinja, Twig and Nunjucks, ``${ }`` for Freemarker, JSP EL and
    Thymeleaf, ``#{ }`` for Ruby and JSF, and ``<%= %>`` for ERB and ASP.
    """
    # EXPR is substituted rather than %-formatted: one of the delimiter families
    # is itself made of % characters.
    families = (
        ("{{EXPR}}", "Jinja, Twig, Nunjucks"),
        ("${EXPR}", "Freemarker, JSP EL, Thymeleaf"),
        ("#{EXPR}", "Ruby, JSF"),
        ("<%= EXPR %>", "ERB, ASP"),
    )
    for template, engines in families:
        if not executor.affordable(2):
            break
        first_payload = template.replace("EXPR", "7*31")
        first = _send(executor, baseline, field, first_payload,
                      f"{field}={first_payload}", base_headers)
        if not first.ok or "217" not in (first.body or "") or "7*31" in (first.body or ""):
            continue
        second_payload = template.replace("EXPR", "9*41")
        second = _send(executor, baseline, field, second_payload,
                       f"{field}={second_payload}", base_headers)
        if not second.ok or "369" not in (second.body or ""):
            continue
        return [finding(
            "input.template-injection", "Parameter is evaluated by a template engine",
            "critical", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            parameter=field,
            method=(f"Sent {first_payload} and {second_payload} in turn, requiring 217 and 369 in the "
                    "responses with the expressions themselves absent. Two independent products rule "
                    "out a coincidental match."),
            detail=(f"The parameter set to {first_payload} returned 217, and {second_payload} returned "
                    "369, with the expression absent from the response. These delimiters are the ones "
                    f"used by {engines}."),
            impact="Server-side template injection commonly escalates to remote code execution.",
            remediation=("Never render user input as a template. Pass it as data to a template compiled "
                         "from a trusted source."),
            highlights=[
                mark(first_payload, "attacker", "The expression Namazu sent."),
                mark("217", "proof", "The product the server returned, so it evaluated the expression."),
            ],
            evidence={"parameter": field, "engine_family": engines,
                      "probe_1": f"{first_payload} gave 217", "probe_2": f"{second_payload} gave 369"},
            exchanges=[baseline, first, second],
        )]
    return []


def _reflection(executor, baseline, endpoint, field, base_headers) -> list:
    """Unencoded reflection into an HTML response body."""
    if not executor.affordable(1):
        return []
    nonce = _nonce()
    payload = f'{nonce}"><svg/onload=1>'
    probe_exchange = _send(executor, baseline, field, payload, f"{field}= HTML canary", base_headers)
    if not probe_exchange.ok or "html" not in probe_exchange.content_type:
        return []
    body = probe_exchange.body or ""
    if f'{nonce}"><svg/onload=1>' not in body:
        return []
    return [finding(
        "input.html-reflection", "Parameter is reflected into HTML without encoding",
        "medium", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Sent a random canary wrapped in markup and checked whether it came back in an HTML "
                "response with its angle brackets and quote still intact."),
        detail=(f"“{field}” was echoed into an HTML response with its angle brackets and quote intact "
                f"(canary {nonce}). The response Content-Type is {probe_exchange.content_type}."),
        impact="A browser rendering this response would execute attacker-supplied markup.",
        remediation="Context-encode output, and return application/json with nosniff for API responses.",
        evidence={"parameter": field, "canary": nonce, "content_type": probe_exchange.content_type,
                  "excerpt": body[max(0, body.find(nonce) - 80):body.find(nonce) + 160]},
        exchanges=[baseline, probe_exchange],
    )]


def _open_redirect(executor, baseline, endpoint, field, base_headers) -> list:
    if not re.match(r"(?i)^(redirect|redirect_?uri|redirect_?url|return|return_?url|next|url|target|dest|"
                    r"destination|continue|goto|callback)$", field):
        return []
    if not executor.affordable(1):
        return []
    target = f"https://{REDIRECT_HOST}/namazu"
    probe_exchange = _send(executor, baseline, field, target, f"{field}=external URL", base_headers)
    if not probe_exchange.ok or probe_exchange.status not in (301, 302, 303, 307, 308):
        return []
    location = probe_exchange.header("location")
    if REDIRECT_HOST not in location:
        return []
    return [finding(
        "input.open-redirect", "Parameter controls the redirect destination",
        "medium", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Set the parameter to a URL on a reserved domain and read the Location header without "
                "following the redirect."),
        detail=(f"Setting “{field}” to {target} returned HTTP {probe_exchange.status} with "
                f"Location: {location}. The server redirects to an arbitrary external host."),
        impact="Used to lend a trusted domain to phishing, and to steal OAuth codes and tokens when the "
               "parameter feeds an authorization redirect.",
        remediation="Redirect only to a server-side allow-list of paths or origins; never to a raw "
                    "client-supplied URL.",
        evidence={"parameter": field, "sent": target, "location": location, "status": probe_exchange.status},
        exchanges=[baseline, probe_exchange],
    )]


def _traversal(executor, baseline, endpoint, field, base_headers) -> list:
    if not re.match(r"(?i)^(file|filename|path|filepath|dir|folder|doc|document|template|page|view|"
                    r"include|load|read|download|attachment|name|resource)$", field):
        return []
    if not executor.affordable(1):
        return []
    payload = "../../../../etc/passwd"
    probe_exchange = _send(executor, baseline, field, payload, f"{field}= traversal canary", base_headers)
    if not probe_exchange.ok or not TRAVERSAL_HITS.search(probe_exchange.body or ""):
        return []
    return [finding(
        "input.path-traversal", "Parameter reads a file outside the intended directory",
        "critical", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Sent a relative path escaping the expected directory and matched the response "
                "against a known system-file signature."),
        detail=(f"“{field}” set to {payload} returned content matching a system file. The value reaches a "
                "file read without being confined to a base directory."),
        impact="Arbitrary file read: configuration, credentials and keys on the host are exposed.",
        remediation="Resolve the path and verify it stays within an allow-listed base directory; prefer "
                    "mapping identifiers to filenames server-side.",
        evidence={"parameter": field, "payload": payload, "excerpt": (probe_exchange.body or "")[:300]},
        exchanges=[baseline, probe_exchange],
    )]


# ── write probes (opt-in) ────────────────────────────────────────────────────

def _json_body(built: dict):
    body = built.get("body")
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, str):
        try:
            return json.loads(body)
        except ValueError:
            return None
    return None


def mass_assignment(executor: Executor, *, built: dict, endpoint: str, base_headers: dict,
                    properties: list[str], read_back_url: str | None = None) -> list:
    """Send a valid body with a privileged property added, then read the object back.

    This writes to the target, so the engine only calls it when write probes are
    enabled. Without a read-back the result stays `possible`: an accepted request
    does not prove the field was stored.
    """
    payload = _json_body(built)
    if not isinstance(payload, dict) or not properties:
        return []
    if "json" not in str(built.get("content_type") or "application/json"):
        return []
    if not executor.affordable(2):
        return []

    nonce = _nonce()
    injected = dict(payload)
    chosen: dict = {}
    for name in properties[:3]:
        leaf = name.split(".")[-1]
        value = True if re.match(r"(?i)^(is_|has_)|^(admin|verified|active|enabled|approved)$", leaf) else "admin"
        injected[leaf] = value
        chosen[leaf] = value
    injected.setdefault("namazu_probe_marker", nonce)

    written = executor.send(
        built["method"], built["url"], label=f"body with {', '.join(chosen)} added",
        headers={**base_headers, "Content-Type": built.get("content_type") or "application/json"},
        body=json.dumps(injected), identity="identity A", mutating=True,
    )
    if not written.ok or written.status >= 400:
        return []

    echoed = {name: value for name, value in chosen.items()
              if re.search(rf'"{re.escape(name)}"\s*:\s*{re.escape(json.dumps(value))}', written.body or "")}

    confirmed = {}
    exchanges = [written]
    if read_back_url and executor.affordable(1):
        read_back = executor.send("GET", read_back_url, label="read the object back",
                                  headers=base_headers, identity="identity A")
        exchanges.append(read_back)
        if read_back.ok and read_back.status < 300:
            confirmed = {name: value for name, value in chosen.items()
                         if re.search(rf'"{re.escape(name)}"\s*:\s*{re.escape(json.dumps(value))}', read_back.body or "")}

    if confirmed:
        return [finding(
            "input.mass-assignment-confirmed", "Privileged property supplied by the client was stored",
            "critical", "confirmed", owasp="API3:2023 Broken Object Property Level Authorization",
            endpoint=endpoint, parameter=", ".join(confirmed), mutating=True,
            method=("Added privileged properties to an otherwise valid request body, then read the object "
                    "back in a separate request and confirmed the supplied values had been stored."),
            detail=(f"The request body was accepted with {', '.join(f'{k}={v!r}' for k, v in confirmed.items())} "
                    "added, and reading the object back returned the same value. The handler binds "
                    "client-supplied properties straight onto the stored model."),
            impact="A caller can grant themselves roles, flags or balances the server should control.",
            remediation="Bind an explicit allow-list of client-writable fields and ignore everything else.",
            evidence={"properties": confirmed, "write_status": written.status, "verified_by_read_back": True},
            exchanges=exchanges,
        )]
    if echoed:
        return [finding(
            "input.mass-assignment-echoed", "Privileged property was accepted and echoed",
            "high", "probable", owasp="API3:2023 Broken Object Property Level Authorization",
            endpoint=endpoint, parameter=", ".join(echoed), mutating=True,
            method=("Added privileged properties to an otherwise valid request body and found the "
                    "supplied values in the response. The object was not read back, so storage is not "
                    "proven."),
            detail=(f"The request was accepted with {', '.join(echoed)} added and the response echoed the "
                    "supplied value. The object was not read back, so persistence is not proven."),
            impact="Suggests the handler accepts client-controlled privileged fields.",
            remediation="Bind an explicit allow-list of client-writable fields and ignore everything else.",
            evidence={"properties": echoed, "write_status": written.status, "verified_by_read_back": False},
            exchanges=exchanges,
        )]
    return [finding(
        "input.unknown-property-accepted", "Unknown properties are accepted without rejection",
        "low", "possible", owasp="API3:2023 Broken Object Property Level Authorization",
        endpoint=endpoint, mutating=True,
        method=("Added properties the schema does not declare, including a unique marker, and the "
                "request was accepted rather than rejected."),
        detail=(f"A body containing {', '.join(chosen)} and an unknown marker property was accepted with "
                f"HTTP {written.status}. The schema is not enforced strictly, though no privileged value "
                "was observed taking effect."),
        impact="Lenient deserialisation is the precondition for mass assignment.",
        remediation="Reject unknown properties (additionalProperties: false) and validate against the schema.",
        evidence={"properties": list(chosen), "marker": nonce, "status": written.status},
        exchanges=[written],
    )]


def write_authorization(executor: Executor, *, built: dict, endpoint: str, base_headers: dict,
                        identity_b: dict) -> list:
    """Does the second identity get to perform a write it should not own?"""
    if not identity_b or not executor.affordable(1):
        return []
    headers = {name: value for name, value in base_headers.items()
               if name.lower() not in ("authorization", "cookie", "x-api-key", "api-key")}
    headers.update(identity_b)
    if built.get("content_type"):
        headers["Content-Type"] = built["content_type"]
    payload = built.get("body")
    body = json.dumps(payload) if isinstance(payload, (dict, list)) else payload
    attempt = executor.send(built["method"], built["url"], label="write attempted as the second identity",
                            headers=headers, body=body, identity="identity B", mutating=True)
    if not attempt.ok or attempt.status >= 400:
        return []
    return [finding(
        "authz.write-bfla", "Second identity completed a write on another identity's resource",
        "critical", "confirmed", owasp="API5:2023 Broken Function Level Authorization",
        endpoint=endpoint, mutating=True,
        method=("Repeated the write with the second identity's credentials against a resource "
                "addressed for the first identity, and checked whether it succeeded."),
        detail=(f"{built['method']} {endpoint} succeeded with HTTP {attempt.status} using the second "
                "identity's credentials against a resource addressed for the first identity."),
        impact="A user can modify or destroy data belonging to another account.",
        remediation="Check ownership and role on every write, scoping the target to the authenticated subject.",
        evidence={"status": attempt.status, "method": built["method"]},
        exchanges=[attempt],
    )]


# ── additional read-only probes ──────────────────────────────────────────────

LDAP_ERRORS = re.compile(
    r"(?i)(javax\.naming\.|LDAPException|com\.sun\.jndi|Invalid DN syntax|"
    r"LDAP: error code \d+|Bad search filter|supplied argument is not a valid ldap)"
)
FETCH_ERRORS = re.compile(
    r"(?i)(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|getaddrinfo|Name or service not known|"
    r"Connection refused|connect ECONNREFUSED|dial tcp|no such host|"
    r"Temporary failure in name resolution|UnknownHostException|NameResolutionError|"
    r"Failed to establish a new connection|certificate verify failed|Max retries exceeded)"
)
SSRF_NAMES = re.compile(
    r"(?i)^(url|uri|href|link|callback|callback_?url|webhook|webhook_?url|endpoint|host|"
    r"proxy|source|src|image_?url|avatar_?url|document_?url|feed|fetch|load|import|remote)$"
)
# A host that resolves nowhere, and a port on the loopback interface that nothing serves.
UNRESOLVABLE = "http://namazu-probe-does-not-resolve.invalid/probe"
CLOSED_PORT = "http://127.0.0.1:9/probe"


def _ldap_error(executor, baseline, endpoint, field, base_headers) -> list:
    if LDAP_ERRORS.search(baseline.body or "") or not executor.affordable(2):
        return []
    broken = _send(executor, baseline, field, "*)(|(objectClass=*", f"{field}= unbalanced LDAP filter",
                   base_headers)
    if not broken.ok or not LDAP_ERRORS.search(broken.body or ""):
        return []
    control = _send(executor, baseline, field, "namazuprobe", f"{field}= inert control", base_headers)
    if control.ok and LDAP_ERRORS.search(control.body or ""):
        return []
    match = LDAP_ERRORS.search(broken.body)
    return [finding(
        "input.ldap-error", "Directory query error from an unbalanced filter",
        "high", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Sent an unbalanced LDAP filter fragment, then an inert alphanumeric control. The "
                "finding requires a directory error on the first and none on the second."),
        detail=(f"“{field}” set to an unbalanced LDAP filter produced a directory error that the inert "
                "control value did not. The parameter reaches a filter built by string concatenation."),
        impact=("Filter injection lets a caller widen a search to records they should not see, and in "
                "authentication filters it can turn into a login bypass."),
        remediation=("Escape the input per RFC 4515 before placing it in a filter, or bind parameters "
                     "through your directory library instead of concatenating."),
        evidence={"parameter": field, "payload": "*)(|(objectClass=*", "control": "namazuprobe",
                  "error_excerpt": broken.body[max(0, match.start() - 60):match.end() + 120]},
        exchanges=[baseline, broken, control],
    )]


def _sql_boolean(executor, baseline, endpoint, field, base_headers, documented=None) -> list:
    """A true and a false predicate must produce different responses to count.

    The comparison is against this parameter's own single-value response rather
    than the operation baseline, so the probe works whether or not the generated
    request happened to carry the parameter.
    """
    original = _seed_value(baseline, field, documented)
    if not original or not str(original).isdigit() or not executor.affordable(4):
        return []
    local = _send(executor, baseline, field, original, f"{field}={original} (local baseline)", base_headers)
    if not local.ok or local.status >= 400:
        return []
    true_probe = _send(executor, baseline, field, f"{original} AND 1=1",
                       f"{field}={original} AND 1=1", base_headers)
    if not true_probe.ok or true_probe.status >= 400:
        return []
    if similarity(true_probe.body, local.body) < 0.95:
        return []  # The true predicate already changed the page; not a clean oracle.
    false_probe = _send(executor, baseline, field, f"{original} AND 1=2",
                        f"{field}={original} AND 1=2", base_headers)
    if not false_probe.ok:
        return []
    if similarity(false_probe.body, true_probe.body) >= 0.95:
        return []  # No difference: the value is not reaching a predicate.
    # A second, different true pair, so one coincidence cannot carry the finding.
    confirm = _send(executor, baseline, field, f"{original} AND 7=7",
                    f"{field}={original} AND 7=7", base_headers)
    if not confirm.ok or similarity(confirm.body, true_probe.body) < 0.95:
        return []
    return [finding(
        "input.sql-boolean", "Parameter is evaluated as a SQL predicate",
        "critical", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=("Sent the parameter four times and compared the bodies: the plain value, then "
                "`AND 1=1`, `AND 1=2` and `AND 7=7` appended to it. Both true predicates matched the "
                "plain response and the false one differed, which only happens if the database "
                "evaluated the appended condition."),
        highlights=[mark("concatenated into a SQL statement", "weak",
                         "The value is not parameterised; the database evaluates what was appended.")],
        detail=(f"“{field}” with a true predicate returned the same content as the plain value, and with "
                "a false predicate returned different content. The value is concatenated into a SQL "
                "statement and the appended condition is being evaluated."),
        impact=("Boolean-based injection extracts data one condition at a time, and the same entry point "
                "normally allows reading arbitrary tables. Treat it as full database read access."),
        remediation=("Use a parameterised query for this input. For a numeric id, casting to an integer "
                     "at the request boundary removes the injection point entirely."),
        evidence={"parameter": field, "seed_value": original,
                  "true_payload": f"{original} AND 1=1", "false_payload": f"{original} AND 1=2",
                  "confirm_payload": f"{original} AND 7=7",
                  "true_vs_plain": similarity(true_probe.body, local.body),
                  "false_vs_true": similarity(false_probe.body, true_probe.body),
                  "confirm_vs_true": similarity(confirm.body, true_probe.body)},
        exchanges=[local, true_probe, false_probe, confirm],
    )]


def _ssrf(executor, baseline, endpoint, field, base_headers) -> list:
    """Did the server actually try to fetch what we handed it?"""
    if not SSRF_NAMES.match(field) or not executor.affordable(2):
        return []
    if FETCH_ERRORS.search(baseline.body or ""):
        return []
    unresolvable = _send(executor, baseline, field, UNRESOLVABLE,
                         f"{field}= host that cannot resolve", base_headers)
    if not unresolvable.ok:
        return []
    hit = FETCH_ERRORS.search(unresolvable.body or "")
    if not hit:
        return []
    closed = _send(executor, baseline, field, CLOSED_PORT,
                   f"{field}= closed port on the server's own loopback", base_headers)
    reached_loopback = closed.ok and FETCH_ERRORS.search(closed.body or "")
    return [finding(
        "input.ssrf-confirmed", "Server fetches a URL supplied in a parameter",
        "high", "confirmed", owasp="API7:2023 Server Side Request Forgery", endpoint=endpoint,
        parameter=field,
        method=("Supplied a hostname that cannot resolve and read the response for a network error "
                "produced by the server's own HTTP client"
                + (", then supplied a closed port on the server's loopback interface and saw a "
                   "connection error from there too." if reached_loopback else ".")),
        highlights=[mark("proves the parameter controls a server-side fetch", "proof",
                     "Only the server attempting the request can produce this network error.")],
        detail=(f"Setting “{field}” to {UNRESOLVABLE} made the application return a network-level error "
                f"(“{hit.group(0)}”). The error can only come from the server attempting the request, "
                "which proves the parameter controls a server-side fetch."
                + (f" A follow-up pointing at {CLOSED_PORT} also produced a connection error, so the "
                   "fetch reaches the server's own loopback interface." if reached_loopback else "")),
        impact=("The server can be directed at hosts only it can reach: cloud instance metadata, internal "
                "admin panels, databases and other services that trust the API's network position. Namazu "
                "stops at proving the fetch happens and does not read any internal resource."),
        remediation=("Resolve the hostname first and reject private, loopback, link-local and multicast "
                     "addresses, re-checking after resolution to defeat DNS rebinding. Allow-list the "
                     "destinations the feature genuinely needs, disable redirect following, and make the "
                     "fetch from a network segment with no access to internal services."),
        evidence={"parameter": field, "unresolvable_payload": UNRESOLVABLE,
                  "error_signature": hit.group(0), "status": unresolvable.status,
                  "loopback_payload": CLOSED_PORT if reached_loopback else None,
                  "reached_loopback": bool(reached_loopback)},
        exchanges=[baseline, unresolvable] + ([closed] if reached_loopback else []),
    )]


def _crlf(executor, baseline, endpoint, field, base_headers) -> list:
    """A header the response only has if our newline was written into it."""
    if not executor.affordable(2):
        return []
    nonce = _nonce()
    header_name = f"X-Namazu-{nonce}"
    control = _send(executor, baseline, field, f"namazu{nonce}", f"{field}= control without newlines",
                    base_headers)
    if not control.ok or control.header(header_name):
        return []
    payload = f"namazu{nonce}\r\n{header_name}: injected"
    probe = _send(executor, baseline, field, payload, f"{field}= value containing CRLF", base_headers)
    if not probe.ok or probe.header(header_name).strip() != "injected":
        return []
    return [finding(
        "input.crlf-injection", "Parameter injects a header into the response",
        "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=(f"Sent a control value with no newlines and confirmed the response carried no "
                f"{header_name} header, then sent the same value followed by CRLF and a unique header "
                "name, and found that exact header in the response."),
        detail=(f"“{field}” carrying a carriage return and line feed caused the response to include "
                f"{header_name}: injected, a header the control request did not produce. The value is "
                "written into the response head without stripping line terminators."),
        impact=("An attacker controls response headers, which allows setting cookies, poisoning a shared "
                "cache with a crafted response, and in some stacks splitting the response entirely."),
        remediation=("Strip or reject CR and LF in any value that reaches a response header. Most modern "
                     "HTTP libraries do this already, so re-enable the check rather than filtering by hand."),
        evidence={"parameter": field, "injected_header": header_name,
                  "control_had_header": False, "probe_header_value": probe.header(header_name)},
        exchanges=[control, probe],
    )]


def _parameter_pollution(executor, baseline, endpoint, field, base_headers, documented=None) -> list:
    """Two values for one parameter: does a filter see one and the handler the other?"""
    seed = _seed_value(baseline, field, documented)
    if not seed or not executor.affordable(2):
        return []
    nonce = _nonce()
    single = _send(executor, baseline, field, seed, f"{field}={seed} (single value)", base_headers)
    if not single.ok or single.status >= 400:
        return []
    parts = urlsplit(_replace_query(baseline.url, field, seed))
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    polluted = urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(pairs + [(field, nonce)]), parts.fragment))
    probe = executor.send(baseline.method, polluted, label=f"{field} supplied twice",
                          headers=base_headers, identity="identity A")
    if not probe.ok or probe.status >= 400:
        return []
    if nonce not in (probe.body or ""):
        return []
    if similarity(probe.body, single.body) >= 0.95:
        return []
    return [finding(
        "input.parameter-pollution", "Duplicate parameter values are both processed",
        "low", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter=field,
        method=(f"Sent “{field}” once, then twice with a second unique value, and compared the two "
                "responses. The finding needs the response to change and to contain the later value."),
        detail=(f"Supplying “{field}” twice returned a response that differs from the single-value "
                f"request and contains the second value ({nonce}). The later occurrence is the one "
                "this layer acts on."),
        impact=("Where a gateway, WAF or authorization filter reads the first occurrence and the handler "
                "reads the last, a caller can show one value to the control and a different one to the "
                "code behind it."),
        remediation=("Decide one behaviour for repeated parameters, apply it identically at every layer, "
                     "and reject duplicates where a single value is expected."),
        evidence={"parameter": field, "first_value": seed, "second_value": nonce,
                  "body_similarity": similarity(probe.body, single.body)},
        exchanges=[single, probe],
    )]


def header_reflection(executor: Executor, *, baseline: Exchange, endpoint: str,
                      base_headers: dict) -> list:
    """Does the application build URLs from a client-supplied host header?"""
    if baseline.method not in ("GET", "HEAD") or not executor.affordable(1):
        return []
    probe_host = "namazu-probe.invalid"
    probe = executor.send(
        baseline.method, baseline.url, label=f"X-Forwarded-Host: {probe_host}",
        headers={**base_headers, "X-Forwarded-Host": probe_host, "X-Forwarded-Proto": "http"},
        identity="identity A",
    )
    if not probe.ok:
        return []
    location = probe.header("location")
    in_header = probe_host in location
    in_body = probe_host in (probe.body or "")[:8000]
    if not in_header and not in_body:
        return []
    return [finding(
        "input.header-reflection", "Client-supplied forwarding header shapes the response",
        "medium", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        parameter="X-Forwarded-Host",
        method=(f"Repeated the baseline request with X-Forwarded-Host: {probe_host} and looked for that "
                "host in the Location header and the response body."),
        detail=(f"With X-Forwarded-Host set to {probe_host}, the value appeared in "
                + ("the Location header" if in_header else "the response body")
                + ". The application trusts a header any client can set when it builds absolute URLs."),
        impact=("Absolute links the application generates, such as password reset mails, OAuth redirects and asset "
                "URLs, can be pointed at an attacker's host. If a shared cache keys on the path but not "
                "on this header, one poisoned entry is served to every subsequent visitor."),
        remediation=("Build absolute URLs from a configured canonical hostname. If a proxy must pass the "
                     "original host, allow-list the values at the edge and strip the header from anything "
                     "arriving from outside."),
        evidence={"header": "X-Forwarded-Host", "value": probe_host,
                  "reflected_in_location": in_header, "reflected_in_body": in_body,
                  "location": location or None},
        exchanges=[baseline, probe],
    )]


def _header_parameters(executor, baseline, endpoint, base_headers, documented) -> list:
    """Documented header parameters reach the same sinks as query parameters.

    They are easy to overlook because they never appear in a URL, so a value
    that is reflected or concatenated there often survives longer than the
    equivalent in a query string.
    """
    out: list = []
    for entry in (documented or [])[:2]:
        name = entry.get("name") if isinstance(entry, dict) else None
        if not name or not executor.affordable(2):
            continue
        nonce = _nonce()
        canary = nonce + '"><svg/onload=1>'
        probe_exchange = executor.send(
            baseline.method, baseline.url, label=f"header {name}: HTML canary",
            headers={**base_headers, name: canary}, identity="identity A",
        )
        if (probe_exchange.ok and "html" in probe_exchange.content_type
                and canary in (probe_exchange.body or "")):
            out.append(finding(
                "input.html-reflection", "Header parameter is reflected into HTML without encoding",
                "medium", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
                parameter=name,
                method=(f"Sent the documented header parameter {name} carrying a random canary wrapped "
                        "in markup, and found it echoed into an HTML response with its angle brackets "
                        "and quote intact."),
                detail=(f"The {name} request header was echoed into a {probe_exchange.content_type} "
                        f"response unencoded (canary {nonce})."),
                impact="A browser rendering this response would execute attacker-supplied markup.",
                remediation=("Context-encode anything written into a response body, and return "
                             "application/json with nosniff for API responses."),
                highlights=[mark(nonce, "attacker", "The random canary Namazu sent in this header.")],
                evidence={"header": name, "canary": nonce,
                          "content_type": probe_exchange.content_type},
                exchanges=[baseline, probe_exchange],
            ))
            continue
        if SQL_ERRORS.search(baseline.body or ""):
            continue
        error_probe = executor.send(
            baseline.method, baseline.url, label=f"header {name}: unbalanced quote",
            headers={**base_headers, name: "'"}, identity="identity A",
        )
        if error_probe.ok and SQL_ERRORS.search(error_probe.body or ""):
            match = SQL_ERRORS.search(error_probe.body)
            out.append(finding(
                "input.sql-error", "Header parameter produces a database error",
                "high", "probable", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
                parameter=name,
                method=(f"Sent a single quote as the value of the documented header parameter {name} "
                        "and matched the response against database engine error signatures. The "
                        "baseline response carried no such error."),
                detail=(f"The {name} header carrying a single quote returned a database error that the "
                        "baseline did not."),
                impact="Indicates the header value is concatenated into a query rather than parameterised.",
                remediation="Use parameterised queries for values taken from headers as well as the URL.",
                evidence={"header": name, "payload": "'",
                          "error_excerpt": error_probe.body[max(0, match.start() - 60):match.end() + 120]},
                exchanges=[baseline, error_probe],
            ))
    return out
