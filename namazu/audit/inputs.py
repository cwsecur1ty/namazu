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

import copy
import json
import re
import secrets
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .identity import same_principal, strip_credentials, subject
from .model import Exchange, finding, mark, similarity
from .transport import BudgetExhausted, Executor

MAX_FIELDS = 4
# Header and cookie parameters are capped separately: a contract that declares
# a dozen of them is usually declaring plumbing, not inputs worth probing.
NAMED_FIELDS = 2
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


# A sleep payload holds a database thread for as long as it sleeps. That is
# the one thing in the read-only battery that costs the target something, so
# the numbers stay small and the whole pass is off unless a profile asks.
SLEEP_SECONDS = 2
SCALE_SECONDS = 4
# What counts as a delay. A 2s sleep has to stand clear of jitter, and asking
# for the whole 2s would lose a hit behind one slow hop, so the bar is most of
# it. The scaling re-test is what removes the remaining doubt.
DELAY_MARGIN_MS = 1300
# Points probed by timing, per operation. Each costs seconds of held thread,
# so this is much lower than the battery's own cap.
TIME_BASED_POINTS = 2
# Breaking out of a quoted string and commenting out the rest. The comment
# needs its trailing space for MySQL.
SLEEP_PAYLOADS = (
    ("MySQL or MariaDB", "{seed}' AND SLEEP({seconds})-- "),
    ("PostgreSQL", "{seed}' AND 1=(SELECT 1 FROM PG_SLEEP({seconds}))-- "),
    ("Microsoft SQL Server", "{seed}'; WAITFOR DELAY '0:0:{seconds:02d}'-- "),
)


def _nonce() -> str:
    return "k" + secrets.token_hex(4)


def _replace_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = [(name, value if name == key else existing) for name, existing in pairs]
    if not any(name == key for name, _ in pairs):
        replaced.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(replaced), parts.fragment))


def _header_value(headers: dict, name: str) -> str:
    """A request header by name, case-insensitively."""
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return str(value)
    return ""


def _without_header(headers: dict, name: str) -> dict:
    return {key: value for key, value in (headers or {}).items() if key.lower() != name.lower()}


def _parse_cookies(header: str) -> list:
    pairs = []
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        pairs.append((unquote(name.strip()), unquote(value.strip())))
    return pairs


def _set_cookie(header: str, name: str, value: str) -> str:
    """The Cookie header with one cookie replaced, or added if it was absent."""
    pairs = _parse_cookies(header)
    if any(existing == name for existing, _ in pairs):
        pairs = [(existing, value if existing == name else carried)
                 for existing, carried in pairs]
    else:
        pairs.append((name, value))
    # The value goes in raw. A payload percent-encoded here would arrive at the
    # sink already decoded into something inert, and the transport rejects the
    # control characters that would otherwise break the header.
    return "; ".join(f"{existing}={carried}" for existing, carried in pairs)


class Point(str):
    """An injection point, which renders as its parameter name.

    Subclassing str so every probe that formats or compares the name keeps
    working unchanged. ``location`` is where the contract declares the value:
    ``query``, ``path``, ``header`` or ``cookie``. A cookie or header
    parameter reaches the same sinks a query parameter does and is easier to
    overlook, because it never appears in a URL, so all four locations get the
    same battery rather than a reduced one.
    """

    __slots__ = ("example", "index", "location")

    def __new__(cls, name: str, index: int | None = None, location: str | None = None,
                example=None):
        point = super().__new__(cls, name)
        point.index = index
        point.location = location or ("path" if index is not None else "query")
        point.example = None if example is None else str(example)
        return point

    @property
    def in_path(self) -> bool:
        return self.location == "path"

    @property
    def in_url(self) -> bool:
        return self.location in ("query", "path")

    def apply(self, url: str, value: str) -> str:
        """The URL with this point's value replaced. URL-borne points only."""
        if self.index is None:
            return _replace_query(url, str(self), value)
        parts = urlsplit(url)
        segments = parts.path.split("/")
        if self.index >= len(segments):
            return url
        segments[self.index] = quote(value, safe="")
        return urlunsplit((parts.scheme, parts.netloc, "/".join(segments),
                           parts.query, parts.fragment))

    def place(self, baseline: Exchange, value: str, base_headers: dict) -> dict:
        """The ``send()`` arguments for a request carrying ``value`` at this point."""
        headers = dict(base_headers or {})
        if self.location == "header":
            return {"method": baseline.method, "url": baseline.url,
                    "headers": {**_without_header(headers, str(self)), str(self): value}}
        if self.location == "cookie":
            carried = (_header_value(headers, "Cookie")
                       or _header_value(baseline.request_headers, "Cookie"))
            return {"method": baseline.method, "url": baseline.url,
                    "headers": {**_without_header(headers, "Cookie"),
                                "Cookie": _set_cookie(carried, str(self), value)}}
        return {"method": baseline.method, "url": self.apply(baseline.url, value),
                "headers": headers}

    def current(self, baseline: Exchange) -> str:
        """The value this point carries in the baseline request."""
        if self.location == "header":
            return _header_value(baseline.request_headers, str(self))
        if self.location == "cookie":
            carried = _header_value(baseline.request_headers, "Cookie")
            return dict(_parse_cookies(carried)).get(str(self), "")
        if self.index is None:
            return dict(parse_qsl(urlsplit(baseline.url).query,
                                  keep_blank_values=True)).get(str(self), "")
        segments = urlsplit(baseline.url).path.split("/")
        return unquote(segments[self.index]) if self.index < len(segments) else ""


# A request body can nest without limit and an array can repeat without limit.
# Neither is worth following: the fields that reach a sink are near the top, and
# probing the hundredth element of a list says nothing the first did not.
MAX_BODY_DEPTH = 4
MAX_BODY_ITEMS = 2
MAX_BODY_LEAVES = 60


def _render_pointer(pointer: list) -> str:
    out = ""
    for part in pointer:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out


def _get_in(document, pointer: list):
    node = document
    for part in pointer:
        node = node[part]
    return node


def _set_in(document, pointer: list, value):
    node = document
    for part in pointer[:-1]:
        node = node[part]
    node[pointer[-1]] = value
    return document


class BodyPoint(Point):
    """A scalar field inside a JSON request body.

    The battery is the same one the query parameters get, because the sinks
    are the same: an ORM filter built by concatenation does not care whether
    the value arrived in a URL or a body. The difference is cost, not kind.
    Every probe here is a state-changing request, so this point only exists
    when write probes are enabled, and the findings it produces are marked
    mutating.
    """

    __slots__ = ("pointer",)

    def __new__(cls, pointer: list, example=None):
        point = super().__new__(cls, _render_pointer(pointer), location="body",
                                example=example)
        point.pointer = list(pointer)
        return point

    def place(self, baseline: Exchange, value: str, base_headers: dict) -> dict:
        document = _parse_json(baseline.request_body)
        mutated = _set_in(copy.deepcopy(document), self.pointer, value)
        content_type = (_header_value(baseline.request_headers, "content-type")
                        or "application/json")
        return {"method": baseline.method, "url": baseline.url,
                "headers": _without_header(dict(base_headers or {}), "content-type"),
                "body": json.dumps(mutated), "content_type": content_type,
                "mutating": True}

    def current(self, baseline: Exchange) -> str:
        try:
            value = _get_in(_parse_json(baseline.request_body), self.pointer)
        except (KeyError, IndexError, TypeError):
            return ""
        return "" if value is None else str(value)


def _parse_json(raw):
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw or "null")
    except (TypeError, ValueError):
        return None


def _body_leaves(node, pointer: list, out: list, depth: int = 0) -> None:
    if len(out) >= MAX_BODY_LEAVES or depth > MAX_BODY_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _body_leaves(value, pointer + [str(key)], out, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node[:MAX_BODY_ITEMS]):
            _body_leaves(value, pointer + [index], out, depth + 1)
    elif isinstance(node, bool):
        # A boolean field rejects a string payload before it reaches anything.
        return
    elif isinstance(node, (str, int, float)):
        out.append((pointer, node))


def _body_points(baseline: Exchange, limit: int) -> list:
    """Scalar fields in the request body, highest signal first."""
    document = _parse_json(baseline.request_body)
    if not isinstance(document, (dict, list)):
        return []
    leaves: list = []
    _body_leaves(document, [], leaves)
    # Named-for-a-sink first, then strings, which reach more sinks than a
    # number does without being rejected by validation on the way.
    leaves.sort(key=lambda leaf: (0 if INTERESTING.match(str(leaf[0][-1])) else 1,
                                  0 if isinstance(leaf[1], str) else 1))
    return [BodyPoint(pointer, example=value) for pointer, value in leaves[:limit]]


# How a finding describes a point that is not an ordinary query parameter.
WHERE = {
    "path": "a path parameter",
    "header": "a documented header parameter",
    "cookie": "a documented cookie parameter",
    "body": "a field in the request body",
}


def _named_points(documented: list | None, location: str, limit: int) -> list:
    """Points for the header or cookie parameters the contract declares."""
    out = []
    for entry in (documented or []):
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        out.append(Point(entry["name"], location=location,
                         example=entry.get("example") or entry.get("default")))
        if len(out) >= limit:
            break
    return out


def _locate(findings: list, field) -> list:
    """Say where the point lives, so a bare name is not read as a query field."""
    if not isinstance(field, Point) or field.location == "query":
        return findings
    for item in findings:
        if isinstance(item.evidence, dict):
            item.evidence.setdefault("location", field.location)
        item.detail = ((item.detail or "").rstrip()
                       + f" “{field}” is {WHERE[field.location]}, not a query parameter.")
    return findings


def _path_points(baseline, path_template: str, documented_path: list | None) -> list:
    """Align the operation's path template with the URL to locate its parameters.

    A path parameter is the most common identifier position in a REST API and
    reaches the same sinks a query parameter does, so it gets the same battery.
    """
    if not path_template:
        return []
    names = {entry.get("name") for entry in (documented_path or [])
             if isinstance(entry, dict) and entry.get("name")}
    template = path_template.split("/")
    actual = urlsplit(baseline.url).path.split("/")
    points = []
    # The URL may sit under a base path, so align from the end where the
    # template and the live path agree in length.
    offset = len(actual) - len(template)
    if offset < 0:
        return []
    for index, segment in enumerate(template):
        match = re.fullmatch(r"\{(.+)\}", segment.strip())
        if not match:
            continue
        name = match.group(1)
        if names and name not in names:
            continue
        points.append(Point(name, offset + index))
    return points


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


def _seed_value(baseline: Exchange, field, documented: list | None):
    """A plausible value for this point: what the request carried, else the contract's."""
    if isinstance(field, Point):
        current = field.current(baseline)
        if current:
            return current
        if field.example:
            return field.example
        if not field.in_url:
            return None  # the documented list passed in holds query parameters
    else:
        present = dict(parse_qsl(urlsplit(baseline.url).query, keep_blank_values=True))
        if present.get(field):
            return present[field]
    return _documented_value(str(field), documented)


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
            out.append(Point(name, example=_documented_value(name, documented)))
    return out[:limit]



def battery(executor: Executor, *, baseline: Exchange, endpoint: str, field,
            base_headers: dict, documented_query: list | None = None) -> list:
    """Every read-only input probe against one point.

    The probes inside are ordered and share a point, so they run in sequence:
    several of them send a payload and then a control, and that pair has to be
    compared against the same target in the same state.
    """
    findings: list = []
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
    findings += _parameter_pollution(executor, baseline, endpoint, field, base_headers,
                                     documented_query)
    return _locate(findings, field)


def points(baseline: Exchange, *, documented_query: list | None = None,
           documented_header: list | None = None, documented_path: list | None = None,
           documented_cookie: list | None = None, path_template: str = "",
           max_fields: int = MAX_FIELDS) -> list:
    """Every injection point this operation documents, highest signal first.

    Path parameters carry identifiers and reach the same sinks as query
    parameters, so they get the same battery rather than only an id swap.
    Header and cookie parameters do too, and are capped lower because a
    contract rarely declares an interesting number of them.
    """
    fields = _path_points(baseline, path_template, documented_path)
    fields += _query_fields(baseline.url, documented_query, max_fields)
    fields = fields[:max_fields + 2]
    fields += _named_points(documented_header, "header", NAMED_FIELDS)
    fields += _named_points(documented_cookie, "cookie", NAMED_FIELDS)
    return fields


def probe(executor: Executor, *, baseline: Exchange, endpoint: str, base_headers: dict,
          documented_query: list | None = None, documented_header: list | None = None,
          documented_path: list | None = None, documented_cookie: list | None = None,
          path_template: str = "", max_fields: int = MAX_FIELDS,
          time_based: bool = False) -> list:
    """Run the read-only input probes over every documented point."""
    findings: list = []
    if baseline.method not in ("GET", "HEAD") or not baseline.ok:
        return findings
    # No query parameters does not mean nothing to probe: header and cookie
    # parameters and the forwarding headers are tested either way.
    fields = points(baseline, documented_query=documented_query,
                    documented_header=documented_header, documented_path=documented_path,
                    documented_cookie=documented_cookie, path_template=path_template,
                    max_fields=max_fields)

    def one(branch, field):
        # Points are independent of each other, so they are the unit of
        # parallelism. Each branch draws on the same request budget.
        if not branch.affordable(4):
            return []
        return battery(branch, baseline=baseline, endpoint=endpoint, field=field,
                       base_headers=base_headers, documented_query=documented_query)

    try:
        for group in executor.fan_out(fields, one):
            findings += group or []
        findings += header_reflection(executor, baseline=baseline, endpoint=endpoint,
                                      base_headers=base_headers)
        if time_based:
            findings += time_based_pass(executor, baseline=baseline, endpoint=endpoint,
                                        base_headers=base_headers, fields=fields,
                                        documented_query=documented_query,
                                        already=findings)
    except BudgetExhausted:
        pass
    return findings


def time_based_pass(executor: Executor, *, baseline: Exchange, endpoint: str,
                    base_headers: dict, fields: list, documented_query: list | None = None,
                    already: list | None = None) -> list:
    """The timing probes, serially, over at most a couple of points.

    Serially on purpose. A wall-clock measurement taken while five other
    probes share the connection pool is not a measurement, so this runs after
    the parallel battery has finished rather than inside it.
    """
    confirmed = {item.id if hasattr(item, "id") else item.get("id")
                 for item in (already or [])}
    findings: list = []
    for field in fields[:TIME_BASED_POINTS]:
        # A point already confirmed as reaching SQL needs no second proof, and
        # the sleep is the expensive way to get one.
        if {"input.sql-error", "input.sql-boolean"} & confirmed:
            break
        if not executor.affordable(len(SLEEP_PAYLOADS) + 2):
            break
        found = _sql_time_based(executor, baseline, endpoint, field, base_headers,
                                documented_query)
        findings += _locate(found, field)
    return findings


def _send(executor, baseline, field, value, label, base_headers) -> Exchange:
    """One probe request with ``value`` placed wherever this point lives."""
    if isinstance(field, Point):
        plan = field.place(baseline, value, base_headers)
    else:
        plan = {"method": baseline.method,
                "url": _replace_query(baseline.url, field, value),
                "headers": dict(base_headers or {})}
    return executor.send(plan.pop("method"), plan.pop("url"), label=label,
                         identity="identity A", **plan)


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


def body_injection(executor: Executor, *, baseline: Exchange, endpoint: str,
                   base_headers: dict, max_fields: int = 3) -> tuple:
    """Run the injection battery against the fields of a JSON request body.

    A payload that only ever travels in a query string misses every sink
    reachable only through a body, which on a modern API is most of the write
    path. The probes and their controls are the same ones the query parameters
    get; what differs is that each request here creates or modifies an object
    on the target, so this runs only under the write profile and every finding
    is marked mutating.

    Returns ``(findings, fields_probed)`` so the caller can report how much
    state it changed.
    """
    content_type = _header_value(baseline.request_headers, "content-type")
    if baseline.method not in ("POST", "PUT", "PATCH") or not baseline.ok:
        return [], []
    if "json" not in (content_type or "application/json"):
        return [], []
    fields = _body_points(baseline, max_fields)
    findings: list = []
    probed: list = []
    for field in fields:
        if not executor.affordable(4):
            break
        probed.append(str(field))
        try:
            findings += battery(executor, baseline=baseline, endpoint=endpoint, field=field,
                                base_headers=base_headers)
        except BudgetExhausted:
            break
    for item in findings:
        item.mutating = True
    return findings, probed


def write_authorization(executor: Executor, *, built: dict, endpoint: str, base_headers: dict,
                        identity_b: dict, notes: list | None = None) -> list:
    """Does the second identity get to perform a write it should not own?"""
    if not identity_b or not executor.affordable(1):
        return []
    # This probe writes, so a misconfigured pair of identities costs more here
    # than anywhere else: the write lands either way, and it would be reported
    # as one account writing another account's resource.
    reason = same_principal(base_headers, identity_b)
    if reason:
        if notes is not None:
            notes.append(f"The write was not replayed as the second identity: {reason}. Testing a "
                         "write boundary needs two different accounts.")
        return []
    headers = strip_credentials(base_headers)
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
        evidence={"status": attempt.status, "method": built["method"],
                  **{key: value for key, value in
                     (("identity_a_subject", subject(base_headers)),
                      ("identity_b_subject", subject(headers))) if value}},
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


def _sql_time_based(executor, baseline, endpoint, field, base_headers,
                    documented=None) -> list:
    """Three measurements: does it sleep, does it sleep only when asked, does it scale."""
    # A sleep longer than the request timeout cannot be measured, only timed
    # out, and a timeout proves nothing either way.
    if executor.timeout < SCALE_SECONDS + 2 or not executor.affordable(len(SLEEP_PAYLOADS) + 2):
        return []
    seed = _seed_value(baseline, field, documented)
    seed = "" if seed is None else str(seed)

    def attempt(engine, template, seconds, label):
        payload = template.format(seed=seed, seconds=seconds)
        return _send(executor, baseline, field, payload,
                     f"{field}: {label} ({engine})", base_headers)

    for engine, template in SLEEP_PAYLOADS:
        slept = attempt(engine, template, SLEEP_SECONDS,
                        f"sleep {SLEEP_SECONDS}s if the value reaches SQL")
        if not slept.ok or slept.elapsed_ms < DELAY_MARGIN_MS:
            continue
        if slept.elapsed_ms - baseline.elapsed_ms < DELAY_MARGIN_MS:
            continue  # The endpoint was already this slow.
        if not executor.affordable(2):
            return []

        # The zero-sleep control: the same payload, nothing to wait for. A
        # payload can make a query slow by making it bad, and this is what
        # tells that apart from a sleep that was executed.
        control = attempt(engine, template, 0, "the same payload with a zero-second sleep")
        if not control.ok or control.elapsed_ms >= DELAY_MARGIN_MS:
            continue

        # And the scaling re-test, against an endpoint that is simply erratic.
        scaled = attempt(engine, template, SCALE_SECONDS,
                         f"sleep {SCALE_SECONDS}s, to see the delay scale")
        if not scaled.ok or scaled.elapsed_ms < slept.elapsed_ms + DELAY_MARGIN_MS:
            continue

        return [finding(
            "input.sql-time-based", "Parameter reaches SQL, confirmed by a timed delay",
            "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
            method=(f"Sent a {engine} sleep payload and measured the response time, then sent "
                    "the identical payload with a zero-second sleep, which returned promptly, "
                    f"then the same payload again at {SCALE_SECONDS}s, which took "
                    "proportionally longer. A slow response alone proves nothing; the zero-"
                    "second control rules out a payload that is simply expensive, and the "
                    "scaling rules out an endpoint that is intermittently slow. Nothing was "
                    "read or written."),
            highlights=[
                mark("confirmed by a timed delay", "proof",
                     "The response time followed the sleep the payload asked for, and did not "
                     "when the same payload asked for none."),
                mark("reaches SQL", "weak",
                     "The value is concatenated into a statement the database executes."),
            ],
            detail=(f"A {engine} sleep payload in {field} returned after "
                    f"{int(slept.elapsed_ms)} ms against a baseline of "
                    f"{int(baseline.elapsed_ms)} ms. The same payload asking for a zero-second "
                    f"sleep returned in {int(control.elapsed_ms)} ms, and asking for "
                    f"{SCALE_SECONDS} seconds it took {int(scaled.elapsed_ms)} ms. The delay "
                    "tracks what the payload asked for, so the value is being executed as part "
                    "of a SQL statement."),
            impact=("The database executes attacker-supplied SQL. Data can be read a character "
                    "at a time through the same timing channel, with no need for the response "
                    "to differ in any other way."),
            remediation=("Use parameterised queries so the value is bound rather than "
                         "concatenated. An allow-list or escaping routine around a "
                         "concatenated statement is not equivalent."),
            limitations=(f"The payloads break out of a quoted string, so a parameter "
                         "interpolated into a numeric context may be injectable without being "
                         f"detected here. Engines without a sleep function, SQLite among them, "
                         "cannot be confirmed this way at all. Confirmation cost the target "
                         f"roughly {SLEEP_SECONDS + SCALE_SECONDS} seconds of held database "
                         "thread on this parameter."),
            evidence={"engine": engine, "baseline_ms": int(baseline.elapsed_ms),
                      "sleep_seconds": SLEEP_SECONDS, "sleep_ms": int(slept.elapsed_ms),
                      "zero_sleep_ms": int(control.elapsed_ms),
                      "scaled_seconds": SCALE_SECONDS, "scaled_ms": int(scaled.elapsed_ms)},
            exchanges=[slept, control, scaled],
        )]
    return []


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
    if isinstance(field, Point) and not field.in_url:
        # A line terminator cannot be carried in a request header or cookie
        # without malforming the request itself, which is request smuggling: a
        # different class, and an invasive one. The transport refuses it.
        return []
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
    if isinstance(field, Point) and field.location != "query":
        # Repeating a path segment changes the route, and a header or cookie
        # supplied twice is a different question from a duplicated query key.
        return []
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
