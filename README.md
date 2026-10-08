<div align="center">

# 鯰 &nbsp;Namazu

**An API security workbench for OpenAPI contracts.**

Import an OpenAPI contract, build and send requests, and audit the API against
the OWASP API Security Top 10, with every finding carrying the requests that
produced it and the command to reproduce them.

[![Tests](https://github.com/cwsecur1ty/namazu/actions/workflows/ci.yml/badge.svg)](https://github.com/cwsecur1ty/namazu/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%3A2023-orange.svg)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

</div>

---

## Why this exists

A finding is only worth having if it holds up when someone pushes back on it.
That means showing the requests behind it, saying how confident you actually
are, and admitting what it does not prove.

| | |
|---|---|
| **Evidence first** | Every finding carries the exchanges that produced it, with a redacted `curl` for bash, PowerShell and cmd. |
| **Honest confidence** | `confirmed`, `probable` or `possible`, plus a **Limitations** section saying what the finding does *not* establish. |
| **Controls, not guesses** | Injection probes ship with a decoy control; a finding fires only when the payload and the decoy behave differently. |
| **A full request log** | Every request the audit sent, in order, whether or not it produced a finding, in a three-pane history / request / response view. |
| **Nothing silent** | Budget reached, write probes refused, tool missing: it is in the report, not swallowed. |

<br>

<div align="center">
<em>How a single finding is laid out.</em>
</div>

```
┌─ ISSUE DETAIL ──────────────────────────────────────────────────────────────┐
│ The specification declares an implicit flow for security scheme "legacy",   │
│ with authorizationUrl https://id.example.com/authorize and 2 scopes.        │
│ Namazu read it statically and did not contact the authorization server.     │
└─────────────────────────────────────────────────────────────────────────────┘
┌─ ISSUE BACKGROUND ──────────────────────────────────────────────────────────┐
│   implicit      browser receives:  ACCESS TOKEN   (usable immediately)      │
│   code + PKCE   browser receives:  CODE           (useless without verifier)│
└─────────────────────────────────────────────────────────────────────────────┘
┌─ LIMITATIONS ───────────────────────────────────────────────────────────────┐
│ Identified statically. This does not establish that the grant is enabled at │
│ the authorization server, or that it is exploitable.                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Install and run

Python 3.10 or newer.

```sh
git clone https://github.com/cwsecur1ty/namazu
cd namazu
python -m venv .venv
.venv/bin/python -m pip install .       # Windows: .venv\Scripts\python -m pip install .
.venv/bin/python -m namazu
```

Then open **http://localhost:8010**.

Or use the launcher, which creates the environment on first run: double-click
`start.bat` on Windows, or `sh start.sh` on Linux and macOS. Both accept
`--port` and `--host`.

<details>
<summary>Docker</summary>

```sh
docker build -t namazu .
docker run --rm -p 127.0.0.1:8010:8010 namazu
```

Requests originate from the Namazu container, so `localhost` means the
container. Use `host.docker.internal` for an API on the Docker Desktop host.
</details>

## What it does

**Workbench.** Import a Swagger or OpenAPI document from a URL, a paste or a
file. Browse operations grouped by tag, method or path. Build requests with a
parameter table, a header editor, OAuth 2 or bearer auth, and a body generated
from the schema. Send one request or run a selection, and validate every
response against its declared contract.

**Audit.** Run the security checks across the contract, choosing how much
traffic you are willing to send.

| Profile | Budget | In flight | What it adds |
|---|---|---|---|
| `passive` | 1 request per operation | 1 | Contract analysis plus the single baseline response. |
| `readonly` | ≤90 per operation | 4 | Authorization, CORS, TLS, bypass and input probes. GET, HEAD and OPTIONS only. |
| `thorough` | ≤160 per operation | 6 | More parameters per endpoint, a bounded rate-limit burst, and time-based blind SQL injection. **Holds a database thread for a few seconds per confirmed parameter.** |
| `writes` | ≤220 per operation | 4 | Mass assignment, write authorization and body-field injection. **Creates and modifies data.** |

Write probes need `allow_mutating` *and* the Allow-writes switch. The transport
refuses a state-changing request without both, so a misconfigured profile cannot
quietly start writing to a target.

**In flight** is how many probes may be sent at once. Independent work runs in
parallel: the surface sweep, the bypass battery, and each injection point's
battery. Dependent work does not, because a payload and its control have to be
compared against the same target in the same state, and a write has to finish
before the read-back that confirms it. The request log merges in submission
order, so a concurrent run and a serial one produce the same log, the same
requests and the same findings. Set **Requests in flight** to 1 to send one at
a time.

How much that saves depends on how much of the endpoint's work is independent.
Against a target 40 ms away: an endpoint with six injection points costs 83
requests and runs in 3.6s serially, 1.3s with eight in flight; one with three
points costs 48 requests and goes from 3.7s to 3.1s. The ceiling is the number
of independent points rather than the number of workers, because the probes
within a point run in sequence, and the per-endpoint single-request checks and
the rate-limit burst are still serial.

### Checks by category

<details open>
<summary><b>OWASP API Security Top 10 (2023)</b></summary>

- **API1 Broken Object Level Authorization**: cross-identity object replay,
  anonymous replay, identifier swapping on path segments and id parameters. The
  cross-identity probes run only when the second identity is a different
  caller, and say in the notes when they did not.
- **API2 Broken Authentication**: credentials in URLs, JWT decoding, weak HMAC
  secret recovery, `alg:none` and re-signed token replay, algorithm confusion
  against the issuer's own published key, missing expiry, remote key URLs,
  forgeable tokens in response bodies.
- **API3 Broken Object Property Level Authorization**: secret-bearing response
  fields, fields the contract never documents, privileged properties a client
  may write, mass assignment verified by reading the object back.
- **API4 Unrestricted Resource Consumption**: unbounded collection parameters,
  pagination limits confirmed unenforced by response size, absence of rate
  limiting over a bounded burst.
- **API5 Broken Function Level Authorization**: documented authentication not
  enforced, privileged routes reachable by a lower-privileged identity,
  verb-bound authorization, method-override headers, and a bypass battery of
  six path rewrites and six forwarding headers against refused routes.
- **API7 Server Side Request Forgery**: fields the server is likely to
  dereference, redirect destinations, and SSRF confirmed by a server-side fetch
  error for a host that cannot resolve.
- **API8 Security Misconfiguration**: TLS validity and protocol, cleartext
  transport, reflected and wildcard CORS, cookie flags, cache directives,
  version banners, stack traces, TRACE, framing controls, HTTPS-to-HTTP
  redirects, forwarding-header reflection, CRLF response-header injection,
  duplicate-parameter handling, web cache deception, and XML external entity
  processing on operations that accept XML.
- **API9 Improper Inventory Management**: zombie operations, undocumented
  version siblings, operational and debug paths, exposed specifications and
  documentation, GraphQL introspection, undocumented methods, and source or
  configuration files served to the public.

</details>

<details>
<summary><b>Input handling</b></summary>

Error-based and boolean-based SQL, document-database operators, LDAP filters,
server-side template injection across four engine families (`{{ }}`, `${ }`,
`#{ }`, `<%= %>`), path traversal, open redirect, CRLF response-header
injection, duplicate parameters and unencoded HTML reflection.

On `thorough` only, time-based blind SQL injection, for the parameters where no
other oracle exists because the response never changes. A delay alone is never
the finding: the same payload is sent asking for zero seconds, which has to
return promptly, and then at double the sleep, which has to take proportionally
longer. That pair is what separates an injectable parameter from an endpoint
that is merely slow, or intermittently so.

The same battery runs wherever the contract declares an input, because the sinks
do not care how the value arrived:

| Declared in | Notes |
|---|---|
| `query` | Parameters the request carried, plus documented optional ones a generated request would omit. |
| `path` | Identifier positions, which reach the same sinks a query parameter does. |
| `header` | Easy to overlook, because the value never appears in a URL. |
| `cookie` | Probed by replacing one cookie and leaving the rest of the jar intact, so a session is not dropped mid-probe. |
| request body | Write profile only. Scalar fields including nested ones (`items[0].sku`); booleans are skipped, since a string payload is rejected before it reaches a sink. |

A line terminator is never placed in a header or a cookie: malforming the
request itself is request smuggling, which is a different class and an invasive
one. Every payload is a detection canary: nothing writes a file, runs a command,
or reads real data beyond the marker that proves the sink exists.

One probe is not free, and says so. The time-based SQL check on `thorough` holds
a database thread for about six seconds on each parameter it confirms, capped at
two parameters per operation. The XML external entity probe points at a path
that cannot exist, so it demonstrates that the parser resolves external entities
without reading anything real; pointed at a file instead, the same request would
return its contents, and Namazu does not do that.

</details>

<details>
<summary><b>OAuth 2</b></summary>

Namazu obtains real tokens so the audit can reach protected routes, and so a
second identity can be a genuinely different account.

| Grant | Browser | Notes |
|---|---|---|
| Authorization code + PKCE | yes | Namazu serves its own redirect URI at `/oauth/callback` and collects the code automatically. |
| Client credentials | no | Machine to machine. |
| Refresh token | no | Renew without repeating the browser flow. |
| Password | no | Supported because engagements still meet it; its use is reported as a finding. |

An OAuth identity can also be handed to the audit directly rather than pasted
in as a header. The engine mints the token server-side and renews it when it
nears expiry, so a run across dozens of operations does not start returning 401
halfway through because the token lapsed. Client credentials and password mint
directly; an authorization code identity renews from the refresh token it was
issued. A credential that cannot be obtained is reported as a setup problem,
not as a page of findings.

It also tests the authorization server itself with three read-only probes: an
unregistered `redirect_uri`, `response_type=token`, and an authorization request
with no `code_challenge`. A rejection is the healthy result.

</details>

## One document

Namazu reads the single document you import. A specification split across files
with `$ref: common.yaml#/...` therefore arrives with those schemas missing, and
that matters more than it sounds: a reference it cannot resolve becomes `null`
in the generated request body, the target rejects or mis-answers the baseline,
and most probes stop there. The result is a short report for a reason nobody
chose.

The import now says so, naming the references and how many, and the run notes
repeat it. Bundle first to audit the whole surface:

```sh
redocly bundle openapi.yaml -o bundled.yaml     # or: swagger-cli bundle
```

A reference naming a schema the document does not define is reported
separately, since that is a defect in the document rather than a consequence of
splitting it.

Everything else resolves: `allOf` inheritance and chains of it, `allOf` beside
its own `properties`, `oneOf`/`anyOf` with a discriminator, objects behind
several `$ref` hops, arrays of references, self-referential schemas, 3.1
nullable type unions, and `readOnly`/`writeOnly`. Each of those shapes is
pinned by a test asserting both that a request body is generated and that the
privileged properties behind it are still found, because a shape that silently
yields nothing produces no finding rather than a wrong one.

## Second opinions

Two mature tools cover ground Namazu does not, and both run locally. Neither is
required; when one is absent the run says so rather than leaving a silent gap.

| Tool | Adds | Install |
|---|---|---|
| [**schemathesis**](https://github.com/schemathesis/schemathesis) | Property-based testing from the same OpenAPI document: undeclared 500s, schema violations, ignored authentication. | `pip install schemathesis` |
| [**nuclei**](https://github.com/projectdiscovery/nuclei) | Community templates for known CVEs, exposed panels, default credentials and misconfigurations. | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [**ZAP**](https://www.zaproxy.org/) | An Automation Framework plan with an OpenAPI import and the OWASP active-scan rule set. | [Download ZAP](https://www.zaproxy.org/download/), or set `NAMAZU_ZAP_DOCKER_IMAGE` |

Each reports its version, what it can do, where its policy comes from, and what
it did not cover. A tool that times out, exits early or tests fewer operations
than it was given says so in the run notes rather than leaving a short result
to speak for itself.

The ZAP adapter inherits the run's scope, credentials, write policy and traffic
limit through the plan it writes, which is a file an operator can read rather
than something to take on trust. Four things it will not do:

- **Widen the write policy to make itself useful.** ZAP's active rules send
  payloads with state-changing methods, and restricting a *running* active scan
  to safe methods is not something the framework guarantees. With writes
  disabled the plan contains no `activeScan` job at all, the passive rules read
  the traffic from the OpenAPI import, and the run reports active-rule coverage
  as a gap rather than a clean result.
- **Treat GET as harmless.** A GET can delete. The policy is an explicit
  method allow-list, written into the plan.
- **Trust a tag or a rule category as a safety property.** The same reasoning
  as a nuclei `cve` tag: the taxonomy describes the subject, not the side
  effects.
- **Fold its coverage into Namazu's.** ZAP's idea of what it covered is not
  Namazu's, so it is reported separately.

The credential goes in the plan file, not on the command line, so it does not
appear in a process list.

**Audit → Second opinion** lists whichever of them this machine can run, with
its version. Running one folds what it reports into the same findings list,
severity bar and export as everything else, tagged with the tool's name in the
list and in the finding header, and marked `probable` with a limitation saying
Namazu did not verify the match itself. A nuclei template match is never
presented as something this tool established.

Tick **Run these after the audit** and the Run audit button carries straight on
into each installed tool once Namazu's own checks have finished, one at a time.
A stopped audit does not start them.

schemathesis is invoked as `python -m schemathesis.cli` using the interpreter
running Namazu, not through the `st` console script. Where that generated script
is built wrong it exits non-zero having written nothing at all, no report and no
message, which leaves nothing to report; the module runs normally in the same
environment. It also pins which installed copy runs instead of trusting PATH
order. Install it into the same environment:

```sh
.venv/Scripts/python -m pip install schemathesis
```

Both are held read-only: destructive, fuzzing and brute-force templates are
excluded, nuclei runs with `-no-interactsh` so there is no outbound callback,
and schemathesis stays on safe methods unless Allow writes is on.

nuclei runs CVE templates as well as exposure, misconfiguration and technology
ones. That is the set worth having, since a known vulnerable version behind the
API is the thing it is here to find, but it costs minutes rather than seconds.
Several template matches at the same URL collapse into one finding listing the
matchers that fired, so the finding count is lower than nuclei's own match
count.

## What a finding claims

A severity and a confidence cannot describe a finding honestly on their own.
Reading an OpenAPI document can establish beyond doubt that the document
declares an implicit OAuth flow, so "confirmed" is accurate. What it must not
be allowed to mean is that a confirmed authentication vulnerability was found.
Those two claims differ in kind, not in certainty, and one field cannot carry
both.

So every finding carries four independent axes.

**Category** is what kind of defect this is.

| Category | Means |
|---|---|
| **Security weakness** | Something an attacker could use, or the surface of it. |
| **Hardening concern** | A control absent or weaker than current guidance, with no demonstrated route to abuse it here. |
| **Contract defect** | The implementation and its published specification disagree. |
| **Reliability defect** | The implementation fails or errors on input it accepts. |
| **Informational** | An observation recorded for the reader, asserting no defect. |

**Origin** is where the evidence came from: `static-declaration` (read from the
specification, nothing sent), `runtime-observation` (seen in a response during
this run), or `external-report` (another tool said so and Namazu normalised it).
Origin is not quality. A runtime observation of a 403 is a fact about one
request; it is not a fact about authorization.

**Verification** is how far the behaviour was taken.

| Rung | Means |
|---|---|
| `unverified` | Nothing beyond the evidence shown was established. |
| `observed` | The behaviour appears in a response captured during this run. |
| `reproduced` | It was replayed and happened again. |
| `impact-demonstrated` | A security consequence was demonstrated, not inferred. |

**Confidence** keeps its old meaning, with one addition: a `confirmed` finding
now has to say *what* was confirmed. That sentence appears in the finding under
**What this establishes**, because "confirmed" with no object is the failure
this structure exists to prevent. The implicit-flow finding now reads:

> What is confirmed is the declaration:
> `#/components/securitySchemes/Oauth2/flows/implicit` exists in the imported
> document. Not confirmed, and not tested: that the authorization server offers
> the implicit grant, that it would issue a token through it, or that any
> client uses it.

### How severity is decided

A probe proposes a severity. The severity a finding ends up with is the one
these rules permit for the kind of evidence behind it, and the finding records
which rule decided it, so an operator can argue a number with a client instead
of defending it.

| Rule | Ceiling | Why |
|---|---|---|
| `informational-is-info` | info | An observation that asserts no defect is not a severity. |
| `contract-defect-is-informational` | info | A disagreement between an implementation and its own specification is a documentation defect. It becomes a security severity when a security consequence is demonstrated, not because a client might mishandle it. |
| `reliability-defect-is-low` | low | An unhandled path is a bug until something is shown to come of it. |
| `hardening-without-impact-is-medium` | medium | A missing control with no demonstrated route to abuse cannot outrank a weakness that was shown. |
| `static-declaration-is-low` | low | A specification states an intention, not behaviour. |
| `unreproduced-external-report-is-medium` | medium | Another tool's unreproduced report is a lead. Namazu has not re-sent the request. |
| `critical-needs-demonstrated-impact` | high | Critical is reserved for a weakness whose consequence was demonstrated. |

Each rule lifts once the evidence reaches the rung it names, so replaying an
external tool's finding or demonstrating a consequence moves it up.

A severity another tool assigned is **preserved, not overwritten**. A nuclei
template rated high appears as medium with `nuclei rated it: high` beside it.

CWE and OWASP mappings now need a stated basis whenever the finding did not
observe the behaviour itself, and a mapping with no defensible relationship is
dropped rather than softened. The implicit-flow finding used to carry CWE-598,
"sensitive information in a query string", for a grant that returns its token
in a URL fragment; the finding's own limitations text said it had not
determined which of the two applied. It now carries no CWE and says why.

## Coverage: what a run actually tested

A report's most dangerous sentence is the one it does not contain. An audit
that ran forty probes against a denied baseline produces no findings for them,
and nothing distinguishes that from forty probes that ran and found the target
sound.

So the first request of each operation is classified, and the result decides
what may follow.

| Baseline outcome | Means |
|---|---|
| `success` | The operation answered with something the probes can compare against. Not the same as 2xx: see below. |
| `authentication-failure` | The credential was not accepted at all. |
| `permission-denied` | The request was refused. A 403 does not say whether the credential was rejected or whether this caller is not allowed this resource, and Namazu does not claim to know which. |
| `invalid-data` | The request never named anything real, usually because the identifier was generated from the schema. |
| `unexpected` | Neither a success nor a refusal this tool can interpret, including a 5xx. |
| `transport-failure` | The request did not complete. |

Then every probe family ends the run in one state:

| State | Means |
|---|---|
| **Ran** | It ran and reached a conclusion. |
| **Blocked** | A prerequisite was not met, with the reason and what would unblock it. |
| **Inconclusive** | It ran, and the evidence supports no conclusion either way. |
| **Not in this profile** | Deliberately not run. |
| **Nothing to test** | The operation has nothing for it to look at. |

There is deliberately no **passed**. A check that ran and found nothing is
shown as **Ran**, because "passed" is a claim about the target and "ran" is a
statement about the audit. **Audit → What was tested** lists every family with
its state, and the export carries the same structure.

Two families are treated specially, and both would have cost real coverage if
they were not. The **access-control bypass** battery needs a baseline that was
*refused*, since what it looks for is a trivially different form of the same
request getting through; a refusal is its input. And a missing second identity
blocks the **cross-identity read** alone, not the whole authorization family,
which also holds the anonymous replay, the identifier swap and the token
battery.

### Getting a usable baseline

Where a contract documents no example, the generated request carries the
literal `string` for a path parameter and `0` for an integer. A request for
`/reports/string` is not a request for a report, so the audit says so before
the run as well as after.

**Audit → Baseline for this operation** takes three things, saved per operation
and per base URL:

- **A request URL and body** known to work. **From last run** takes the one the
  Request tab just sent. Credential headers in a saved example are ignored and
  the audited identity is applied over it, so an example cannot change who the
  audit runs as.
- **Assertions**: the status that counts as success, and a string the response
  must contain. A 2xx alone is not always success.
- **A negative flag**, for an operation whose correct answer is a refusal. With
  it, a 403 is a baseline that worked and a passing negative test, rather than
  a reported gap.

## Evidence and replay

A finding that says another tool found something and carries a seed is not
evidence. The seed reproduces the input only if the tool, its version, the
schema and the generator all line up, and a reader holding the report has none
of those.

Namazu now captures a **case** for each failing exchange: the request as sent,
the response as received, which identity sent it, when, the correlation ids the
response carried, the expected outcome, the prerequisite steps, the tool and
version, the schema hash, and an explicit list of what is *not* in the capture.
schemathesis findings are built from its NDJSON scenario record rather than its
summary, which is where the actual requests and responses live.

**Replay** sends a case again, up to five attempts, and reports `reproduced`,
`not-reproduced`, `intermittent`, `blocked` or `error` with the attempt counts.
Three things it will not do:

- **Send a redaction placeholder as a credential.** Credentials never enter a
  case; the case records an *identity reference* and replay resolves it from
  local configuration. A case whose identity is not configured is `blocked`,
  because replaying it anonymously answers a different question and would read
  as "not reproduced".
- **Repeat a mutating request to raise confidence.** A case that changes state
  is `blocked` unless writes are enabled for the run, and Namazu will not
  re-send one on its own initiative.
- **Claim more than it showed.** Replay establishes that the recorded behaviour
  happens again. It can raise a finding to `reproduced` and no further; whether
  the behaviour is a weakness is a separate judgement.

Replay goes through the same executor as a probe, so the request budget, the
write policy and the outbound route all apply to it.

### Seeds and wide integers

A schemathesis seed is 128 bits wide, and `JSON.parse` rounds anything past
2<sup>53</sup>. A shipped export held `2.315194611349191e+38` where the seed had
been `231519461134919091197611956279382553858`: still a number, no longer the
seed, and useless for reproducing anything. Integers outside JavaScript's exact
range are now written as decimal strings, and a seed that arrives as a float is
refused rather than truncated, because by that point it is a different number.

## Duplicates

Namazu and the external tools overlap. Two reports are merged only on evidence:

- **Merged** when both carry a captured exchange and the exchanges agree on the
  operation, the response status and the specific thing observed, such as the
  media type. Both sources are kept on the merged finding.
- **Marked a possible duplicate** when the semantics line up but one side has no
  exchange, so the agreement cannot be checked. Both findings stay.

Nothing merges because two titles or two endpoints match. Two findings on
`GET /orders/{id}` with the same title can be two different failures against
two different inputs, and merging them loses one.

## Authorization and workflows

**Audit → permission matrix** (`POST /api/matrix`) states who should be able to
do what: identity, role, tenant, test resource, operation, and whether access
is expected to be allowed or denied.

Two rules make its answers worth having. A row is only concluded after that
identity's **own positive control** has passed, because an API that refuses
everybody looks exactly like an API with a working boundary, and an API that is
down looks like both; without a control, a denial is `inconclusive`. And access
is judged by a **resource marker**, a string that appears in that resource and
no other, rather than by a status code or by how similar two bodies are. A 200
that does not carry the marker has not shown the resource was reached, which is
how a tool comes to report a bypass against an API that returns an empty list
to everyone.

The **sequence runner** (`POST /api/sequence`) gets real identifiers into
downstream requests: steps run in order, each can extract values from its
response by JSON Pointer or from a response header, and later steps substitute
them as `${name}`. There are no conditionals, loops or expressions, because none
of them is needed to get an identifier into a path and each would need its own
safety argument. An undefined variable stops the sequence rather than sending a
request with the placeholder left in or blanked out, since `/reports/` is a
different request from `/reports/r-100`.

Objects are recorded as **created**, **possibly-created** (a write whose
response never arrived) or **attempted**. Nothing is deleted: Namazu does not
remove a resource without a configured cleanup step and an identity authorised
to run it.

## OAuth conclusions

"The implicit flow is enabled" was being used for five different claims. They
are now separate rungs, and a probe reports the highest one its evidence
reaches:

1. **advertised**: the specification declares the flow. A static read.
2. **client-configured**: this client is set up for it.
3. **server-accepts**: the authorization server did not reject the request.
4. **token-issued**: a token came back, and where it came back is known.
5. **weakness-demonstrated**: a concrete consequence was shown.

A login page, a redirect and an HTTP 200 all sit at rung 3 at best. An
authorization server renders a sign-in form to an unauthenticated browser
whether or not it would ever issue through this grant, so rung 4 requires
`access_token` in the fragment or the query string of the redirect. Which of
the two it is decides whether the Referer and server-log exposure routes apply,
so the finding reports the location rather than assuming one.

Rung 4 needs a browser and a consenting user, so it is reported as *requiring*
interactive verification, with the prerequisites named, and the token it would
return is a live credential. A PKCE downgrade conclusion is only drawn from two
observations of the same client and the same flow; a server may require PKCE
for one client and not another, which is a configuration difference and not a
downgrade.

## Reading a finding

Each finding is laid out as an advisory, with what is true about *this target*
kept separate from what is true about *this class of weakness*:

**Issue detail** · **Issue background** · **How this was found** · **Impact** ·
**Limitations** · **Classification** (OWASP + CWE) · **Evidence** ·
**Proof of concept** · **Remediation** · **Remediation background** · **References**

Sections collapse and remember your choice. Values that carry the meaning are
marked inline, and hovering one says why:

| Colour | Means |
|---|---|
| 🔴 red | the weakness itself: the grant, the setting, the recovered secret |
| 🟥 deep red | data that escaped: secrets, card numbers, private keys, undocumented fields |
| 🟠 amber | a value Namazu supplied, so a probe is distinguishable from real traffic |
| 🔵 blue | what proves it: the matching body signature, the Location header, the error pattern |

Every captured request renders as a command for **bash**, **PowerShell** and
**cmd**. Findings taken from the contract have no request to replay, so they get
a command that prints the exact part of the document instead:

```sh
curl -s https://api.example.com/openapi.json | jq '.components.securitySchemes.legacy.flows.implicit'
```

## Traffic

**Audit → Traffic** is three panes: the request history, and beside it the
request and the response for whichever row is selected.

The history lists every request sent, in order: the 404 calibration, the
inventory sweep, the baseline, each probe and each control. Columns are
sequence, method, path, which probe sent it, status, size and time. Filter to
probes, errors or state-changing requests, and walk the list with the arrow
keys.

The request and response panes each offer **Pretty** and **Raw**; the request
pane also carries the reproduction command for bash, PowerShell and cmd. Raw is
rebuilt from the captured exchange rather than being a capture of the bytes on
the wire, and the pane says so. Credential headers are masked in both. Drag
either gutter to resize, or focus it and use the arrow keys; the widths are
remembered.

This is the record of what the tool actually did, which is what you need when a
finding is disputed or when something on the target breaks mid-test.

## Media types

A response whose media type carries a structured syntax suffix (RFC 6839) is
matched against a declared media type of the same syntax. An operation that
documents `application/json` and returns `application/problem+json` for its
errors, which is what RFC 9457 problem details look like, is validated against
the schema declared for `application/json`.

That is a warning, not a pass and not a failure: the contract really does not
document the media type, and a client that registers a deserializer for the
exact string will not handle the response. But the body is the syntax the
schema was written for, so refusing to look at it loses the useful finding to
keep the cosmetic one. The audit reports this as `info`; a media type that
matches nothing at all is still `low`.

## Safety

- Read-only HTTP methods unless you explicitly enable writes, refused at the transport.
- Hard request budget per operation, held atomically so concurrency cannot
  overshoot it; reaching it is reported, not hidden.
- Parallel work is read-only by construction: the transport refuses a
  state-changing request sent from inside a fan-out.
- Body injection writes. The report names the fields probed and counts the
  state-changing requests sent, so the objects it created can be removed.
- Detection-only payloads. No file writes, no command execution, and no file
  read: the XML external entity probe names a path that cannot exist, so a
  parser's own error is the only thing it learns from.
- One timed probe, on `thorough` only. A sleep payload holds a database thread,
  so it is off on `passive` and `readonly`, capped at two parameters per
  operation, and costs about six seconds per parameter it confirms.
- A cross-identity finding is never reported from one account asked twice. If
  both identities carry the same credential, or two tokens with the same
  subject or the same client, the probe is skipped and the run says so: a
  critical finding naming an account boundary has to have had two accounts to
  compare. Credentials the second identity does not replace are removed from
  its request, so a write can never succeed on the first identity's token and
  be read as the second one's.
- No outbound callback service: nuclei runs with `-no-interactsh`.
- Redirects are read, never followed. Requests are never retried.
- No database. Tokens, headers and responses live in the browser tab and the
  server process only. Theme and layout are the only things stored locally.
- Exports mask recognised credential headers and query values. Response bodies
  are **not** masked; review before sharing.
- Namazu identifies itself by name on every request, by default. See
  **Outbound identity** below.
- Every request can go through your proxy, so the engagement record is the one
  you already keep. Set **Upstream proxy** under Settings to
  `http://127.0.0.1:8080` and each probe lands in Burp or ZAP, replayable from
  Repeater. An intercepting proxy presents its own certificate, so give it its
  **CA bundle** too, or every HTTPS request fails verification instead of
  reaching the target. The certificate inspection is the one thing that still
  connects directly, deliberately, since through an intercepting proxy it would
  be reading the proxy's certificate; the report says when that happened.
  **Client certificate** and **Client key** cover an API that requires mutual
  TLS; both are paths read by the Namazu server, which keeps the private key
  off the wire.
- Loopback by default. With `--host 0.0.0.0` you supply your own access control.

## Outbound identity

By default the traffic says what it is. The user agent names Namazu and its
repository, and so does every probe marker: the Origin the CORS check sends,
the header the TRACE check looks for, the path the cache-deception check
appends, the body property the mass-assignment check adds, the host the SSRF
check cannot resolve. Both sides of an engagement can then pick the test out of
a log afterwards, and a marker left in a database says where it came from.

**Settings → Outbound identity → Do not name the tool** removes all of it. The
user agent becomes an ordinary browser string, and every marker, header name
and path segment is derived instead from a token drawn fresh for the run. Two
reasons to want it: testing whether the target's own monitoring notices a scan,
and a WAF that refuses an unfamiliar client by name before the test can start.
A user agent you set yourself still wins over both defaults.

The quiet markers are random rather than a second fixed set on purpose. A fixed
alternative would be a Namazu fingerprint of its own as soon as anyone wrote it
down.

Two things it does not do. It changes what the traffic is called, not what it
is: the same probes run in the same order, an injection payload still looks
exactly like an injection payload, and a hundred requests to one endpoint still
look like a hundred requests to one endpoint. It defeats attribution to this
tool, not detection of testing. And it does not reach the external scanners,
which announce themselves on their own terms.

Because a quiet run signs nothing, the report names the token it used. Search
the target's logs and stored data for that value to attribute the run during
cleanup.

## Limits

Namazu reports what it could establish from outside, within a bounded number of
requests. It does not model business logic, chain findings into a working
exploit, obtain sessions through a browser login, test under load, or prove the
absence of a vulnerability.

External `$ref` documents, custom schema dialects and dynamic references produce
**Not validated** rather than a pass. OpenAPI 3.2 is not supported in this
version.

Blind findings need a callback the target can reach, and Namazu runs no such
service. Blind SSRF, blind XXE and stored injection are therefore out of reach:
the XML probe confirms that external entities resolve but cannot see a parser
that resolves them silently, and the SQL timing probe covers only parameters
interpolated into a quoted string on an engine that has a sleep function.

On the evidence and coverage work specifically:

- **Rung 4 of the OAuth ladder cannot be reached automatically.** Showing that
  a token is issued through the implicit grant needs a browser and a consenting
  user, so Namazu reports the prerequisites and stops at rung 3. Rung 5 is
  recorded from an operator's own evidence and is never inferred.
- **nuclei findings carry no replayable case.** It reports the matcher that
  fired and the URL it matched, not the exchange, so its findings cannot be
  replayed and stay at `unverified`. schemathesis and ZAP both record the
  exchange and can be.
- **Correlation is limited to the observations listed in `correlate.py`.** Two
  sources agreeing about something not in that table are reported twice. That
  is the deliberate direction to fail in: a missed merge is a duplicate in the
  report, and a wrong merge is a finding that disappeared.
- **A replay of a mutating case is refused, not queued.** Enabling writes is
  the only way to replay one, and Namazu will not repeat a write on its own
  initiative to raise confidence.
- **Cleanup is recorded, not performed.** Nothing is deleted without a cleanup
  step you configure and an identity authorised to run it, so an audit that
  created objects leaves them for you with a list of what they were.
- **The ZAP adapter has not been exercised against an installed ZAP here.** Its
  plan is built, round-tripped through a YAML parser and tested, and its report
  parsing is tested against the `traditional-json-plus` shape, but no ZAP
  binary was available to run end to end.

**Only run this against systems you are authorised to test.**

## Development

```sh
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m pytest --cov            # 77% of lines, reported not gated
node --check namazu/static/app.js
```

454 tests across 93 checks, about 90 seconds to run, most of which is the
time-based SQL tests waiting for real delays. Detections are asserted in both
directions: a check fires on the broken handler, and stays silent on the correct
one. Where a check rests on a control, the test asserts the control is what
suppressed it, rather than only that nothing was reported.

The HTTP API is `POST /api/import`, `/api/prepare`, `/api/run`, `/api/audit`,
`/api/audit/inventory`, the `/api/oauth/*` family, `/api/tools`, and
`GET /api/health`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the bar a new check has to meet.

## Licence

[MIT](LICENSE) © 2026 cwsecur1ty
