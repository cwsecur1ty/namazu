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
| **A full request log** | Every request the audit sent, in order, whether or not it produced a finding. |
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

| Profile | Budget | What it adds |
|---|---|---|
| `passive` | 1 request per operation | Contract analysis plus the single baseline response. |
| `readonly` | ≤60 per operation | Authorization, CORS, TLS, bypass and input probes. GET, HEAD and OPTIONS only. |
| `thorough` | ≤120 per operation | More parameters per endpoint, plus a bounded rate-limit burst. |
| `writes` | ≤140 per operation | Mass assignment and write authorization. **Creates and modifies data.** |

Write probes need `allow_mutating` *and* the Allow-writes switch. The transport
refuses a state-changing request without both, so a misconfigured profile cannot
quietly start writing to a target.

### Coverage

<details open>
<summary><b>OWASP API Security Top 10 (2023)</b></summary>

- **API1 Broken Object Level Authorization**: cross-identity object replay,
  anonymous replay, identifier swapping on path segments and id parameters.
- **API2 Broken Authentication**: credentials in URLs, JWT decoding, weak HMAC
  secret recovery, `alg:none` and re-signed token replay, missing expiry,
  remote key URLs, forgeable tokens in response bodies.
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
  duplicate-parameter handling, and web cache deception.
- **API9 Improper Inventory Management**: zombie operations, undocumented
  version siblings, operational and debug paths, exposed specifications and
  documentation, GraphQL introspection, undocumented methods, and source or
  configuration files served to the public.

</details>

<details>
<summary><b>Input handling</b></summary>

Error-based and boolean-based SQL, document-database operators, LDAP filters,
server-side template injection across four engine families (`{{ }}`, `${ }`,
`#{ }`, `<%= %>`), path traversal, open redirect and unencoded HTML reflection.
Probed in query parameters and in documented header parameters.

Every payload is a detection canary. Nothing sleeps, writes a file, runs a
command, or reads real data beyond the marker that proves the sink exists.

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

## Second opinions

Two mature tools cover ground Namazu does not, and both run locally. Neither is
required; when one is absent the run says so rather than leaving a silent gap.

| Tool | Adds | Install |
|---|---|---|
| [**schemathesis**](https://github.com/schemathesis/schemathesis) | Property-based testing from the same OpenAPI document: undeclared 500s, schema violations, ignored authentication. | `pip install schemathesis` |
| [**nuclei**](https://github.com/projectdiscovery/nuclei) | Community templates for known CVEs, exposed panels, default credentials and misconfigurations. | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

Their findings are normalised into the same advisory shape and clearly attributed
to the tool that produced them, marked `probable` because Namazu did not verify
them itself.

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

## Request log

**Audit → Log** lists every request sent, in order: the 404 calibration, the
inventory sweep, the baseline, each probe and each control. Columns are
sequence, method, path, which probe sent it, status, size and time. Filter to
probes, errors or state-changing requests. Selecting a row shows the full
exchange and its reproduction command.

This is the record of what the tool actually did, which is what you need when a
finding is disputed or when something on the target breaks mid-test.

## Safety

- Read-only HTTP methods unless you explicitly enable writes, refused at the transport.
- Hard request budget per operation; reaching it is reported, not hidden.
- Detection-only payloads. No sleeps, no file writes, no command execution.
- No outbound callback service: nuclei runs with `-no-interactsh`.
- Redirects are read, never followed. Requests are never retried.
- No database. Tokens, headers and responses live in the browser tab and the
  server process only. Theme and layout are the only things stored locally.
- Exports mask recognised credential headers and query values. Response bodies
  are **not** masked; review before sharing.
- Loopback by default. With `--host 0.0.0.0` you supply your own access control.

## Limits

Namazu reports what it could establish from outside, within a bounded number of
requests. It does not model business logic, chain findings into a working
exploit, obtain sessions through a browser login, test under load, or prove the
absence of a vulnerability.

External `$ref` documents, custom schema dialects and dynamic references produce
**Not validated** rather than a pass. OpenAPI 3.2 is not supported in this
version.

**Only run this against systems you are authorised to test.**

## Development

```sh
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
node --check namazu/static/app.js
```

226 tests across 89 checks. Detections are asserted in both directions: a check fires on the
broken handler, and stays silent on the correct one.

The HTTP API is `POST /api/import`, `/api/prepare`, `/api/run`, `/api/audit`,
`/api/audit/inventory`, the `/api/oauth/*` family, `/api/tools`, and
`GET /api/health`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the bar a new check has to meet.

## Licence

[MIT](LICENSE) © 2026 cwsecur1ty
