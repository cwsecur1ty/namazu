# Contributing

Thanks for looking. The most useful contribution is a new check, or a fix to an
existing one that reports something it should not.

## The bar for a check

A check earns its place by being hard to argue with. Before a new one is merged
it needs all of these.

**A control, not just a payload.** A finding may not fire on reflection alone.
The error-based probes send a structurally identical inert twin (`''` against
`'`, `[xne]` against `[$ne]`) and require the twin to stay clean. Template
injection has to evaluate two different sums. Reflection is matched on a
per-probe random nonce so a string already in the response cannot satisfy it.

**A method sentence.** Every finding says how it was reached, in terms a reader
can repeat by hand from the proof-of-concept requests. If the check reads the
contract rather than sending a request, it says so.

**Honest confidence.** `confirmed` means the evidence establishes it.
`probable` means the evidence is consistent with it. `possible` means it is
attack surface worth testing, not a demonstrated weakness. If you are choosing
between two, choose the weaker one.

**Limitations.** What does this finding *not* establish? A static read cannot
show the running server behaves as documented. A version match is not a
behaviour proof. Write it down; the field exists for this.

**Tests in both directions.** One test asserting the finding fires on a broken
handler, and one asserting it stays silent on a correct one. The second is the
one that matters. Look at `tests/test_audit.py` for the pattern:

```python
def test_per_user_scoping_is_not_reported_as_bola():
    """Each identity gets its own object, so nothing should fire."""
```

**A catalogue entry.** Add the check id to `namazu/audit/catalogue.py` with its
CWE and references. A test fails if a check can be emitted without one.

**Read-only unless gated.** If the probe can change server state it must be
marked `mutating=True` and sit behind the `writes` profile. The transport
refuses it otherwise, but mark it anyway so the report is accurate.

## Project shape

```
namazu/
  app.py            FastAPI routes and the host/origin guard
  spec.py           OpenAPI parsing, request building, schema validation
  runner.py         single request execution and response review
  discovery.py      documentation fetching, URL and header validation
  oauth.py          OAuth 2 grants, PKCE, authorization-server probes
  audit/
    engine.py       orchestration, profiles, budgets, result shape
    transport.py    bounded, safety-gated HTTP execution
    model.py        Exchange, Finding, highlights, reproduction commands
    catalogue.py    CWE, references, issue background, default limitations
    specscan.py     contract analysis, sends nothing
    passive.py      single-response analysis
    posture.py      TLS, dangerous methods, framing, resource limits
    authz.py        authorization probes, JWT replay
    bypass.py       access-control bypass battery, cache deception
    inputs.py       input-handling probes and write probes
    inventory.py    shadow endpoints, exposed documents and source
    jwtlab.py       JWT decode, weak-secret recovery, offline forging
    external.py     schemathesis and nuclei, normalised
  static/           the whole frontend: one HTML file, one JS file, one CSS file
```

The frontend has no build step and no dependencies. A strict CSP blocks inline
script and style, so build DOM nodes rather than assigning `innerHTML`.

## Running the checks

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
node --check namazu/static/app.js
```

Tests use mocked transports and an ephemeral loopback target. Nothing in the
suite contacts an external host.

## Style

Match what is there. Comments explain why a thing is the way it is, not what the
line does. No em dashes anywhere in the project; a test enforces it.

Finding text is read by people writing reports for clients, so it should be
specific, qualified where it depends on something unmeasured, and free of
marketing language.

## Reporting a false positive

That is the most valuable issue you can file. Include the response that caused
it, the check id, and what the correct behaviour would have been. A false
positive is treated as a bug of the same weight as a missed detection.

## Security

Do not open a public issue for a vulnerability in Namazu itself. See
[SECURITY.md](SECURITY.md).
