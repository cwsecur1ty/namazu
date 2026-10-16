# Native campaigns and explicit OOB evidence

The desktop **Fuzzing & OOB** destination exposes the existing bounded audit
campaigns and a separate, offline callback evidence workflow. Opening this view,
preparing a payload, importing collector output or reviewing a plan sends no
target or callback requests.

## Native schema campaigns

Choose contracts and their selected operations, the read-only, thorough or writes
profile, a shared request budget and rate, then **Review native fuzzing plan**.
The existing planner provides deterministic omission, null, type and boundary
mutations, field/case prerequisites and supplemental check families. These are
the existing audit profiles, so they can include security checks beyond schema
mutations. The reviewed workspace plan retains contract limits, identity scopes,
overlap decisions, snapshot hashes and inventory versus endpoint traffic.

Starting the reviewed audit is a separate action. Its existing executor enforces
the shared budget/rate, cancellation, HTTP 429 stopping, contract write permission
and run write authorisation. Selecting the writes profile does not grant a
contract permission. Missing successful controls or explicit permission
expectations remain missing. Counts and retained receipts describe what actually
ran; the local regression tests do not establish API security coverage.

## Bring an explicitly authorised callback session

Namazu does not start an Interactsh client, register a session, poll a collector,
resolve the callback hostname or choose a public callback service. Supply an
HTTP(S) session origin that you control and are authorised to use, including a
self-hosted session. Origins with credentials, paths, queries, fragments or IP
addresses are rejected. The official [Interactsh project](https://github.com/projectdiscovery/interactsh)
documents its client/server and JSONL output; using that separate software is an
explicit operator action outside Namazu.

1. Open an exact workspace contract operation and its request draft.
2. In **Fuzzing & OOB**, supply the session origin, confirm its authorised scope,
   and choose a body JSON pointer, query parameter or noncredential header.
3. Prepare the case. Namazu generates a random per-case DNS label and URL and
   inserts that exact value into the selected draft field. This clears write
   consent. Case-purpose choices are hypothesis labels; they do not generate
   executable commands, XML documents or complete exploit payloads.
4. Inspect the resulting request and use the ordinary **Send** action if
   authorised. Its existing scope, credential, redirect, write-consent and
   cancellation checks apply. A linked OOB case is checked for expiry, retirement
   and changed context before Send. Preparation alone remains **prepared**.
5. Import the collector's Interactsh JSON Lines into the exact case. Retain its
   source name. Review matched and unmatched records, timestamp-window labels,
   import errors and existing receipt links. No polling or replay occurs.

Each case retains workspace, contract, operation, target, snapshot hash, identity
reference/revision and assigned scopes. Target changes, credential rotation or
assignment changes disable its future payload use. Retiring a case also disables
future use; it cannot retract an already submitted request or callback. A case
expires after one day by default; the API accepts 60 seconds through seven days.
Use a new case for a new context.

## Correlation and evidence accounting

The Interactsh [interaction structure](https://github.com/projectdiscovery/interactsh/blob/main/pkg/server/server.go)
contains `protocol`, `unique-id`, `full-id`, timestamps and raw request/response
fields. Namazu uses the exact per-case full ID or exact callback hostname from
the imported request. The normal server
[HTTP handling](https://github.com/projectdiscovery/interactsh/blob/main/pkg/server/http_server.go)
retains the prefix through the session label in `full-id`; Namazu recognises that
form. A bare session `unique-id`, matching text in a response/body, a similar
hostname or an explicitly conflicting full ID cannot correlate a case.

An existing receipt can be linked only when its exact contract, operation,
target, snapshot, identity reference/revision/source and selected field payload
match, and it records one dispatched attempt. Linking that receipt counts no new
network attempt. Repeated links are idempotent. Distinct DNS/HTTP observations
remain separate interactions; importing an identical event again records a
duplicate instead of another observation. Late or missing timestamps are
explicitly marked outside or unknown, and malformed lines do not discard valid
lines in the same import.

Imported records are always **external-report / imported-unverified**. A callback
is a callback observation, with attribution and security impact **not
established**. It can arise from a resolver, previewer, scanner or intermediary.
Even an exact payload and receipt link do not prove which component initiated a
callback or demonstrate a vulnerability. No callback also does not establish
safety. This feature does not auto-create findings or confirm SSRF, blind command
injection or XXE from a callback alone.

## Persistence, exports and limits

Cases and observations persist in version 1 `evidence/oob.db` in desktop mode
(alongside the run database in source mode). The database rejects unsupported
future versions. Secret fields and available named-profile values are redacted
from imported event text. Markup stays inert text. Evidence includes an explicit
redaction flag, original JSONL SHA-256 and original canonical-event SHA-256;
stored structured JSON is labelled sanitised and is not a byte-exact copy of the
source file. Original source bytes are not retained.

Version 1 `namazu-oob-evidence` JSON exports retain boundaries, cases, source
hashes and links. Opening an export creates a separate, retired historical case;
it cannot become a live payload, acquire live receipt links or resume collection.
Imported verification/impact claims are reset to the same unverified observation
classification. Original evidence remains unchanged. Failed writes return a
generic storage error and preserve the previous saved row.

Imports are bounded to 8 MiB, 1,000 JSONL lines per operation, 64 KiB per event and
10,000 events per case. Storage accepts at most 2,000 cases; the list shows the
latest 500 and the evidence panel expands at most 100 records per group while
exports retain all. There is no built-in Interactsh registration, encrypted
session import, collector authentication, live polling, DNS-only payload mode,
arbitrary callback protocol support or automatic vulnerability inference.
Existing optional Nuclei execution continues to disable its automatic Interactsh
integration.

## Local verification

`tests/test_oob.py` uses only local SQLite state and `httpx.MockTransport` for one
explicit request and synthetic collector events. It verifies correlation,
receipt accounting, separate contract identities, scope/rotation invalidation,
retirement/expiry, malformed and partial imports, redaction, historical
roundtrips, future-format refusal and failed-write preservation.

`python tests/desktop_detection_ui.py` exercises the source desktop against an
isolated loopback backend. `--cdp http://127.0.0.1:PORT` attaches to an explicitly
enabled native diagnostic session. It checks offline native campaign planning,
payload insertion, collector import, provenance, redaction and historical
roundtrips at desktop and narrow widths, with zero target requests.
