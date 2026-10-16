# Real Bruno interoperability fixture

`report.json` and `omitted.json` were produced by the pinned, installed
`@usebruno/cli@4.2.1`, using `@usebruno/lang@0.40.0`, against an owned loopback
mock. They are not hand-written examples of a presumed reporter format.
`provenance.json` records commands, source/output hashes, normalization and counts.

The collection has 36 definitions. Each report runs two iterations: 72 logical
executions, 70 HTTP responses and two timeouts. The separate mock receipt ledgers
record 72 actual target attempts for each run. That independent fixture count
must not be inferred from a production Bruno report: its exact wire-attempt
count remains unknown, including possible redirects or retries.

The corpus covers nested folders and duplicate request names, static environment
and request variables, disabled overrides, inherited and per-request bearer
authentication, explicit no-auth, unresolved variables, object and scalar JSON,
escaped strings, Unicode, spaces, text, XML, form data, a local file, multipart,
GraphQL, successful/failed assertions, failed script tests, application denials,
field validation, an explicit edge-block page, timeouts and omitted evidence.
Credentials and upload content are inert synthetic fixture values.

`25-empty-text.bru` intentionally captures an official grammar boundary: an
empty text block followed by assertions is interpreted as nonempty literal text
by the pinned parser. `33-empty-text-mode.bru` supplies the genuine zero-byte
text-mode request. Tests must keep those cases distinct rather than silently
describe the first as an empty body.

Files under `negative/` are explicitly hand-authored malformed or unsupported
inputs. They are never executed and are not labelled CLI-generated evidence.
The file and multipart definitions refer only to `assets/local payload.txt`.
Namazu's importer does not read that referenced file or execute scripts.

From the Namazu repository root:

```powershell
.venv\Scripts\python.exe tests/bruno_comprehensive_fixture.py --cli PATH\TO\@usebruno\cli\bin\bru.js
.venv\Scripts\python.exe -m pytest tests/test_bruno_comprehensive.py
.venv\Scripts\python.exe -m tests.bruno_comprehensive_roundtrip --cli PATH\TO\@usebruno\cli\bin\bru.js
python tests/bruno_workbench_ui.py --backend "dist\Namazu Desktop Header Bruno\backend\Namazu.Backend.exe" --output .local-reports/bruno-packaged-headless
```

The browser journey uses headless Chromium and the packaged backend/static
resources when `--backend` is supplied. It does not control the native window,
inject a native bridge or open operating-system file dialogs. These checks
establish interoperability and product boundaries, not API security coverage.
