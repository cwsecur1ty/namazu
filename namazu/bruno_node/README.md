# Offline Bruno grammar bridge

`parser.cjs` bundles the official MIT-licensed `@usebruno/lang@0.40.0` v2
request, collection and environment parsers and request/environment serializers.
Namazu does not implement a regular-expression BRU parser. `bridge.cjs` accepts
a bounded JSON stdin protocol and performs syntax conversion only. It imports
no CLI runner and never evaluates uploaded scripts, dynamic expressions or file
references. Node.js 20+ is required; JSON run report import does not use Node.

Reproduce the checked-in bundle from this directory:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --check parser.cjs
```

The lockfile pins parser dependencies and `esbuild@0.25.12`. The bundle includes
Bruno's parser utilities, lodash 4.18.1 and ohm-js 16.6.0. Their unmodified MIT
notices are retained in `BRUNO-LICENSE.txt`, `LODASH-LICENSE.txt` and
`OHM-LICENSE.txt`; esbuild also retains bundled legal comments. Build tooling
and unused parser dependencies are not shipped as executable dependencies.

Official sources consulted:

- https://github.com/usebruno/bruno/tree/main/packages/bruno-lang/v2/src
- https://github.com/usebruno/bruno/tree/main/packages/bruno-cli/src
- https://docs.usebruno.com/bru-cli/run/options
- https://docs.usebruno.com/variables/overview

The CLI report schema is established by actual pinned 4.2.1 output and installed
package source, not by assuming that the repository's moving `main` reporter
matches it. See `tests/fixtures/bruno/provenance.json` and `tests/bruno_fixture.py`.
This integration does not imply Bruno endorsement.
