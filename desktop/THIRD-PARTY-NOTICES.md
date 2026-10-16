# Namazu desktop third-party components

Namazu is licensed under the included MIT LICENSE. The release includes license
and notice files for the Python interpreter, pinned Python dependencies, Node.js,
.NET runtime, Microsoft WebView2 SDK, and the bundled Bruno parser.

- Python 3.14: Python Software Foundation license; see `licenses/python`.
- Python packages: exact names, versions, and included notice paths appear in
  `licenses/python-dependencies.json` and their package directories.
- Node.js 25.2.1: Node.js and bundled dependencies' license notices are included
  in `licenses/node/LICENSE`.
- .NET 10: Microsoft .NET distribution notices ship in `licenses/dotnet`;
  source and licensing: https://github.com/dotnet/runtime.
- Microsoft.Web.WebView2 1.0.4258.31: Microsoft WebView2 SDK redistribution terms
  accompany the package. The Evergreen WebView2 Runtime is an independently
  installed Microsoft component, updated by Microsoft; it is not bundled here.
- `@usebruno/lang` 0.40.0: parser only; bundled parser notices are included in
  `licenses/bruno`. Imported collection scripts are not executed.

Optional external scanners remain separate installations and retain their own
licenses. Building the package does not execute external scanners.
