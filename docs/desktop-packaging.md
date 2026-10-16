# Windows desktop package

The Windows x64 package contains a native WinForms window, the pinned WebView2
SDK, a self-contained .NET runtime, Namazu's frozen Python backend, and a Node.js
runtime for the offline Bruno parser. It uses the same request, audit, identity,
workspace and evidence engines as the browser application.

## Open the app

Extract the complete release folder, including `backend`, `runtime` and
`licenses`, and open `Namazu.exe`. Python, Node.js, a .NET SDK and a development
server are not needed on the receiving machine. The Microsoft Edge WebView2
Evergreen Runtime must already be installed; if absent, the app offers to open
Microsoft's official installation page. No runtime installer runs silently.

Data defaults to `%LOCALAPPDATA%\Namazu`. For an isolated local workspace:

```powershell
& '.\Namazu Desktop\Namazu.exe' --state-dir 'C:\Namazu Test Data\Local workspace'
```

Only one instance can own a data directory. Separate directories are independent.
The app does not resume requests or audits after reopening. See
[desktop-capabilities.md](desktop-capabilities.md) for persistence, migration and
feature limits.

The custom header uses WebView2's supported non-client drag regions. Buttons,
inputs and selectors are excluded from dragging. WinForms retains its standard
resizable/minimise/maximise/system-menu styles; a validated message enum exposes
only menu, minimise, maximise/restore, close and the two themes to the exact local
top-level application document. It accepts no file paths, URLs, coordinates,
scripts or process commands. No host objects are enabled. Remote documents and
subframes do not receive this capability. The app's own close command always
passes through the existing active-work cancellation prompt.

Window bounds and theme are stored under `config/window-placement.json` and
fitted to the available monitor work area on restore. Alt+Space opens the Windows
system menu; Ctrl+O opens the unified Import chooser. Windows owns native movement,
resize and snapping. These are implemented capabilities; the new build's actual
hit testing, double-click, snapping, file dialogs and mixed-DPI movement have not
been manually validated while native-window control is stopped. Browser scale
factor tests do not substitute for Windows DPI tests. See the
[current validation record](desktop-header-bruno-validation.md).

## Build from source

Use Windows x64, Python 3.14 x64, Node.js 25.2.1, and PowerShell. The script
bootstraps the repository-local .NET SDK 10.0.402 from Microsoft's official
distribution and verifies its SHA512 before extraction. Python dependencies
are pinned in `desktop/requirements-build.lock.txt`; the WebView2 SDK is pinned
in the NuGet lock file.

```powershell
python -m venv .venv
.\scripts\build-desktop.ps1 -InstallDependencies -OutputPath 'C:\Builds\Namazu Desktop'
```

The output directory must be new. Existing releases are preserved. The script
checks installed dependency versions, publishes the native runtime, freezes
the backend/static resources, copies Node and license notices, and writes a ZIP.
`-Python` selects a different Python virtual environment and `-SkipArchive`
omits the ZIP during local QA. Packaging does not scan any target.

`build-manifest.json` records versions and source revision.
`content-manifest.json` records SHA256 hashes of shipped source inputs and every
artifact file except the manifest itself. A source change during the build
rejects that candidate as a final release; rebuild from the finished source.
The manifests identify an artifact but are not a publisher signature. Builds
are currently unsigned, and there is no installer, updater or SmartScreen
reputation claim. Reproduction uses pinned inputs; ZIP timestamps are not
claimed to be byte-for-byte deterministic.

## Local checks

```powershell
$env:NAMAZU_PACKAGED_BACKEND = 'C:\Builds\Namazu Desktop\backend\Namazu.Backend.exe'
.venv\Scripts\python.exe -m pytest tests/test_desktop_host.py -q
```

These checks remove developer tools from the packaged child process's PATH,
exercise private loopback authentication, duplicate-instance refusal, clean
shutdown, owner-pipe shutdown, active-audit cancellation, interrupted audit
recovery without replay, offline Bruno parsing and bundled Schemathesis help.
They do not run an external scanner or establish API security coverage.

For explicit local UI automation only, `--diagnostic-port 9228` opens Chromium
DevTools on loopback and shows a diagnostic-session label. Do not use that mode
with real credentials. Normal launches have DevTools and remote debugging
disabled. The private API session capability remains native and is never
embedded in page JavaScript, browser storage, URLs or command-line arguments.

## Process and navigation boundary

The native window starts one loopback backend on an ephemeral port. A random
per-launch capability crosses a private stdin pipe; the backend returns only
its address and process/data-directory metadata. Native request interception
adds the session header only to that exact origin. The app blocks remote
top-level navigation, denies WebView permissions, and offers a confirmation
before a user-requested external site opens in the default browser. OAuth's
external callback is restricted to a pending random state; collected tokens
remain behind the private session API.

Closing checks active ordinary requests and audits. The close prompt defaults
to keeping the window open; stopping work cancels future dispatch, permits a
bounded settling interval for already-sent exchanges, flushes UI state, and
closes the owned backend. A Windows job object terminates only owned backend
children if the shell dies. Interrupted work remains interrupted on recovery.
The application does not stop processes by image name or sweep unrelated ports.

Schemathesis is bundled and starts through the packaged backend. Optional
Nuclei and ZAP integrations retain their own installation/service requirements.
Linux and macOS native packages are not implemented.
