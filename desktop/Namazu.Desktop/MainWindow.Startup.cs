using System.Diagnostics;
using System.Net.Http.Json;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Namazu.Desktop;

internal sealed partial class MainWindow
{
    private readonly StartupGate startupGate = new();
    private readonly FlowLayoutPanel startupActions = new() { Dock = DockStyle.Bottom, Height = 64,
        FlowDirection = FlowDirection.LeftToRight, Padding = new Padding(20, 12, 20, 12), Visible = false };
    private readonly Button startupRetry = new() { Text = "Retry workspace", AutoSize = true, Height = 34 };
    private readonly string nativeSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private readonly string expectedBuild = StartupPolicy.SafeBuild(Assembly.GetExecutingAssembly()
        .GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == "NamazuBuildId")?.Value ?? "source");
    private CancellationTokenSource? startupCancellation;
    private bool retryInProgress;
    private string startupStage = "created", startupCode = "none", backendBuild = "unavailable", frontendBuild = "unavailable";
    private int? backendProcessId;
    private readonly List<object> startupEvents = [];

    private void InitializeStartup()
    {
        startupRetry.Click += async (_, _) => await RetryStartupAsync();
        var diagnostics = new Button { Text = "View startup details", AutoSize = true, Height = 34 };
        diagnostics.Click += (_, _) => ShowStartupDetails();
        startupActions.Controls.Add(startupRetry);
        startupActions.Controls.Add(diagnostics);
        Controls.Add(startupActions);
        ShowLoadingChrome();
    }

    private bool CurrentAttempt(int generation) => startupGate.Current(generation) && !closingApproved && !IsDisposed;

    private void Stage(string value)
    {
        startupStage = value;
        RecordStartup("stage", value);
        loading.Text = "NAMAZU\n\nOpening your workspace…\n\n" + value.Replace('-', ' ');
    }

    private async Task StartAsync()
    {
        startupCancellation?.Dispose();
        startupCancellation = new CancellationTokenSource();
        var cancellation = startupCancellation.Token;
        int generation = startupGate.Begin();
        ready = false;
        startupCode = "none";
        backendBuild = frontendBuild = "unavailable";
        backendProcessId = null;
        startupEvents.Clear();
        startupActions.Visible = false;
        ShowLoadingChrome();
        var view = web; // A retry cannot redirect this attempt onto a different control.
        try
        {
            Stage("runtime-check");
            _ = CoreWebView2Environment.GetAvailableBrowserVersionString();
            Directory.CreateDirectory(dataRoot);
            string executable = Path.Combine(AppContext.BaseDirectory, "backend", "Namazu.Backend.exe");
            if (!File.Exists(executable)) throw new StartupFailure("backend-missing");
            Stage("backend-start");
            job = new OwnedProcessJob();
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = AppContext.BaseDirectory };
            start.ArgumentList.Add("--desktop-host");
            start.ArgumentList.Add("--state-dir");
            start.ArgumentList.Add(dataRoot);
            var process = Process.Start(start) ?? throw new StartupFailure("backend-start-failed");
            backend = process;
            backendProcessId = process.Id;
            try { job.Own(process); }
            catch { try { process.Kill(entireProcessTree: true); } catch { } throw; }
            _ = Task.Run(async () => { try { while (await process.StandardError.ReadLineAsync() is not null) { } } catch { } });
            process.EnableRaisingEvents = true;
            process.Exited += (_, _) => {
                if (!IsHandleCreated || IsDisposed) return;
                try { BeginInvoke(() => { if (CurrentAttempt(generation) && startupGate.BackendReady && !closingInProgress && !retryInProgress)
                    ShowStartupFailure(generation, "backend-exited"); }); } catch (InvalidOperationException) { }
            };
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { session_secret = secret,
                native_secret = nativeSecret, expected_build_id = expectedBuild, parent_pid = Environment.ProcessId }));
            await process.StandardInput.FlushAsync(cancellation);
            Stage("backend-handshake");
            string? line = await process.StandardOutput.ReadLineAsync(cancellation).AsTask().WaitAsync(TimeSpan.FromSeconds(45), cancellation);
            if (line is null || line.Length > 16384) throw new StartupFailure("backend-handshake-invalid");
            using var reply = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 5 });
            var handshake = reply.RootElement;
            if (handshake.ValueKind != JsonValueKind.Object || !handshake.TryGetProperty("ready", out var isReady)
                || isReady.ValueKind != JsonValueKind.True)
            {
                string? code = handshake.ValueKind == JsonValueKind.Object && handshake.TryGetProperty("code", out var value)
                    && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                throw new StartupFailure(code is not null && StartupPolicy.BackendCodes.Contains(code) ? code : "backend-start-failed");
            }
            backendBuild = ReadBuild(handshake, "build_id");
            frontendBuild = ReadBuild(handshake, "frontend_build_id");
            if (!StartupPolicy.BackendMatches(handshake, expectedBuild)) throw new StartupFailure("native-backend-build-mismatch");
            if (!handshake.TryGetProperty("pid", out var pid) || !pid.TryGetInt32(out int reportedPid) || reportedPid != process.Id
                || !handshake.TryGetProperty("origin", out var address) || address.ValueKind != JsonValueKind.String
                || !StartupPolicy.ValidOrigin(address.GetString(), out var privateOrigin)) throw new StartupFailure("backend-handshake-invalid");
            origin = privateOrigin;
            api.BaseAddress = origin;
            api.DefaultRequestHeaders.Add("X-Namazu-Session", secret);
            Stage("backend-health");
            using (var response = await api.GetAsync("api/health", cancellation))
            {
                if (!response.IsSuccessStatusCode) throw new StartupFailure("backend-health-failed");
                using var health = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellation));
                if (!StartupPolicy.BackendMatches(health.RootElement, expectedBuild)) throw new StartupFailure("backend-health-build-mismatch");
            }
            cancellation.ThrowIfCancellationRequested();
            startupGate.BackendReady = true;
            Stage("renderer-initialize");
            Environment.SetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", null);
            Environment.SetEnvironmentVariable("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER", null);
            var options = new CoreWebView2EnvironmentOptions { AdditionalBrowserArguments = diagnosticPort is { } port
                ? $"--remote-debugging-port={port} --remote-debugging-address=127.0.0.1 --disable-features=msEdgeSidebarV2"
                : "--disable-features=msEdgeSidebarV2" };
            var environment = await CoreWebView2Environment.CreateAsync(null, Path.Combine(dataRoot, "cache", "webview"), options)
                .WaitAsync(TimeSpan.FromSeconds(20), cancellation);
            await view.EnsureCoreWebView2Async(environment).WaitAsync(TimeSpan.FromSeconds(25), cancellation);
            cancellation.ThrowIfCancellationRequested();
            var core = view.CoreWebView2;
            core.Settings.AreDevToolsEnabled = diagnosticPort is not null;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.IsWebMessageEnabled = true;
            core.Settings.IsNonClientRegionSupportEnabled = true;
            core.Settings.IsGeneralAutofillEnabled = false;
            core.Settings.IsPasswordAutosaveEnabled = false;
            core.Settings.IsBuiltInErrorPageEnabled = false;
            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            core.WebResourceRequested += (_, e) => {
                // Only the session capability enters browser requests. The native
                // filesystem capability is deliberately stripped even locally.
                e.Request.Headers.RemoveHeader("X-Namazu-Native");
                if (CurrentAttempt(generation) && IsLocal(e.Request.Uri)) e.Request.Headers.SetHeader("X-Namazu-Session", secret);
                else e.Request.Headers.RemoveHeader("X-Namazu-Session");
            };
            var navigation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            core.NavigationStarting += (_, e) => {
                if (!CurrentAttempt(generation)) { e.Cancel = true; return; }
                if (ready && WindowChromePolicy.IsAppDocument(e.Uri, origin)
                    && new Uri(e.Uri).Fragment == new Uri(core.Source).Fragment) {
                    e.Cancel = true; ShowStartupFailure(generation, "document-reload-requested"); return;
                }
                if (WindowChromePolicy.IsAppDocument(e.Uri, origin) || e.Uri == "about:blank") return;
                e.Cancel = true;
                if (e.IsUserInitiated) ConfirmExternal(e.Uri);
            };
            core.NewWindowRequested += (_, e) => { e.Handled = true;
                if (CurrentAttempt(generation) && e.IsUserInitiated) ConfirmExternal(e.Uri); };
            core.FrameNavigationStarting += (_, e) => e.Cancel = true;
            core.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
            core.WebMessageReceived += HandleWindowMessage;
            core.DocumentTitleChanged += (_, _) => { if (CurrentAttempt(generation)) Text = "Namazu · " + core.DocumentTitle; };
            core.ProcessFailed += (_, e) => { if (CurrentAttempt(generation)) {
                RecordStartup("renderer-process-failed", ((int)e.ProcessFailedKind).ToString());
                ShowStartupFailure(generation, "renderer-process-failed");
            } };
            core.WebResourceResponseReceived += (_, e) => {
                if (!CurrentAttempt(generation)) return;
                string? route = StartupPolicy.AssetRoute(e.Request.Uri, origin);
                if (route is null) return;
                int status = e.Response.StatusCode;
                RecordStartup("asset-response", route, status);
                if (status >= 400) ShowStartupFailure(generation, "asset-load-failed");
            };
            core.NavigationCompleted += (_, e) => {
                if (!CurrentAttempt(generation)) return;
                RecordStartup("navigation-completed", e.IsSuccess ? "success" : "failed", (int)e.WebErrorStatus);
                if (!e.IsSuccess) { navigation.TrySetException(new StartupFailure("navigation-failed"));
                    ShowStartupFailure(generation, "navigation-failed"); return; }
                if (WindowChromePolicy.IsAppDocument(core.Source, origin)) {
                    startupGate.NavigationReady = true;
                    navigation.TrySetResult(true);
                }
            };
            await core.AddScriptToExecuteOnDocumentCreatedAsync(WindowChromePolicy.Bootstrap(origin!, ChromeState()))
                .WaitAsync(TimeSpan.FromSeconds(5), cancellation);
            Stage("document-navigation");
            view.Visible = true; // rAF readiness requires a visible, non-zero renderer under the opaque overlay.
            ShowLoadingChrome();
            core.Navigate(origin!.AbsoluteUri);
            await navigation.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellation);
            Stage("frontend-readiness");
            DateTime deadline = DateTime.UtcNow.AddSeconds(30);
            FrontendReceipt receipt = new("loading", "receipt-missing", "unavailable", false);
            while (DateTime.UtcNow < deadline)
            {
                cancellation.ThrowIfCancellationRequested();
                receipt = StartupPolicy.ReadReceipt(await view.ExecuteScriptAsync(StartupPolicy.SnapshotScript)
                    .WaitAsync(TimeSpan.FromSeconds(3), cancellation));
                frontendBuild = receipt.BuildId;
                if (receipt.Status == "failed") throw new StartupFailure(receipt.Code == "none" ? "frontend-initialization-failed" : receipt.Code);
                if (receipt.BuildId != "unavailable" && receipt.BuildId != expectedBuild) throw new StartupFailure("native-frontend-build-mismatch");
                if (startupGate.TryReady(generation, receipt, expectedBuild,
                    StartupPolicy.NativeBoundsValid(ClientRectangle, view.Bounds, view.Visible)))
                {
                    ready = true;
                    Stage("ready");
                    loading.Visible = fallbackChrome.Visible = startupActions.Visible = false;
                    view.BringToFront();
                    PublishChromeState();
                    return;
                }
                await Task.Delay(120, cancellation);
            }
            throw new StartupFailure(receipt.Code == "receipt-missing" ? "frontend-receipt-missing" : "frontend-readiness-timeout");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (WebView2RuntimeNotFoundException) { ShowStartupFailure(generation, "webview-runtime-missing"); }
        catch (StartupFailure error) { ShowStartupFailure(generation, error.Code); }
        catch (TimeoutException) { ShowStartupFailure(generation, "stage-timeout"); }
        catch (OperationCanceledException) { ShowStartupFailure(generation, "stage-timeout"); }
        catch (Exception) { ShowStartupFailure(generation, "stage-failed"); }
    }

    private static string ReadBuild(JsonElement root, string name) => root.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String ? StartupPolicy.SafeBuild(value.GetString()) : "unavailable";

    private void ShowStartupFailure(int generation, string code)
    {
        if (!CurrentAttempt(generation) || !startupGate.Fail(generation)) return;
        ready = false;
        startupCode = code;
        startupCancellation?.Cancel();
        RecordStartup("failure", code);
        string instruction = code == "webview-runtime-missing" ? "Install the Microsoft Edge WebView2 Runtime, then retry."
            : code.Contains("build") || code.Contains("asset") || code.Contains("manifest")
                ? "Re-extract the complete Namazu package into one folder, then retry."
                : "Retry to reopen this workspace. Saved work is retained; requests are not replayed.";
        loading.Text = "Namazu could not finish opening this workspace.\n\n" + instruction + "\n\nStage: " + startupStage
            + "\nCode: " + code + "\nBuild: " + expectedBuild;
        startupActions.Visible = true;
        startupRetry.Enabled = !retryInProgress;
        ShowLoadingChrome();
    }

    private async Task<int> ActiveWorkAsync()
    {
        if (origin is null || backend is not { HasExited: false }) return 0;
        try {
            using var response = await api.GetAsync("api/desktop/status");
            response.EnsureSuccessStatusCode();
            using var state = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return StartupPolicy.ActiveWork(state.RootElement);
        } catch { return 1; } // Unknown work always gets an explicit stop decision.
    }

    private async Task RetryStartupAsync()
    {
        if (retryInProgress || closingInProgress || closingApproved) return;
        retryInProgress = true;
        startupRetry.Enabled = false;
        try
        {
            if (await ActiveWorkAsync() > 0 && !ConfirmStop(retry: true)) return;
            startupCancellation?.Cancel();
            startupGate.Begin();
            if (origin is not null && backend is { HasExited: false }) {
                try { await api.PostAsJsonAsync("api/desktop/shutdown", new { stop_runs = true }); } catch { }
                try { await backend.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(18)); } catch { }
            }
            Controls.Remove(web);
            CleanupOwnedSession(); // Mutex stays held throughout the retry.
            api = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            web = new WebView2 { Dock = DockStyle.Fill, DefaultBackgroundColor = BackColor, Visible = true };
            web.KeyDown += (_, e) => { if (e.Alt && e.KeyCode == Keys.Space) {
                e.Handled = e.SuppressKeyPress = true; ShowSystemMenu(); } };
            Controls.Add(web);
            ShowLoadingChrome();
            await StartAsync();
        }
        finally { retryInProgress = false; startupRetry.Enabled = true; }
    }

    private object StartupDetails() => new { version = 1, native_build_id = expectedBuild, backend_build_id = backendBuild,
        frontend_build_id = frontendBuild, native_pid = Environment.ProcessId, backend_pid = backendProcessId,
        private_origin = origin?.GetLeftPart(UriPartial.Authority), application_directory = AppContext.BaseDirectory,
        workspace_directory = dataRoot, stage = startupStage, code = startupCode,
        client_bounds = new { width = ClientSize.Width, height = ClientSize.Height },
        renderer_bounds = new { x = web.Left, y = web.Top, width = web.Width, height = web.Height, visible = web.Visible },
        events = startupEvents.ToArray() };

    private void RecordStartup(string name, string code, int? status = null)
    {
        if (startupEvents.Count == 64) startupEvents.RemoveAt(0);
        startupEvents.Add(new { time = DateTime.UtcNow.ToString("O"), name, code, status });
        try {
            string directory = Path.Combine(dataRoot, "logs");
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "desktop-startup.json"), JsonSerializer.Serialize(StartupDetails(),
                new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }

    private void ShowStartupDetails()
    {
        string details = JsonSerializer.Serialize(StartupDetails(), new JsonSerializerOptions { WriteIndented = true });
        using var dialog = new Form { Text = "Namazu startup details", StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(720, 520), MinimizeBox = false, MaximizeBox = false };
        var content = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
            WordWrap = false, Text = details, Font = new Font("Consolas", 10) };
        var copy = new Button { Dock = DockStyle.Bottom, Height = 38, Text = "Copy startup details" };
        copy.Click += (_, _) => { try { Clipboard.SetText(details); } catch (ExternalException) { } };
        dialog.Controls.Add(content); dialog.Controls.Add(copy); dialog.ShowDialog(this);
    }

    private sealed class StartupFailure(string code) : Exception
    {
        internal string Code { get; } = code;
    }
}
