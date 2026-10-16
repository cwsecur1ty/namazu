using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Namazu.Desktop;

internal sealed partial class MainWindow : Form
{
    private WebView2 web = new() { Dock = DockStyle.Fill, DefaultBackgroundColor = Color.FromArgb(245, 246, 248) };
    private readonly Label loading = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter,
        Text = "NAMAZU\n\nOpening your workspace…", Font = new Font("Segoe UI", 16), ForeColor = Color.FromArgb(44, 58, 76) };
    private HttpClient api = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private readonly string dataRoot;
    private readonly int? diagnosticPort;
    private Process? backend;
    private OwnedProcessJob? job;
    private Uri? origin;
    private bool closingApproved, closingInProgress, ready;
    private Mutex? instanceMutex;
    private bool ownsInstance;

    internal MainWindow(string[] args)
    {
        Text = "Namazu - API workbench";
        Icon = SystemIcons.Application;
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(1440, 950);
        MinimumSize = new Size(540, 540);
        BackColor = Color.FromArgb(245, 246, 248);
        AutoScaleMode = AutoScaleMode.Dpi;
        dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Namazu");
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--state-dir" && i + 1 < args.Length) dataRoot = Path.GetFullPath(args[++i]);
            else if (args[i] == "--diagnostic-port" && i + 1 < args.Length && int.TryParse(args[++i], out int port) && port is >= 1024 and <= 65535)
                diagnosticPort = port;
        }
        string instanceKey = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            Path.GetFullPath(dataRoot).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant())));
        instanceMutex = new Mutex(true, "Local\\Namazu-" + instanceKey, out ownsInstance);
        Controls.Add(web);
        Controls.Add(loading);
        InitializeChrome();
        InitializeStartup();
        Shown += async (_, _) => {
            if (!ownsInstance) {
                MessageBox.Show(this, "This Namazu workspace is already open. Switch to its existing window.\n\nUse a separate --state-dir only when you need an independent workspace store.",
                    "Namazu is already open", MessageBoxButtons.OK, MessageBoxIcon.Information);
                closingApproved = true; Close(); return;
            }
            await StartAsync();
        };
        FormClosing += HandleClosing;
        FormClosed += (_, _) => Cleanup();
    }

    private bool IsLocal(string value) => origin is not null && Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == origin.Scheme && uri.Host == origin.Host && uri.Port == origin.Port && string.IsNullOrEmpty(uri.UserInfo);

    private void ConfirmExternal(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo)) return;
        if (MessageBox.Show(this, $"Open this external site in your default browser?\n\n{uri.Host}\n\nNamazu's private session is not sent to it.",
            "Open external site", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) OpenExternal(uri.AbsoluteUri);
    }
    private static void OpenExternal(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    private void OpenDataFolder()
    {
        Directory.CreateDirectory(dataRoot);
        var start = new ProcessStartInfo("explorer.exe") { UseShellExecute = true };
        start.ArgumentList.Add(dataRoot); Process.Start(start);
    }
    private async Task CaptureAsync()
    {
        if (!ready) return;
        using var dialog = new SaveFileDialog { Title = "Save workspace screenshot", Filter = "PNG image|*.png", FileName = "Namazu workspace.png" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        using var stream = File.Create(dialog.FileName);
        await web.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, stream);
    }

    private async void HandleClosing(object? sender, FormClosingEventArgs e)
    {
        if (closingApproved) return;
        e.Cancel = true;
        if (closingInProgress) return;
        closingInProgress = true;
        try
        {
            int active = await ActiveWorkAsync();
            if (active > 0 && !ConfirmStop()) return;
            startupCancellation?.Cancel();
            if (ready)
            {
                try {
                    await web.ExecuteScriptAsync("window.__namazuCloseFlush='pending';Promise.resolve().then(()=>window.NamazuDesktop?.flush?.()).then(()=>window.__namazuCloseFlush='saved',()=>window.__namazuCloseFlush='failed');")
                        .WaitAsync(TimeSpan.FromSeconds(3));
                    DateTime deadline = DateTime.UtcNow.AddSeconds(4);
                    string result;
                    do {
                        result = await web.ExecuteScriptAsync("window.__namazuCloseFlush").WaitAsync(TimeSpan.FromSeconds(3));
                        if (result == "\"saved\"") break;
                        if (result == "\"failed\"") throw new IOException("Unsaved workspace changes");
                        await Task.Delay(80);
                    } while (DateTime.UtcNow < deadline);
                    if (result != "\"saved\"") throw new IOException("Workspace save timed out");
                } catch {
                    if (MessageBox.Show(this, "The current workspace could not finish saving. Keep Namazu open to retry?", "Unsaved changes",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) return;
                }
            }
            if (origin is not null && backend is { HasExited: false })
            {
                loading.Text = "Closing workspace…\nWaiting briefly for in-flight evidence."; ShowLoadingChrome();
                try { await api.PostAsJsonAsync("api/desktop/shutdown", new { stop_runs = true }); } catch { }
                try { await backend.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(18)); } catch { }
            }
            closingApproved = true;
            SaveWindowPlacement();
            Cleanup();
            Close();
        }
        finally { closingInProgress = false; }
    }

    private bool ConfirmStop(bool retry = false)
    {
        using var dialog = new Form { Text = "Work is still running", FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent, ClientSize = new Size(460, 170), MaximizeBox = false, MinimizeBox = false };
        dialog.Controls.Add(new Label { Text = (retry ? "Stop active work and retry the workspace?" : "Stop active work and close Namazu?") + "\n\nNew requests will stop. Responses already in flight get a brief\nchance to settle; partial evidence is retained.",
            AutoSize = false, Bounds = new Rectangle(22, 20, 420, 90), Font = new Font("Segoe UI", 10) });
        var cancel = new Button { Text = retry ? "Cancel retry" : "Cancel close", DialogResult = DialogResult.Cancel, Bounds = new Rectangle(170, 120, 115, 30) };
        var stop = new Button { Text = retry ? "Stop work and retry" : "Stop work and close", DialogResult = DialogResult.OK, Bounds = new Rectangle(295, 120, 145, 30) };
        dialog.Controls.Add(cancel); dialog.Controls.Add(stop); dialog.AcceptButton = cancel; dialog.CancelButton = cancel;
        return dialog.ShowDialog(this) == DialogResult.OK;
    }

    private void Cleanup()
    {
        ready = false;
        startupCancellation?.Cancel();
        startupGate.Begin();
        CleanupOwnedSession();
        if (ownsInstance) { try { instanceMutex?.ReleaseMutex(); } catch { } ownsInstance = false; }
        instanceMutex?.Dispose(); instanceMutex = null;
    }

    private void CleanupOwnedSession()
    {
        ready = false;
        try { web.Dispose(); } catch { }
        try { backend?.StandardInput.Close(); } catch { }
        job?.Dispose(); job = null;
        try { backend?.Dispose(); } catch { }
        backend = null;
        origin = null;
        api.Dispose();
    }
}
