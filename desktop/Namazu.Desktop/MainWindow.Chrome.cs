using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Namazu.Desktop;

internal sealed partial class MainWindow
{
    private readonly ContextMenuStrip desktopMenu = new() { ShowImageMargin = false };
    private readonly Panel fallbackChrome = new() { Dock = DockStyle.Top, Height = 48 };
    private readonly ToolStripMenuItem placementWarning = new() { Enabled = false, Visible = false };
    private readonly System.Windows.Forms.Timer placementTimer = new() { Interval = 600 };
    private WindowPlacementStore placementStore = null!;
    private WindowPlacement? lastPlacement;
    private bool placementReady, windowActive = true;
    private string chromeTheme = "dark";

    private void InitializeChrome()
    {
        // Keep the standard resizable, minimizable, maximizable window styles.
        // WM_NCCALCSIZE below removes only the caption's vertical reservation.
        // Windows still owns the resize border, system menu and snap commands.
        FormBorderStyle = FormBorderStyle.Sizable;
        placementStore = new WindowPlacementStore(Path.Combine(dataRoot, "config", "window-placement.json"));
        lastPlacement = placementStore.Load();
        chromeTheme = lastPlacement?.Theme ?? "dark";
        desktopMenu.Items.Add("Import...", null, async (_, _) => await RunFrontendCommand("window.NamazuDesktop?.openImport?.()"));
        desktopMenu.Items.Add("Open workspace folder", null, (_, _) => OpenDataFolder());
        desktopMenu.Items.Add("Save workspace screenshot...", null, async (_, _) => await CaptureAsync());
        desktopMenu.Items.Add(new ToolStripSeparator());
        desktopMenu.Items.Add("Settings", null, async (_, _) => await RunFrontendCommand("window.NamazuDesktop?.openExpert?.('settings')"));
        desktopMenu.Items.Add("About Namazu", null, (_, _) => MessageBox.Show(this,
            "Namazu\nLocal API security workbench\n\nContracts, request work and evidence stay in your workspace.\nDesktop preview 0.1.0 - Windows x64\n\nExternal tools retain their own installation requirements.",
            "About Namazu", MessageBoxButtons.OK, MessageBoxIcon.Information));
        desktopMenu.Items.Add("Startup details", null, (_, _) => ShowStartupDetails());
        if (diagnosticPort is not null)
        {
            desktopMenu.Items.Add(new ToolStripSeparator());
            desktopMenu.Items.Add(new ToolStripMenuItem("Diagnostic session - loopback only") { Enabled = false });
        }
        desktopMenu.Items.Add(new ToolStripSeparator());
        desktopMenu.Items.Add("Exit", null, (_, _) => Close());
        desktopMenu.Items.Add(placementWarning);

        // The loading/error state also needs usable controls, before a web
        // document exists. This native row disappears when the app header loads.
        var title = new Label { Text = "NAMAZU", AutoSize = false, Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(14, 0, 0, 0), Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        title.MouseDown += (_, e) => {
            if (e.Button == MouseButtons.Left) { ReleaseCapture(); SendMessage(Handle, 0x00A1, 2, 0); }
            else if (e.Button == MouseButtons.Right) ShowSystemMenu();
        };
        title.DoubleClick += (_, _) => ToggleMaximize();
        fallbackChrome.Controls.Add(title);
        AddFallbackButton("Application menu", "\u22ef", (_, _) => ShowDesktopMenu());
        AddFallbackButton("Minimize", "\u2212", (_, _) => WindowState = FormWindowState.Minimized);
        AddFallbackButton("Maximize or restore", "\u25a1", (_, _) => ToggleMaximize());
        AddFallbackButton("Close", "\u00d7", (_, _) => Close());
        Controls.Add(fallbackChrome);
        fallbackChrome.BringToFront();
        ApplyChromeTheme(chromeTheme);

        placementTimer.Tick += (_, _) => { placementTimer.Stop(); SaveWindowPlacement(); };
        Load += (_, _) => RestoreWindowPlacement();
        Move += (_, _) => QueuePlacementSave();
        Resize += (_, _) => { PublishChromeState(); QueuePlacementSave(); };
        DpiChanged += (_, _) => { ApplyChromeTheme(chromeTheme); PublishChromeState(); QueuePlacementSave(); };
        Activated += (_, _) => { windowActive = true; PublishChromeState(); };
        Deactivate += (_, _) => { windowActive = false; PublishChromeState(); };
        FormClosed += (_, _) => { placementTimer.Dispose(); desktopMenu.Dispose(); };
        web.KeyDown += (_, e) => {
            if (e.Alt && e.KeyCode == Keys.Space) { e.Handled = true; e.SuppressKeyPress = true; ShowSystemMenu(); }
        };
    }

    private void AddFallbackButton(string name, string text, EventHandler click)
    {
        var button = new Button { Text = text, AccessibleName = name, Dock = DockStyle.Right, Width = 46,
            FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 12), TabStop = true };
        button.FlatAppearance.BorderSize = 0;
        button.Click += click;
        fallbackChrome.Controls.Add(button);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyChromeTheme(chromeTheme);
    }

    protected override void WndProc(ref Message message)
    {
        const int WmNcCalcSize = 0x0083;
        if (message.Msg == WmNcCalcSize && message.WParam != 0)
        {
            var original = Marshal.PtrToStructure<NativeRect>(message.LParam);
            base.WndProc(ref message);
            var client = Marshal.PtrToStructure<NativeRect>(message.LParam);
            int dpi = (int)GetDpiForWindow(Handle);
            if (dpi == 0) dpi = 96;
            int resizeBorder = GetSystemMetricsForDpi(33, (uint)dpi) + GetSystemMetricsForDpi(92, (uint)dpi);
            client.Top = original.Top + resizeBorder;
            Marshal.StructureToPtr(client, message.LParam, false);
            message.Result = 0;
            return;
        }
        base.WndProc(ref message);
    }

    protected override bool ProcessCmdKey(ref Message message, Keys keyData)
    {
        if (keyData == (Keys.Alt | Keys.Space)) { ShowSystemMenu(); return true; }
        if (keyData == (Keys.Control | Keys.O)) { _ = RunFrontendCommand("window.NamazuDesktop?.openImport?.()"); return true; }
        return base.ProcessCmdKey(ref message, keyData);
    }

    private async Task RunFrontendCommand(string script)
    {
        if (!ready || !WindowChromePolicy.IsAppDocument(web.CoreWebView2?.Source, origin)) return;
        try { await web.ExecuteScriptAsync(script); }
        catch (Exception ex) when (ex is InvalidOperationException or COMException) { }
    }

    private void HandleWindowMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (closingInProgress || !WindowChromePolicy.TryReadAction(e.WebMessageAsJson, e.Source,
            web.CoreWebView2.Source, origin, out string action)) return;
        switch (action)
        {
            case "menu": ShowDesktopMenu(); break;
            case "minimize": WindowState = FormWindowState.Minimized; break;
            case "maximize": ToggleMaximize(); break;
            case "close": Close(); break; // Always uses the existing active-work close flow.
            case "theme-light": ApplyChromeTheme("light"); QueuePlacementSave(); break;
            case "theme-dark": ApplyChromeTheme("dark"); QueuePlacementSave(); break;
            case "pick-bruno-folder": _ = PickBrunoSourceAsync(archive: false); break;
            case "pick-bruno-archive": _ = PickBrunoSourceAsync(archive: true); break;
        }
    }

    private object ChromeState() => new { maximized = WindowState == FormWindowState.Maximized,
        active = windowActive, dpi = DeviceDpi, diagnostic = diagnosticPort is not null,
        placementWarning = placementStore?.Warning ?? "" };

    private void PublishChromeState()
    {
        if (!ready || web.IsDisposed || !WindowChromePolicy.IsAppDocument(web.CoreWebView2?.Source, origin)) return;
        try { web.CoreWebView2!.PostWebMessageAsJson(JsonSerializer.Serialize(new { type = "namazu-native-state", version = 1, state = ChromeState() })); }
        catch (Exception ex) when (ex is InvalidOperationException or COMException) { }
    }

    private void ToggleMaximize() => WindowState = WindowState == FormWindowState.Maximized
        ? FormWindowState.Normal : FormWindowState.Maximized;

    private void ShowDesktopMenu()
    {
        desktopMenu.Items[0].Enabled = ready;
        desktopMenu.Items[2].Enabled = ready;
        desktopMenu.Items[4].Enabled = ready;
        placementWarning.Text = placementStore.Warning;
        placementWarning.Visible = placementWarning.Text.Length > 0;
        int height = (int)Math.Round(48 * DeviceDpi / 96d);
        int captionWidth = (int)Math.Round(138 * DeviceDpi / 96d);
        desktopMenu.Show(this, new Point(Math.Max(0, ClientSize.Width - captionWidth - 8), height), ToolStripDropDownDirection.BelowLeft);
    }

    private void ShowSystemMenu()
    {
        if (!IsHandleCreated) return;
        // The standard Windows menu and SC_* processing preserve keyboard move,
        // size, minimize, maximize and Alt+F4, including the audit-close guard.
        SendMessage(Handle, 0x0112, 0xF100, 0x20);
    }

    private void ShowLoadingChrome()
    {
        loading.Visible = true;
        loading.BringToFront();
        fallbackChrome.Visible = true;
        fallbackChrome.BringToFront();
        if (startupActions.Visible) startupActions.BringToFront();
    }

    private void ApplyChromeTheme(string theme)
    {
        chromeTheme = theme;
        bool dark = theme == "dark";
        Color background = dark ? Color.FromArgb(30, 32, 35) : Color.FromArgb(250, 250, 248);
        Color foreground = dark ? Color.FromArgb(232, 233, 235) : Color.FromArgb(34, 37, 35);
        BackColor = loading.BackColor = fallbackChrome.BackColor = desktopMenu.BackColor = background;
        ForeColor = loading.ForeColor = fallbackChrome.ForeColor = desktopMenu.ForeColor = foreground;
        if (startupActions is not null) { startupActions.BackColor = background; startupActions.ForeColor = foreground; }
        if (!web.IsDisposed) web.DefaultBackgroundColor = background;
        foreach (ToolStripItem item in desktopMenu.Items) { item.BackColor = background; item.ForeColor = foreground; }
        if (!IsHandleCreated) return;
        int darkValue = dark ? 1 : 0;
        int border = ColorTranslator.ToWin32(dark ? Color.FromArgb(59, 62, 67) : Color.FromArgb(201, 204, 199));
        // Unsupported DWM color attributes on older Windows safely return an HRESULT.
        _ = DwmSetWindowAttribute(Handle, 20, ref darkValue, sizeof(int));
        _ = DwmSetWindowAttribute(Handle, 34, ref border, sizeof(int));
    }

    private void RestoreWindowPlacement()
    {
        if (!ownsInstance) return;
        if (lastPlacement is { } saved)
        {
            var screen = Screen.AllScreens.FirstOrDefault(s => s.DeviceName == saved.Monitor)
                ?? Screen.FromRectangle(new Rectangle(saved.X, saved.Y, saved.Width, saved.Height));
            StartPosition = FormStartPosition.Manual;
            // Move the existing (not yet shown) HWND onto the chosen monitor,
            // then use that window's actual per-monitor DPI for the final fit.
            Bounds = WindowPlacementLogic.Fit(saved, screen.WorkingArea, saved.Dpi);
            int dpi = (int)GetDpiForWindow(Handle);
            if (dpi == 0) dpi = DeviceDpi;
            Bounds = WindowPlacementLogic.Fit(saved, screen.WorkingArea, dpi);
            lastPlacement = saved with { X = Left, Y = Top, Width = Width, Height = Height, Dpi = dpi,
                WorkX = screen.WorkingArea.X, WorkY = screen.WorkingArea.Y, Monitor = screen.DeviceName };
            if (saved.Maximized) WindowState = FormWindowState.Maximized;
        }
        placementReady = true;
        QueuePlacementSave();
    }

    private void QueuePlacementSave()
    {
        if (!placementReady || !ownsInstance || closingApproved) return;
        CaptureWindowPlacement();
        placementTimer.Stop();
        placementTimer.Start();
    }

    private void SaveWindowPlacement()
    {
        if (!placementReady || !ownsInstance) return;
        CaptureWindowPlacement();
        if (lastPlacement is not null && !placementStore.Save(lastPlacement)) PublishChromeState();
    }

    private void CaptureWindowPlacement()
    {
        if (WindowState == FormWindowState.Normal)
        {
            var screen = Screen.FromRectangle(Bounds);
            lastPlacement = new WindowPlacement(1, Left, Top, Width, Height, DeviceDpi,
                screen.WorkingArea.X, screen.WorkingArea.Y, screen.DeviceName, false, chromeTheme);
        }
        else if (lastPlacement is not null)
        {
            lastPlacement = lastPlacement with { Maximized = WindowState == FormWindowState.Maximized
                || (WindowState == FormWindowState.Minimized && lastPlacement.Maximized), Theme = chromeTheme };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect { internal int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(nint window);
    [DllImport("user32.dll")] private static extern int GetSystemMetricsForDpi(int index, uint dpi);
    [DllImport("user32.dll")] private static extern nint SendMessage(nint window, uint message, nint wParam, nint lParam);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ReleaseCapture();
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(nint window, uint attribute, ref int value, int size);
}
