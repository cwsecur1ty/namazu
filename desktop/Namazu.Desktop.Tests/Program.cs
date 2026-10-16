using System.Drawing;
using System.Text.Json;
using Namazu.Desktop;

// No Form, HWND, WebView, browser, backend or GUI is created by these tests.
int checks = 0;
void Check(bool condition, string name)
{
    if (!condition) throw new Exception("FAILED: " + name);
    checks++;
}
var origin = new Uri("http://127.0.0.1:43210/");
string source = origin.AbsoluteUri;
string Message(string action) => JsonSerializer.Serialize(new { type = "namazu-window", version = 1, action });
foreach (string action in new[] { "menu", "minimize", "maximize", "close", "theme-light", "theme-dark", "pick-bruno-folder", "pick-bruno-archive" })
    Check(WindowChromePolicy.TryReadAction(Message(action), source, source, origin, out var parsed) && parsed == action, "allowed " + action);
foreach (string document in new[] { "http://localhost:43210/", "http://127.0.0.1:43211/", "https://127.0.0.1:43210/",
    "https://example.test/", source + "api/desktop/status", source + "?untrusted=true", "http://user@127.0.0.1:43210/", "about:blank", "file:///index.html" })
{
    Check(!WindowChromePolicy.TryReadAction(Message("close"), document, source, origin, out _), "reject sender " + document);
    Check(!WindowChromePolicy.TryReadAction(Message("close"), source, document, origin, out _), "reject current " + document);
}
Check(WindowChromePolicy.TryReadAction(Message("menu"), source + "#workspace", source, origin, out _), "same document fragment");
foreach (string message in new[] { "null", "[]", "1", "{", "{\"type\":\"namazu-window\",\"version\":1,\"action\":\"close\",\"path\":\"C:/private\"}",
    "{\"type\":\"namazu-window\",\"version\":1,\"action\":\"close\",\"action\":\"menu\"}",
    "{\"type\":\"namazu-window\",\"version\":\"1\",\"action\":\"close\"}",
    "{\"type\":\"namazu-window\",\"version\":2,\"action\":\"close\"}",
    Message("open-url"), Message("exec"), Message("Close"), Message("theme-system"), new string('x', 257) })
    Check(!WindowChromePolicy.TryReadAction(message, source, source, origin, out _), "reject malformed or broad protocol");
Check(!WindowChromePolicy.TryReadAction(Message("close"), source, source, null, out _), "uninitialized origin");
string script = WindowChromePolicy.Bootstrap(origin, new { maximized = false, active = true, dpi = 144, diagnostic = false });
if (args.Length > 1) File.WriteAllText(Path.GetFullPath(args[1]), script);
Check(script.Contains("window !== window.top") && script.Contains("location.pathname !== '/'") && script.Contains("location.search"), "bootstrap top-document guard");
Check(!script.Contains("session_secret") && !script.Contains("X-Namazu-Session"), "no backend secret in protocol");
Check(!script.Contains("native_secret") && !script.Contains("X-Namazu-Native"), "no native capability in protocol");
StartupPolicyTests.Run(Check);

var saved = new WindowPlacement(1, -1800, 100, 1000, 700, 96, -1920, 0, "LEFT", false, "dark");
Check(saved.IsValid, "negative monitor coordinates valid");
Check(WindowPlacementLogic.Fit(saved, new Rectangle(-1920, 0, 1920, 1040), 96) == new Rectangle(-1800, 100, 1000, 700), "same monitor roundtrip");
Check(WindowPlacementLogic.Fit(saved, new Rectangle(0, 0, 2560, 1400), 144) == new Rectangle(180, 150, 1500, 1050), "DPI size and offset scale");
var fit = WindowPlacementLogic.Fit(saved, new Rectangle(0, 0, 800, 600), 192);
Check(fit == new Rectangle(0, 0, 800, 600), "missing display and small work area clamp");
fit = WindowPlacementLogic.Fit(saved with { X = 100000, Y = -100000 }, new Rectangle(40, 30, 1920, 1000), 96);
Check(fit == new Rectangle(960, 30, 1000, 700), "offscreen coordinates clamped including taskbar inset");
Check(!(saved with { Dpi = 0 }).IsValid && !(saved with { Width = int.MaxValue }).IsValid
    && !(saved with { Theme = "custom" }).IsValid && !(saved with { Version = 2 }).IsValid, "corrupt placement rejected");

string directory = Path.Combine(Path.GetFullPath(args.Length > 0 ? args[0] : "."), "window-placement-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
string path = Path.Combine(directory, "placement.json");
var store = new WindowPlacementStore(path);
Check(store.Load() is null, "new store");
Check(store.Save(saved) && store.Load() == saved, "atomic initial save");
var updated = saved with { Maximized = true, Theme = "light" };
Check(store.Save(updated) && store.Load() == updated, "atomic replacement");
Check(JsonSerializer.Deserialize<WindowPlacement>(File.ReadAllText(path + ".bak")) == saved, "previous placement backup retained");
Check(!Directory.EnumerateFiles(directory, "*.tmp").Any(), "no abandoned temporary file");
File.WriteAllText(path, "{bad json");
Check(store.Load() is null, "corrupt state defaults safely");
Check(store.Save(saved) && store.Load() == saved, "corrupt state replacement remains complete");
string recovery = Directory.GetFiles(directory, "*.recovery-*.bak").Single();
Check(File.ReadAllText(recovery) == "{bad json", "corrupt original retained in recovery backup");
Check(store.Save(updated) && File.ReadAllText(recovery) == "{bad json", "later writes preserve recovery backup");
File.WriteAllText(path, JsonSerializer.Serialize(saved with { Version = 2 }));
var futureStore = new WindowPlacementStore(path);
Check(futureStore.Load() is null && !futureStore.Save(saved), "future placement never overwritten");
Check(JsonSerializer.Deserialize<WindowPlacement>(File.ReadAllText(path))!.Version == 2, "future state preserved");
File.Delete(path);
foreach (string backup in Directory.GetFiles(directory, "*.bak")) File.Delete(backup);
Directory.Delete(directory);
Console.WriteLine($"PASS: {checks} native chrome/startup/picker policy/placement checks; no GUI created.");
