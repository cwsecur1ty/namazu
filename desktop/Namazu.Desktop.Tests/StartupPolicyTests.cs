using System.Drawing;
using System.Text.Json;
using Namazu.Desktop;

internal static class StartupPolicyTests
{
    internal static void Run(Action<bool, string> check)
    {
        const string build = "namazu-0123456789abcdef01234567";
        var origin = new Uri("http://127.0.0.1:43210/");
        check(StartupPolicy.ValidBuild(build) && StartupPolicy.ValidBuild("source"), "valid build identities");
        foreach (string bad in new[] { "", "namazu-short", "NAMAZU-0123456789abcdef01234567", "source\n", "secret or server text" })
            check(!StartupPolicy.ValidBuild(bad) && StartupPolicy.SafeBuild(bad) == "unavailable", "invalid build is not diagnostic text");
        foreach (string address in new[] { "http://localhost:43210", "https://127.0.0.1:43210", "http://127.0.0.1:43210/api",
            "http://user@127.0.0.1:43210", "http://127.0.0.1:43210/?token=secret", "http://127.0.0.1:43210/#fragment" })
            check(!StartupPolicy.ValidOrigin(address, out _), "reject unsafe handshake origin");
        check(StartupPolicy.ValidOrigin(origin.AbsoluteUri, out var parsed) && parsed == origin, "exact private origin");
        check(StartupPolicy.AssetRoute(origin + "static/app.js?credential=secret", origin) == "/static/app.js", "diagnostic asset route strips query");
        check(StartupPolicy.AssetRoute(origin + "api/proxy?url=private", origin) is null
            && StartupPolicy.AssetRoute("https://target.test/static/app.js", origin) is null, "diagnostics exclude API and target requests");
        using var handshake = JsonDocument.Parse(JsonSerializer.Serialize(new { build_id = build, frontend_build_id = build, resources_verified = true }));
        check(StartupPolicy.BackendMatches(handshake.RootElement, build), "matching backend resources");
        check(!StartupPolicy.BackendMatches(handshake.RootElement, "source"), "stale backend refused");
        using var unverified = JsonDocument.Parse(JsonSerializer.Serialize(new { build_id = build, frontend_build_id = build, resources_verified = false }));
        check(!StartupPolicy.BackendMatches(unverified.RootElement, build), "unverified resources refused");
        string receipt = JsonSerializer.Serialize(new { version = 1, status = "ready", code = "none", buildId = build,
            checks = new { assets = true, dependencies = true, initialized = true, layout = true, controls = true, view = true } });
        var ready = StartupPolicy.ReadReceipt(receipt);
        check(ready.Status == "ready" && ready.ChecksPassed && ready.BuildId == build, "rendered frontend receipt accepted");
        check(StartupPolicy.ReadReceipt(null).Code == "receipt-missing", "missing helper waits for bounded timeout");
        foreach (string bad in new[] { "{", "[]", "1", "{}", new string('x', 4097), receipt.Replace("\"controls\":true", "\"controls\":false"),
            receipt.Replace("\"version\":1", "\"version\":2"), receipt.Replace("\"none\"", "\"private server text\"") })
            check(StartupPolicy.ReadReceipt(bad).Status == "failed", "malformed or incomplete readiness fails closed");
        check(StartupPolicy.ReadReceipt(receipt.Replace(build, "invalid")).Code == "build-id-invalid", "frontend missing build refused");
        var gate = new StartupGate();
        int first = gate.Begin();
        check(!gate.TryReady(first, ready, build, true), "navigation alone is not backend readiness");
        gate.BackendReady = true;
        check(!gate.TryReady(first, ready, build, true), "frontend alone is not navigation completion");
        gate.NavigationReady = true;
        check(!gate.TryReady(first, ready, build, false), "zero native layout cannot hide fallback");
        check(!gate.TryReady(first, ready with { BuildId = "source" }, build, true), "stale frontend cannot hide fallback");
        check(!gate.TryReady(first, ready with { ChecksPassed = false }, build, true), "unbound controls cannot hide fallback");
        check(gate.TryReady(first, ready, build, true) && gate.Ready, "all independent startup conditions required");
        check(gate.Fail(first) && !gate.Ready, "renderer failure revokes readiness");
        check(!gate.TryReady(first, ready, build, true), "late success cannot revive failed renderer");
        int retry = gate.Begin();
        check(!gate.Fail(first) && !gate.TryReady(first, ready, build, true), "old callback cannot affect retry");
        check(!gate.BackendReady && !gate.NavigationReady && !gate.Ready, "retry starts with no inherited readiness");
        gate.BackendReady = gate.NavigationReady = true;
        check(gate.TryReady(retry, ready, build, true), "fresh retry can become ready");
        check(StartupPolicy.NativeBoundsValid(new Rectangle(0, 0, 800, 600), new Rectangle(0, 48, 800, 552), true), "positive native renderer layout");
        check(!StartupPolicy.NativeBoundsValid(new Rectangle(0, 0, 800, 600), new Rectangle(900, 0, 800, 600), true)
            && !StartupPolicy.NativeBoundsValid(new Rectangle(0, 0, 800, 600), new Rectangle(0, 0, 800, 600), false), "invisible or offscreen renderer refused");
        using var active = JsonDocument.Parse("{\"active_runs\":1,\"active_requests\":2,\"active_authentications\":3,\"active_source_jobs\":4}");
        check(StartupPolicy.ActiveWork(active.RootElement) == 10, "close guard includes authentication and source jobs");
        using var unknown = JsonDocument.Parse("{\"active_runs\":-1}");
        check(StartupPolicy.ActiveWork(unknown.RootElement) == 1, "unknown activity requires explicit stop choice");
        check(StartupPolicy.ValidJobId("job-123_abc"), "safe picker job identifier");
        foreach (string bad in new[] { "", "../private", "C:/private", "é", new string('x', 129) })
            check(!StartupPolicy.ValidJobId(bad), "picker never forwards path or arbitrary diagnostic as job id");
    }
}
