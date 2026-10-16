using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Namazu.Desktop;

internal sealed record FrontendReceipt(string Status, string Code, string BuildId, bool ChecksPassed);

internal static partial class StartupPolicy
{
    internal const string SnapshotScript = "window.NamazuStartup?.snapshot?.() ?? null";
    [GeneratedRegex("\\A(source|namazu-[a-f0-9]{24})\\z")]
    private static partial Regex BuildPattern();
    internal static bool ValidBuild(string? value) => value is not null && BuildPattern().IsMatch(value);
    internal static string SafeBuild(string? value) => ValidBuild(value) ? value! : "unavailable";

    private static readonly HashSet<string> FrontendCodes = ["none", "asset-load-failed", "script-error", "initialization-failed",
        "dependencies-missing", "styles-missing", "controls-unbound", "render-not-visible", "build-id-invalid"];
    internal static readonly HashSet<string> BackendCodes = ["backend-build-identity-missing", "backend-build-identity-invalid",
        "native-backend-build-mismatch", "frontend-manifest-missing", "frontend-manifest-invalid", "backend-frontend-build-mismatch",
        "frontend-manifest-mismatch", "frontend-asset-missing", "frontend-asset-mismatch", "frontend-index-missing",
        "frontend-page-build-mismatch", "frontend-asset-reference-invalid"];
    private static readonly HashSet<string> Assets = ["/", "/static/style.css", "/static/setup.css", "/static/results-ux.css",
        "/static/bruno.css", "/static/workspaces.css", "/static/desktop-workbench.css", "/static/desktop-header.css",
        "/static/desktop-readiness.js", "/static/setup-model.js", "/static/audit-results.js", "/static/audit-results-view.js",
        "/static/assessment-view.js", "/static/readiness.js", "/static/bruno.js", "/static/app.js", "/static/workspaces.js",
        "/static/desktop-model.js", "/static/desktop-testing.js", "/static/desktop-header.js", "/static/desktop-workbench.js"];
    internal static string? AssetRoute(string? value, Uri? origin)
    {
        if (origin is null || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != origin.Scheme
            || uri.Host != origin.Host || uri.Port != origin.Port || uri.UserInfo.Length != 0) return null;
        return Assets.Contains(uri.AbsolutePath) ? uri.AbsolutePath : null;
    }

    internal static bool ValidOrigin(string? value, out Uri? uri)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out uri) && uri.Scheme == "http" && uri.Host == "127.0.0.1"
            && uri.Port > 0 && uri.UserInfo.Length == 0 && uri.AbsolutePath == "/" && uri.Query.Length == 0 && uri.Fragment.Length == 0) return true;
        uri = null;
        return false;
    }

    internal static bool BackendMatches(JsonElement state, string expected)
    {
        return ValidBuild(expected) && state.ValueKind == JsonValueKind.Object
            && state.TryGetProperty("build_id", out var backend) && backend.ValueKind == JsonValueKind.String && backend.GetString() == expected
            && state.TryGetProperty("frontend_build_id", out var frontend) && frontend.ValueKind == JsonValueKind.String && frontend.GetString() == expected
            && state.TryGetProperty("resources_verified", out var verified) && verified.ValueKind == JsonValueKind.True;
    }

    internal static int ActiveWork(JsonElement state)
    {
        if (state.ValueKind != JsonValueKind.Object) return 1;
        long total = 0;
        foreach (string name in new[] { "active_runs", "active_requests", "active_authentications", "active_source_jobs" })
        {
            if (!state.TryGetProperty(name, out var count)) continue;
            if (count.ValueKind != JsonValueKind.Number || !count.TryGetInt32(out int value) || value < 0) return 1;
            total += value;
        }
        // Old status responses must at least identify the original audit counter.
        return state.TryGetProperty("active_runs", out _) ? (int)Math.Min(total, int.MaxValue) : 1;
    }

    internal static bool ValidJobId(string? value) => value is not null && value.Length is > 0 and <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    internal static FrontendReceipt ReadReceipt(string? json)
    {
        if (json is null or "null") return new("loading", "receipt-missing", "unavailable", false);
        if (json.Length > 4096) return new("failed", "receipt-invalid", "unavailable", false);
        try
        {
            using var parsed = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            var root = parsed.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("version", out var version)
                || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out int revision) || revision != 1
                || !root.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("code", out var code) || code.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("buildId", out var build) || build.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("checks", out var checks) || checks.ValueKind != JsonValueKind.Object)
                return new("failed", "receipt-invalid", "unavailable", false);
            string? statusValue = status.GetString(), codeValue = code.GetString();
            string buildId = SafeBuild(build.GetString());
            if (statusValue is not ("ready" or "failed" or "loading") || codeValue is null || !FrontendCodes.Contains(codeValue))
                return new("failed", "receipt-invalid", buildId, false);
            if (buildId == "unavailable") return new("failed", "build-id-invalid", buildId, false);
            bool passed = new[] { "assets", "dependencies", "initialized", "layout", "controls", "view" }
                .All(name => checks.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True);
            if (statusValue == "ready" && (codeValue != "none" || !passed)) return new("failed", "receipt-invalid", buildId, false);
            return new(statusValue, codeValue, buildId, passed);
        }
        catch (JsonException) { return new("failed", "receipt-invalid", "unavailable", false); }
    }

    internal static bool NativeBoundsValid(Rectangle client, Rectangle web, bool visible)
        => visible && client.Width >= 240 && client.Height >= 160 && web.Width >= 240 && web.Height >= 160
            && Rectangle.Intersect(client, web).Width >= 240 && Rectangle.Intersect(client, web).Height >= 160;
}

// Generation checks keep a late navigation or old process exit from reviving a
// failed attempt or overwriting the state of a newer retry.
internal sealed class StartupGate
{
    internal int Generation { get; private set; }
    internal bool Failed { get; private set; }
    internal bool BackendReady { get; set; }
    internal bool NavigationReady { get; set; }
    internal bool Ready { get; private set; }
    internal int Begin() { Generation++; Failed = BackendReady = NavigationReady = Ready = false; return Generation; }
    internal bool Current(int generation) => generation == Generation;
    internal bool Fail(int generation) { if (!Current(generation) || Failed) return false; Failed = true; Ready = false; return true; }
    internal bool TryReady(int generation, FrontendReceipt receipt, string expected, bool nativeBounds)
    {
        if (!Current(generation) || Failed || !BackendReady || !NavigationReady || !nativeBounds || !StartupPolicy.ValidBuild(expected)
            || receipt.Status != "ready" || receipt.Code != "none" || !receipt.ChecksPassed || receipt.BuildId != expected) return false;
        Ready = true;
        return true;
    }
}
