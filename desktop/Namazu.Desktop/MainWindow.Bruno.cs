using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Namazu.Desktop;

internal sealed partial class MainWindow
{
    private bool sourcePickerInProgress;
    private const long MaximumArchiveBytes = 16 * 1024 * 1024;

    private async Task PickBrunoSourceAsync(bool archive)
    {
        if (!ready || sourcePickerInProgress || closingInProgress || retryInProgress) return;
        sourcePickerInProgress = true;
        int generation = startupGate.Generation;
        string kind = archive ? "archive" : "folder";
        try
        {
            string selected;
            if (archive)
            {
                using var picker = new OpenFileDialog { Title = "Import Bruno workspace or collection ZIP",
                    Filter = "ZIP archive|*.zip", Multiselect = false, CheckFileExists = true };
                if (picker.ShowDialog(this) != DialogResult.OK) { PublishSourceResult(kind, "cancelled"); return; }
                selected = picker.FileName;
            }
            else
            {
                using var picker = new FolderBrowserDialog { Description = "Choose a Bruno workspace or collection folder",
                    UseDescriptionForTitle = true, ShowNewFolderButton = false };
                if (picker.ShowDialog(this) != DialogResult.OK) { PublishSourceResult(kind, "cancelled"); return; }
                selected = picker.SelectedPath;
            }
            if (!CurrentAttempt(generation) || !ready) return;
            using var request = new HttpRequestMessage(HttpMethod.Post, archive ? "api/bruno/sources" : "api/bruno/sources/native");
            if (archive)
            {
                await using var stream = new FileStream(selected, FileMode.Open, FileAccess.Read, FileShare.Read,
                    65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                if (stream.Length > MaximumArchiveBytes) { PublishSourceResult(kind, "failed", code: "archive-too-large"); return; }
                byte[] bytes = new byte[checked((int)stream.Length)];
                await stream.ReadExactlyAsync(bytes);
                if (stream.ReadByte() != -1) { PublishSourceResult(kind, "failed", code: "archive-changed"); return; }
                request.Content = JsonContent.Create(new { zip_base64 = Convert.ToBase64String(bytes), filename = Path.GetFileName(selected) });
            }
            else
            {
                request.Headers.Add("X-Namazu-Native", nativeSecret);
                request.Content = JsonContent.Create(new { root = selected });
            }
            if (!CurrentAttempt(generation) || !ready) return;
            using var response = await api.SendAsync(request);
            if (!response.IsSuccessStatusCode) { PublishSourceResult(kind, "failed", code: "source-start-failed"); return; }
            using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            string? id = result.RootElement.TryGetProperty("id", out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            if (!StartupPolicy.ValidJobId(id)) { PublishSourceResult(kind, "failed", code: "source-response-invalid"); return; }
            if (CurrentAttempt(generation)) PublishSourceResult(kind, "queued", id!);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or HttpRequestException
            or TaskCanceledException or JsonException or InvalidOperationException or COMException)
        {
            if (CurrentAttempt(generation)) PublishSourceResult(kind, "failed", code: "source-start-failed");
        }
        finally { sourcePickerInProgress = false; }
    }

    private void PublishSourceResult(string kind, string status, string jobId = "", string code = "none")
    {
        if (!ready || web.IsDisposed || !WindowChromePolicy.IsAppDocument(web.CoreWebView2?.Source, origin)) return;
        try { web.CoreWebView2!.PostWebMessageAsJson(JsonSerializer.Serialize(new {
            type = "namazu-native-bruno-source", version = 1, kind, status, jobId, code })); }
        catch (Exception error) when (error is InvalidOperationException or COMException) { }
    }
}
