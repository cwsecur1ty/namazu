using System.Drawing;
using System.Text.Json;

namespace Namazu.Desktop;

internal sealed record WindowPlacement(int Version, int X, int Y, int Width, int Height, int Dpi,
    int WorkX, int WorkY, string Monitor, bool Maximized, string Theme)
{
    internal bool IsValid => Version == 1 && Width is >= 200 and <= 32768 && Height is >= 200 and <= 32768
        && X is >= -131072 and <= 131072 && Y is >= -131072 and <= 131072
        && WorkX is >= -131072 and <= 131072 && WorkY is >= -131072 and <= 131072
        && Dpi is >= 48 and <= 768 && Monitor is { Length: <= 128 } && Theme is "light" or "dark";
}

internal static class WindowPlacementLogic
{
    internal const int MinimumLogicalSize = 540;

    internal static Rectangle Fit(WindowPlacement saved, Rectangle workArea, int currentDpi)
    {
        if (!saved.IsValid || workArea.Width <= 0 || workArea.Height <= 0) throw new ArgumentException("Invalid window placement");
        currentDpi = Math.Clamp(currentDpi, 48, 768);
        double scale = (double)currentDpi / saved.Dpi;
        int minimum = (int)Math.Round(MinimumLogicalSize * currentDpi / 96d);
        int width = Math.Clamp((int)Math.Round(saved.Width * scale), Math.Min(minimum, workArea.Width), workArea.Width);
        int height = Math.Clamp((int)Math.Round(saved.Height * scale), Math.Min(minimum, workArea.Height), workArea.Height);
        int x = workArea.Left + (int)Math.Round((saved.X - saved.WorkX) * scale);
        int y = workArea.Top + (int)Math.Round((saved.Y - saved.WorkY) * scale);
        return new Rectangle(Math.Clamp(x, workArea.Left, workArea.Right - width),
            Math.Clamp(y, workArea.Top, workArea.Bottom - height), width, height);
    }
}

internal sealed class WindowPlacementStore(string path)
{
    private bool readOnly;
    private bool preserveOriginal;
    internal string Warning { get; private set; } = "";
    internal WindowPlacement? Load()
    {
        try
        {
            if (!File.Exists(path)) return null;
            if (new FileInfo(path).Length > 16384) { CannotRestore(); return null; }
            var value = JsonSerializer.Deserialize<WindowPlacement>(File.ReadAllText(path));
            if (value is { Version: > 1 })
            {
                readOnly = true;
                Warning = "Saved window placement is from a newer version. It will not be overwritten.";
            }
            else if (value is not { IsValid: true }) CannotRestore();
            return value is { IsValid: true } ? value : null;
        }
        catch (JsonException) { CannotRestore(); return null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            readOnly = true;
            Warning = "Saved window placement could not be read. Default bounds are in use; the existing file will not be overwritten.";
            return null;
        }
    }

    private void CannotRestore()
    {
        preserveOriginal = true;
        Warning = "Saved window placement could not be restored. Default bounds are in use; the original will be retained as a recovery backup.";
    }

    internal bool Save(WindowPlacement value)
    {
        if (readOnly || !value.IsValid) return false;
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            // The temporary file is in the same directory/volume. Readers see
            // either complete version, including if the process is interrupted.
            if (File.Exists(path))
            {
                string backup = preserveOriginal ? path + ".recovery-" + Guid.NewGuid().ToString("N") + ".bak" : path + ".bak";
                File.Replace(temporary, path, backup);
                preserveOriginal = false;
            }
            else File.Move(temporary, path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Warning = "Window placement could not be saved. Existing saved state has been retained.";
            return false;
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
