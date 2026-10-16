namespace Namazu.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.ThreadException += (_, e) => MessageBox.Show(
            "Namazu encountered a desktop error. Your saved workspace remains available.\n\n" + e.Exception.GetType().Name,
            "Namazu", MessageBoxButtons.OK, MessageBoxIcon.Error);
        using var window = new MainWindow(args);
        Application.Run(window);
    }
}
