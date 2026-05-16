using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace CISAudit.App;

public partial class App : Application
{
    /// <summary>
    /// Where crash details get written. Created on first failure.
    /// We always use %LOCALAPPDATA% because the elevated process's CWD is
    /// %SystemRoot%\System32, which is not user-writable.
    /// </summary>
    private static readonly string CrashLogDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     "CISAuditTool", "Logs");

    protected override void OnStartup(StartupEventArgs e)
    {
        // Catch every flavor of unhandled exception so we see *something* instead
        // of WPF disappearing silently.
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            WriteCrash("AppDomain.UnhandledException", args.ExceptionObject as Exception);

        DispatcherUnhandledException += (s, args) =>
        {
            WriteCrash("Dispatcher.UnhandledException", args.Exception);
            args.Handled = true;   // keep the UI alive so the user can see + report it
        };

        TaskScheduler.UnobservedTaskException += (s, args) =>
        {
            WriteCrash("TaskScheduler.UnobservedTaskException", args.Exception);
            args.SetObserved();
        };

        base.OnStartup(e);
    }

    private static void WriteCrash(string source, Exception? ex)
    {
        try
        {
            Directory.CreateDirectory(CrashLogDir);
            var path = Path.Combine(CrashLogDir, $"crash_{DateTime.Now:yyyyMMdd-HHmmss}.log");
            var body =
                $"Source: {source}\n" +
                $"Time:   {DateTime.Now:O}\n" +
                $"OS:     {Environment.OSVersion}\n" +
                $"CLR:    {Environment.Version}\n" +
                $"User:   {Environment.UserName}\n\n" +
                (ex?.ToString() ?? "(no exception object)");
            File.WriteAllText(path, body);
            MessageBox.Show(
                $"CIS Audit Tool hit an unhandled error.\n\n{ex?.GetType().Name}: {ex?.Message}\n\nFull details written to:\n{path}",
                "CIS Audit Tool — error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch
        {
            // Last resort if even logging fails.
            MessageBox.Show(ex?.ToString() ?? "Unknown error", "CIS Audit Tool — fatal", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
