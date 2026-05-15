using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using CISAudit.Core.Audit;
using CISAudit.Core.Models;
using CISAudit.Reporting;

namespace CISAudit.App;

public partial class MainWindow : Window
{
    private CancellationTokenSource? _cts;
    private string? _lastReportPath;
    private static readonly string ReportsDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CISAuditTool", "Reports");

    public MainWindow()
    {
        InitializeComponent();
        Directory.CreateDirectory(ReportsDir);
        Log($"Output folder: {ReportsDir}");
        Log("Click 'Start Scan' to begin.");
    }

    private void Log(string message)
    {
        var ts = DateTime.Now.ToString("HH:mm:ss");
        LogBox.AppendText($"[{ts}] {message}\n");
        LogBox.ScrollToEnd();
    }

    private void SetBusy(bool busy)
    {
        BtnScan.IsEnabled = !busy;
        CbL1.IsEnabled = !busy;
        CbL2.IsEnabled = !busy;
        CbBL.IsEnabled = !busy;
        CbNG.IsEnabled = !busy;
    }

    private async void BtnScan_Click(object sender, RoutedEventArgs e)
    {
        var selectedProfiles = SelectedProfiles();
        if (selectedProfiles.Count == 0)
        {
            MessageBox.Show(this, "Pick at least one profile.", "No profiles selected",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SetBusy(true);
        BtnOpen.IsEnabled = false;
        Progress.Value = 0;
        LogBox.Clear();
        Log($"Scan starting — profiles: {string.Join(", ", selectedProfiles)}");

        _cts = new CancellationTokenSource();
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var report = await Task.Run(() => RunScan(selectedProfiles, _cts.Token));
            stopwatch.Stop();
            Log($"Scan completed in {stopwatch.Elapsed.TotalSeconds:F1}s.");
            Log($"Score: {report.ScorePercent:F1}%  ({report.Passed}/{report.ScoredTotal} scored checks passed)");
            Log($"Pass={report.Passed}  Fail={report.Failed}  Manual={report.Manual}  Error={report.Errored}  N/A={report.NotApplicable}");

            var fileName = $"CISAudit_{Environment.MachineName}_{DateTime.Now:yyyyMMdd-HHmmss}.html";
            var path = Path.Combine(ReportsDir, fileName);
            HtmlReportWriter.Write(path, report, selectedProfiles);
            _lastReportPath = path;
            BtnOpen.IsEnabled = true;
            Log($"Report saved: {path}");

            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (OperationCanceledException)
        {
            Log("Scan cancelled.");
        }
        catch (Exception ex)
        {
            Log("ERROR: " + ex);
            MessageBox.Show(this, ex.Message, "Scan failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void BtnOpen_Click(object sender, RoutedEventArgs e)
    {
        if (_lastReportPath is not null && File.Exists(_lastReportPath))
            Process.Start(new ProcessStartInfo(_lastReportPath) { UseShellExecute = true });
    }

    private void BtnFolder_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo(ReportsDir) { UseShellExecute = true });
    }

    private List<string> SelectedProfiles()
    {
        var list = new List<string>();
        if (CbL1.IsChecked == true) list.Add("L1");
        if (CbL2.IsChecked == true) list.Add("L2");
        if (CbBL.IsChecked == true) list.Add("BL");
        if (CbNG.IsChecked == true) list.Add("NG");
        return list;
    }

    private AuditReport RunScan(List<string> selectedProfiles, CancellationToken ct)
    {
        var allControls = AuditEngine.LoadCatalogFromEmbedded();
        UiPost(() => Log($"Loaded catalog: {allControls.Count} total controls"));

        var selected = allControls.Where(c => MatchesProfile(c, selectedProfiles)).ToList();
        UiPost(() => Log($"Filtered to selected profiles: {selected.Count} controls"));

        var engine = new AuditEngine();
        var progress = new Progress<ProgressUpdate>(u =>
        {
            Progress.Value = 100.0 * u.Completed / Math.Max(1, u.Total);
            StatusText.Text = $"[{u.Completed}/{u.Total}] {u.CurrentControlId} — {u.Message}";
        });
        return engine.Run(selected, progress, ct);
    }

    private static bool MatchesProfile(ControlDefinition def, List<string> selected) =>
        def.Profiles.Any(p => selected.Contains(p, StringComparer.OrdinalIgnoreCase));

    private void UiPost(Action a) => Dispatcher.BeginInvoke(a, DispatcherPriority.Background);
}
