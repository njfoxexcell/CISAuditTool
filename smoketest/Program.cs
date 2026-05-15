using CISAudit.Core.Audit;
using CISAudit.Core.Models;
using CISAudit.Reporting;

// Tiny CLI runner — same code path the WPF app uses, minus the UI.
var profiles = args.Length > 0 ? args[0].Split(',') : new[] { "L1", "L2", "BL", "NG" };
Console.WriteLine($"Profiles: {string.Join(", ", profiles)}");

var all = AuditEngine.LoadCatalogFromEmbedded();
Console.WriteLine($"Catalog: {all.Count} controls");

var selected = all.Where(c => c.Profiles.Any(p => profiles.Contains(p, StringComparer.OrdinalIgnoreCase))).ToList();
Console.WriteLine($"Selected: {selected.Count} controls");

var engine = new AuditEngine();
var progress = new Progress<ProgressUpdate>(u =>
{
    if (u.Completed % 25 == 0 || u.Completed == u.Total)
        Console.WriteLine($"  [{u.Completed,4}/{u.Total}] {u.CurrentControlId}");
});

var report = engine.Run(selected, progress);

Console.WriteLine();
Console.WriteLine($"Score: {report.ScorePercent:F1}%  ({report.Passed}/{report.ScoredTotal})");
Console.WriteLine($"  Pass:    {report.Passed}");
Console.WriteLine($"  Fail:    {report.Failed}");
Console.WriteLine($"  Manual:  {report.Manual}");
Console.WriteLine($"  Error:   {report.Errored}");
Console.WriteLine($"  N/A:     {report.NotApplicable}");

var outDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                          "CISAuditTool", "Reports");
Directory.CreateDirectory(outDir);
var outPath = Path.Combine(outDir, $"CISAudit_smoke_{DateTime.Now:yyyyMMdd-HHmmss}.html");
HtmlReportWriter.Write(outPath, report, profiles);
Console.WriteLine();
Console.WriteLine($"Report: {outPath}");
