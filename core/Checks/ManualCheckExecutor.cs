using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

public sealed class ManualCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.Manual;
    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx) => new()
    {
        ControlId = def.Id,
        Status = CheckStatus.ManualReview,
        Detail = "Requires manual review per CIS benchmark — no automated check defined."
    };
}

public sealed class WindowsFeatureCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.WindowsFeature;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var p = def.Parameters;
        if (!p.TryGetValue("featureName", out var feature))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = "feature check missing 'featureName'" };
        }
        var expected = p.GetValueOrDefault("expected", "Disabled");
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "root\\cimv2",
                $"SELECT InstallState FROM Win32_OptionalFeature WHERE Name='{feature.Replace("'", "''")}'");
            using var r = searcher.Get();
            string actual = "NotInstalled";
            foreach (System.Management.ManagementBaseObject row in r)
            {
                // 1=Enabled, 2=Disabled, 3=Absent, 4=Unknown
                var state = (int)(uint)(row["InstallState"] ?? 4u);
                actual = state switch { 1 => "Enabled", 2 => "Disabled", 3 => "Absent", _ => "Unknown" };
            }
            var allowed = expected.Split('|').Select(s => s.Trim()).ToArray();
            // Treat "Disabled" and "Absent" as equivalent for CIS "should be disabled" guidance.
            bool pass = allowed.Any(a => string.Equals(a, actual, StringComparison.OrdinalIgnoreCase))
                || (allowed.Contains("Disabled", StringComparer.OrdinalIgnoreCase) && actual == "Absent");
            return new CheckResult
            {
                ControlId = def.Id,
                Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
                ExpectedValue = def.ExpectedDisplay ?? expected,
                ActualValue = actual,
                Evidence = $"Win32_OptionalFeature['{feature}']"
            };
        }
        catch (Exception ex)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = ex.Message };
        }
    }
}
