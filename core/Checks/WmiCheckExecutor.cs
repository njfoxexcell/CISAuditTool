using System.Diagnostics;
using System.Management;
using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

/// <summary>
/// Generic WMI / CIM check. Used for BitLocker, TPM, Secure Boot — places where
/// the system state is not a single registry value.
///
/// Parameters:
///   namespace : e.g. "root\\cimv2" or "root\\CIMV2\\Security\\MicrosoftTpm"
///   query     : full WQL — must return one column
///   op        : equals | gte | lte | notEmpty | inList | exists
///   expected  : value to compare against
/// </summary>
public sealed class WmiCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.Wmi;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var p = def.Parameters;
        if (!p.TryGetValue("namespace", out var ns) || !p.TryGetValue("query", out var query))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = "wmi check missing 'namespace' or 'query'", Duration = sw.Elapsed };
        }
        var op = p.GetValueOrDefault("op", "equals");
        var expected = p.GetValueOrDefault("expected", "");

        try
        {
            using var searcher = new ManagementObjectSearcher(ns, query);
            using var results = searcher.Get();
            var rows = new List<string>();
            foreach (ManagementBaseObject obj in results)
            {
                foreach (PropertyData pd in obj.Properties)
                {
                    rows.Add(pd.Value?.ToString() ?? "");
                }
            }
            var actual = rows.Count == 0 ? "" : string.Join(",", rows);

            bool pass = op.ToLowerInvariant() switch
            {
                "exists" => rows.Count > 0,
                "notempty" => actual.Length > 0,
                "equals" => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase),
                "inlist" => expected.Split('|').Any(v => v.Trim().Equals(actual, StringComparison.OrdinalIgnoreCase)),
                "gte" => long.TryParse(actual, out var a1) && long.TryParse(expected, out var e1) && a1 >= e1,
                "lte" => long.TryParse(actual, out var a2) && long.TryParse(expected, out var e2) && a2 <= e2,
                _ => false
            };

            return new CheckResult
            {
                ControlId = def.Id,
                Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
                ExpectedValue = def.ExpectedDisplay ?? expected,
                ActualValue = actual.Length == 0 ? "(no rows)" : actual,
                Evidence = $"{ns} :: {query}",
                Duration = sw.Elapsed
            };
        }
        catch (Exception ex)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = ex.Message, Duration = sw.Elapsed };
        }
    }
}
