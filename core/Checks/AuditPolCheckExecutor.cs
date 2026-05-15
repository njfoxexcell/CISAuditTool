using System.Diagnostics;
using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

/// <summary>
/// Verifies an Advanced Audit Policy subcategory setting.
///
/// Parameters:
///   subcategory : exact CIS subcategory name (e.g. "Credential Validation")
///   expected    : "Success" | "Failure" | "Success and Failure" | "No Auditing"
///                 — may be pipe-delimited to allow any of N values
/// </summary>
public sealed class AuditPolCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.AuditPolicy;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var snap = ctx.AuditPol.Value;
        if (snap.Error is not null)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = $"auditpol unavailable: {snap.Error}", Duration = sw.Elapsed };
        }

        var p = def.Parameters;
        if (!p.TryGetValue("subcategory", out var subcat))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = "auditpol check missing 'subcategory'", Duration = sw.Elapsed };
        }
        var expected = p.GetValueOrDefault("expected", "");

        snap.BySubcategory.TryGetValue(subcat, out var actual);
        actual ??= "(not present)";

        var allowed = expected.Split('|', StringSplitOptions.RemoveEmptyEntries)
                              .Select(s => s.Trim())
                              .ToArray();
        var pass = allowed.Any(a => string.Equals(a, actual, StringComparison.OrdinalIgnoreCase));

        return new CheckResult
        {
            ControlId = def.Id,
            Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
            ExpectedValue = def.ExpectedDisplay ?? expected,
            ActualValue = actual,
            Evidence = $"auditpol subcategory '{subcat}' = '{actual}'",
            Duration = sw.Elapsed
        };
    }
}
