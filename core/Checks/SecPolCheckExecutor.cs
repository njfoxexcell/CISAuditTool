using System.Diagnostics;
using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

/// <summary>
/// Looks up a value in the secedit export.
///
/// Parameters:
///   section : SystemAccess | EventAudit | RegistryValues
///   name    : the INF key (e.g. MinimumPasswordAge, NewAdministratorName)
///   op      : equals | gte | lte | notEmpty | notEquals | inList | regex
///   expected: value to compare (for inList, pipe-delimited)
///   stripQuotes: "true" to strip leading/trailing quotes from actual
/// </summary>
public sealed class SecPolCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.SecurityPolicy;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var snap = ctx.SecPol.Value;
        if (snap.Error is not null)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = $"secedit unavailable: {snap.Error}", Duration = sw.Elapsed };
        }

        var p = def.Parameters;
        if (!p.TryGetValue("section", out var section) || !p.TryGetValue("name", out var name))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = "secpol check missing 'section' or 'name'", Duration = sw.Elapsed };
        }

        var dict = section switch
        {
            "SystemAccess"   => snap.SystemAccess,
            "EventAudit"     => snap.EventAudit,
            "RegistryValues" => snap.RegistryValues,
            _ => null
        };
        if (dict is null)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = $"Unknown secpol section '{section}'", Duration = sw.Elapsed };
        }

        dict.TryGetValue(name, out var actual);
        actual ??= "";
        // INF RegistryValues format is "<type>,<value>" — split off the value half.
        if (section == "RegistryValues")
        {
            var comma = actual.IndexOf(',');
            if (comma >= 0) actual = actual[(comma + 1)..].Trim();
        }
        if (p.GetValueOrDefault("stripQuotes") == "true")
            actual = actual.Trim('"');

        var op = p.GetValueOrDefault("op", "equals");
        var expected = p.GetValueOrDefault("expected", "");

        bool pass = op.ToLowerInvariant() switch
        {
            "equals" => NumOrStrEq(actual, expected),
            "notequals" => !NumOrStrEq(actual, expected),
            "gte" => long.TryParse(actual, out var a1) && long.TryParse(expected, out var e1) && a1 >= e1,
            "lte" => long.TryParse(actual, out var a2) && long.TryParse(expected, out var e2) && a2 <= e2,
            "between" => Between(actual, expected),
            "notempty" => actual.Length > 0,
            "inlist" => expected.Split('|').Any(v => v.Trim().Equals(actual, StringComparison.OrdinalIgnoreCase)),
            "regex" => System.Text.RegularExpressions.Regex.IsMatch(actual, expected),
            _ => false
        };

        return new CheckResult
        {
            ControlId = def.Id,
            Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
            ExpectedValue = def.ExpectedDisplay ?? expected,
            ActualValue = actual.Length == 0 ? "(unset)" : actual,
            Evidence = $"[{section}] {name}={actual}",
            Duration = sw.Elapsed
        };
    }

    private static bool NumOrStrEq(string a, string e)
    {
        if (long.TryParse(a, out var av) && long.TryParse(e, out var ev)) return av == ev;
        return string.Equals(a, e, StringComparison.OrdinalIgnoreCase);
    }

    // expected format: "min..max"
    private static bool Between(string actual, string expected)
    {
        var parts = expected.Split("..", 2);
        if (parts.Length != 2) return false;
        return long.TryParse(actual, out var a)
            && long.TryParse(parts[0], out var lo)
            && long.TryParse(parts[1], out var hi)
            && a >= lo && a <= hi;
    }
}
