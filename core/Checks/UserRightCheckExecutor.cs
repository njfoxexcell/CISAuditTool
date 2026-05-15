using System.Diagnostics;
using System.Security.Principal;
using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

/// <summary>
/// Compares the principals assigned to a SeXxxPrivilege user-right against an allowlist.
///
/// Parameters:
///   privilege : "SeDenyNetworkLogonRight", "SeTcbPrivilege", etc.
///   mode      : "exact" (members must equal allowlist) | "subset" (members must be subset of allowlist) | "empty" (must be empty)
///   expected  : pipe-delimited list of principals — names ("Administrators", "Guests")
///               or SIDs ("*S-1-5-32-544"). Names will be resolved to SIDs for comparison.
/// </summary>
public sealed class UserRightCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.UserRight;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var snap = ctx.SecPol.Value;
        if (snap.Error is not null)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = $"secedit unavailable: {snap.Error}", Duration = sw.Elapsed };
        }

        var p = def.Parameters;
        if (!p.TryGetValue("privilege", out var priv))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = "user right check missing 'privilege'", Duration = sw.Elapsed };
        }
        var mode = p.GetValueOrDefault("mode", "exact");
        var expectedRaw = p.GetValueOrDefault("expected", "");

        snap.PrivilegeRights.TryGetValue(priv, out var actualRaw);
        actualRaw ??= "";

        var actual = SplitSids(actualRaw);
        if (mode.Equals("empty", StringComparison.OrdinalIgnoreCase))
        {
            return new CheckResult
            {
                ControlId = def.Id,
                Status = actual.Count == 0 ? CheckStatus.Pass : CheckStatus.Fail,
                ExpectedValue = "(no principals)",
                ActualValue = actual.Count == 0 ? "(empty)" : string.Join(", ", actual.Select(ResolveSidOrName)),
                Evidence = $"{priv}={actualRaw}",
                Duration = sw.Elapsed
            };
        }

        var expected = ResolveExpectedToSids(expectedRaw);

        bool pass = mode.ToLowerInvariant() switch
        {
            "exact" => SetEquals(actual, expected),
            "subset" => actual.All(a => expected.Contains(a, StringComparer.OrdinalIgnoreCase)),
            _ => false
        };

        return new CheckResult
        {
            ControlId = def.Id,
            Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
            ExpectedValue = def.ExpectedDisplay ?? string.Join(", ", expected.Select(ResolveSidOrName)),
            ActualValue = actual.Count == 0 ? "(empty)" : string.Join(", ", actual.Select(ResolveSidOrName)),
            Evidence = $"{priv}={actualRaw}",
            Duration = sw.Elapsed
        };
    }

    private static List<string> SplitSids(string raw) =>
        raw.Split(',', StringSplitOptions.RemoveEmptyEntries)
           .Select(s => s.Trim().TrimStart('*'))
           .Where(s => s.Length > 0)
           .ToList();

    private static List<string> ResolveExpectedToSids(string raw)
    {
        var result = new List<string>();
        foreach (var tok in raw.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = tok.Trim().TrimStart('*');
            if (t.Length == 0) continue;
            if (t.StartsWith("S-1-")) { result.Add(t); continue; }
            try
            {
                var sid = ((SecurityIdentifier)new NTAccount(t).Translate(typeof(SecurityIdentifier))).Value;
                result.Add(sid);
            }
            catch { result.Add(t); /* leave unresolved; comparison will fail-noisy */ }
        }
        return result;
    }

    private static string ResolveSidOrName(string s)
    {
        if (!s.StartsWith("S-1-")) return s;
        try { return ((NTAccount)new SecurityIdentifier(s).Translate(typeof(NTAccount))).Value; }
        catch { return s; }
    }

    private static bool SetEquals(List<string> a, List<string> b) =>
        a.Count == b.Count && new HashSet<string>(a, StringComparer.OrdinalIgnoreCase).SetEquals(b);
}
