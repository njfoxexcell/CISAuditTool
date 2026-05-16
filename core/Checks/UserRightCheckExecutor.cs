using System.Diagnostics;
using System.Security.Principal;
using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

/// <summary>
/// Compares the principals assigned to a SeXxxPrivilege user-right against an allowlist.
///
/// Source of truth: <see cref="LsaUserRights.EnumerateAccounts"/>. The LSA API
/// returns the EFFECTIVE set of accounts that hold the right (local policy +
/// domain GPO + OS default), whereas secedit /export only emits explicit local
/// overrides — which is why earlier reports showed many rights as "(empty)"
/// even though a GPO was setting them.
///
/// Parameters:
///   privilege : "SeDenyNetworkLogonRight", "SeTcbPrivilege", etc.
///   mode      : "exact"  — actual must equal allowlist (set semantics)
///               "subset" — actual must be a subset of allowlist
///               "empty"  — actual must be empty
///   expected  : pipe-delimited principals — friendly names ("Administrators",
///               "Window Manager\Window Manager Group") or SIDs ("*S-1-5-32-544").
///               Friendly names are resolved to SIDs for comparison.
/// </summary>
public sealed class UserRightCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.UserRight;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var p = def.Parameters;
        if (!p.TryGetValue("privilege", out var priv))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error,
                                     Detail = "user right check missing 'privilege'", Duration = sw.Elapsed };
        }
        var mode = p.GetValueOrDefault("mode", "exact");
        var expectedRaw = p.GetValueOrDefault("expected", "");

        List<SecurityIdentifier> actual;
        try
        {
            actual = LsaUserRights.EnumerateAccounts(priv);
        }
        catch (Exception ex)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error,
                                     Detail = $"LSA enumeration failed for {priv}: {ex.Message}",
                                     Duration = sw.Elapsed };
        }
        var actualSids = actual.Select(s => s.Value).ToList();
        var actualDisplay = FormatPrincipals(actualSids);

        if (mode.Equals("empty", StringComparison.OrdinalIgnoreCase))
        {
            return new CheckResult
            {
                ControlId = def.Id,
                Status = actualSids.Count == 0 ? CheckStatus.Pass : CheckStatus.Fail,
                ExpectedValue = "(no principals)",
                ActualValue = actualSids.Count == 0 ? "(none)" : actualDisplay,
                Evidence = $"{priv} via LSA -> {string.Join(", ", actualSids)}",
                Duration = sw.Elapsed
            };
        }

        var expectedSids = ResolveExpectedToSids(expectedRaw);
        var expectedDisplay = def.ExpectedDisplay ?? FormatPrincipals(expectedSids);

        bool pass = mode.ToLowerInvariant() switch
        {
            "exact"  => SetEquals(actualSids, expectedSids),
            "subset" => actualSids.All(a => expectedSids.Contains(a, StringComparer.OrdinalIgnoreCase)),
            _        => false
        };

        return new CheckResult
        {
            ControlId = def.Id,
            Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
            ExpectedValue = expectedDisplay,
            ActualValue = actualSids.Count == 0 ? "(none)" : actualDisplay,
            Evidence = $"{priv} via LSA: {string.Join(", ", actualSids)}",
            Duration = sw.Elapsed
        };
    }

    private static List<string> ResolveExpectedToSids(string raw)
    {
        var result = new List<string>();
        foreach (var tok in raw.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = tok.Trim().TrimStart('*');
            if (t.Length == 0) continue;
            if (t.StartsWith("S-1-")) { result.Add(t); continue; }

            // CIS sometimes writes "DOMAIN\name" or just "name". Try both.
            string? sid = TryResolve(t) ?? TryResolveAliases(t);
            result.Add(sid ?? t);  // unresolved tokens stay literal — comparison will fail noisily
        }
        return result;
    }

    private static string? TryResolve(string name)
    {
        try { return ((SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier))).Value; }
        catch { return null; }
    }

    /// <summary>CIS occasionally uses display variants that don't resolve verbatim.
    /// These are stable aliases for common cases.</summary>
    private static string? TryResolveAliases(string name) => name switch
    {
        // "Window Manager\Window Manager Group" is the display form for SID S-1-5-90-0
        @"Window Manager\Window Manager Group" => "S-1-5-90-0",
        "Window Manager Group"                  => "S-1-5-90-0",
        // "Virtual Machines" = the Hyper-V virtual-machines local group on hosts.
        "Virtual Machines" or @"NT VIRTUAL MACHINE\Virtual Machines" => TryResolve(@"NT VIRTUAL MACHINE\Virtual Machines"),
        // "LOCAL SERVICE", "NETWORK SERVICE" sometimes appear with different prefix conventions
        "LOCAL SERVICE"   or "Local Service"   => "S-1-5-19",
        "NETWORK SERVICE" or "Network Service" => "S-1-5-20",
        "SERVICE"         or "Service"         => "S-1-5-6",
        // "RESTRICTED SERVICES\PrintSpoolerService" — a virtual restricted-service account.
        @"RESTRICTED SERVICES\PrintSpoolerService" => TryResolve(@"NT SERVICE\PrintSpoolerService"),
        _ => null
    };

    private static string FormatPrincipals(List<string> sids)
    {
        if (sids.Count == 0) return "(none)";
        var parts = sids.Select(s =>
        {
            try { return ((NTAccount)new SecurityIdentifier(s).Translate(typeof(NTAccount))).Value; }
            catch { return s; }
        });
        return string.Join(", ", parts);
    }

    private static bool SetEquals(List<string> a, List<string> b) =>
        a.Count == b.Count
        && new HashSet<string>(a, StringComparer.OrdinalIgnoreCase)
              .SetEquals(b.Where(x => x is not null && x.Length > 0));
}
