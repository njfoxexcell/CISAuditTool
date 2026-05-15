using System.Diagnostics;
using System.ServiceProcess;
using CISAudit.Core.Models;
using Microsoft.Win32;

namespace CISAudit.Core.Checks;

/// <summary>
/// Verifies a Windows service's startup configuration.
///
/// Parameters:
///   serviceName : the registry/service short name (e.g. "Browser", "XblGameSave")
///   expected    : "Disabled" | "Manual" | "Automatic" | "AutomaticDelayedStart" — pipe-delimited allowed
///   allowAbsent : "true" to pass if the service is not installed at all (CIS often allows this)
/// </summary>
public sealed class ServiceCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.Service;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var p = def.Parameters;
        if (!p.TryGetValue("serviceName", out var name))
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = "service check missing 'serviceName'", Duration = sw.Elapsed };
        }
        var expected = p.GetValueOrDefault("expected", "Disabled");
        var allowAbsent = p.GetValueOrDefault("allowAbsent", "false") == "true";

        try
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}");
            if (k is null)
            {
                return new CheckResult
                {
                    ControlId = def.Id,
                    Status = allowAbsent ? CheckStatus.Pass : CheckStatus.NotApplicable,
                    ExpectedValue = def.ExpectedDisplay ?? expected,
                    ActualValue = "(service not installed)",
                    Evidence = $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name} not present",
                    Duration = sw.Elapsed
                };
            }
            var start = (int)(k.GetValue("Start") ?? -1);
            var delayed = (int)(k.GetValue("DelayedAutostart") ?? 0);
            var actual = StartToString(start, delayed);
            var allowed = expected.Split('|').Select(s => s.Trim()).ToArray();
            var pass = allowed.Any(a => string.Equals(a, actual, StringComparison.OrdinalIgnoreCase));
            return new CheckResult
            {
                ControlId = def.Id,
                Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
                ExpectedValue = def.ExpectedDisplay ?? expected,
                ActualValue = actual,
                Evidence = $"Services\\{name}: Start={start}, DelayedAutostart={delayed}",
                Duration = sw.Elapsed
            };
        }
        catch (Exception ex)
        {
            return new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = ex.Message, Duration = sw.Elapsed };
        }
    }

    private static string StartToString(int start, int delayed) => start switch
    {
        0 => "Boot",
        1 => "System",
        2 => delayed == 1 ? "AutomaticDelayedStart" : "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => $"Unknown({start})"
    };
}
