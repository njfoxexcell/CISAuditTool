using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using CISAudit.Core.Checks;
using CISAudit.Core.Models;
using Microsoft.Win32;

namespace CISAudit.Core.Audit;

public sealed record ProgressUpdate(int Completed, int Total, string CurrentControlId, string Message);

public sealed class AuditEngine
{
    private readonly Dictionary<CheckKind, ICheckExecutor> _executors;

    public AuditEngine()
    {
        _executors = new ICheckExecutor[]
        {
            new RegistryCheckExecutor(),
            new SecPolCheckExecutor(),
            new AuditPolCheckExecutor(),
            new UserRightCheckExecutor(),
            new ServiceCheckExecutor(),
            new WmiCheckExecutor(),
            new WindowsFeatureCheckExecutor(),
            new ManualCheckExecutor()
        }.ToDictionary(e => e.Kind, e => e);
    }

    public static List<ControlDefinition> LoadCatalog(Stream jsonStream)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            Converters = { new JsonStringEnumConverter() }
        };
        return JsonSerializer.Deserialize<List<ControlDefinition>>(jsonStream, options)
               ?? new List<ControlDefinition>();
    }

    public static List<ControlDefinition> LoadCatalogFromEmbedded()
    {
        var asm = typeof(AuditEngine).Assembly;
        var name = asm.GetManifestResourceNames()
                      .FirstOrDefault(n => n.EndsWith("Controls.json", StringComparison.OrdinalIgnoreCase))
                  ?? throw new InvalidOperationException("Embedded Controls.json not found");
        using var s = asm.GetManifestResourceStream(name)!;
        return LoadCatalog(s);
    }

    public AuditReport Run(
        IEnumerable<ControlDefinition> controls,
        IProgress<ProgressUpdate>? progress = null,
        CancellationToken cancel = default)
    {
        var list = controls.ToList();
        var started = DateTime.UtcNow;
        var isElevated = IsElevated();
        var isDomain = IsDomainJoined();
        var ctx = new AuditContext(isElevated, isDomain, SecPolSnapshot.Load, AuditPolSnapshot.Load);

        var report = new AuditReport
        {
            StartedUtc = started,
            IsElevated = isElevated,
            IsDomainJoined = isDomain
        };

        int i = 0;
        foreach (var def in list)
        {
            cancel.ThrowIfCancellationRequested();
            i++;
            progress?.Report(new ProgressUpdate(i, list.Count, def.Id, def.Title));

            CheckResult result;
            try
            {
                if (!_executors.TryGetValue(def.Kind, out var exec))
                {
                    result = new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = $"No executor for kind {def.Kind}" };
                }
                else
                {
                    result = exec.Evaluate(def, ctx);
                }
            }
            catch (Exception ex)
            {
                result = new CheckResult { ControlId = def.Id, Status = CheckStatus.Error, Detail = ex.Message };
            }
            report.Controls.Add(new EvaluatedControl { Definition = def, Result = result });
        }

        report.CompletedUtc = DateTime.UtcNow;
        return report;
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static bool IsDomainJoined()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            var domain = k?.GetValue("Domain") as string;
            return !string.IsNullOrWhiteSpace(domain);
        }
        catch { return false; }
    }
}
