using System.Diagnostics;

namespace CISAudit.Core.Checks;

/// <summary>
/// Snapshot of `auditpol /get /category:* /r` — Advanced Audit Policy settings.
/// Subcategory -> "No Auditing" | "Success" | "Failure" | "Success and Failure".
/// </summary>
public sealed class AuditPolSnapshot
{
    public Dictionary<string, string> BySubcategory { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Error { get; }

    private AuditPolSnapshot(string? error) => Error = error;

    public static AuditPolSnapshot Load()
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe", "/get /category:* /r")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15_000);
            if (p.ExitCode != 0)
            {
                return new AuditPolSnapshot($"auditpol exit {p.ExitCode}: {p.StandardError.ReadToEnd()}");
            }
            var snap = new AuditPolSnapshot(null);
            // CSV columns: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
            bool first = true;
            foreach (var line in stdout.Split('\n'))
            {
                if (first) { first = false; continue; }
                var trimmed = line.Trim();
                if (trimmed.Length == 0) continue;
                var parts = trimmed.Split(',');
                if (parts.Length < 5) continue;
                var subcat = parts[2].Trim();
                var setting = parts[4].Trim();
                if (subcat.Length > 0) snap.BySubcategory[subcat] = setting;
            }
            return snap;
        }
        catch (Exception ex)
        {
            return new AuditPolSnapshot(ex.Message);
        }
    }
}
