using System.Diagnostics;
using System.IO;
using System.Text;

namespace CISAudit.Core.Checks;

/// <summary>
/// One-shot export of the local security policy via secedit /export.
/// Sections we care about: [System Access] (password/lockout), [Event Audit],
/// [Privilege Rights] (user rights), [Registry Values] (security options).
/// </summary>
public sealed class SecPolSnapshot
{
    public Dictionary<string, string> SystemAccess { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> EventAudit { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> RegistryValues { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> PrivilegeRights { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string RawText { get; }
    public string? Error { get; }

    private SecPolSnapshot(string rawText, string? error)
    {
        RawText = rawText;
        Error = error;
    }

    public static SecPolSnapshot Load()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"cisaudit-secpol-{Guid.NewGuid():N}.inf");
        try
        {
            var psi = new ProcessStartInfo("secedit.exe", $"/export /cfg \"{tmp}\" /quiet")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit(30_000);
            if (!File.Exists(tmp))
            {
                return new SecPolSnapshot("", $"secedit /export failed (exit {p.ExitCode}). stderr: {p.StandardError.ReadToEnd()}");
            }
            // secedit writes UTF-16; let .NET auto-detect.
            var text = File.ReadAllText(tmp, Encoding.Unicode);
            var snap = new SecPolSnapshot(text, null);
            ParseInto(snap, text);
            return snap;
        }
        catch (Exception ex)
        {
            return new SecPolSnapshot("", ex.Message);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best-effort */ }
        }
    }

    private static void ParseInto(SecPolSnapshot snap, string text)
    {
        Dictionary<string, string>? current = null;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r', ' ', '\t');
            if (line.Length == 0) continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                current = line[1..^1].Trim() switch
                {
                    "System Access"    => snap.SystemAccess,
                    "Event Audit"      => snap.EventAudit,
                    "Registry Values"  => snap.RegistryValues,
                    "Privilege Rights" => snap.PrivilegeRights,
                    _ => null
                };
                continue;
            }
            if (current is null) continue;
            var eq = line.IndexOf('=');
            if (eq < 0) continue;
            var k = line[..eq].Trim();
            var v = line[(eq + 1)..].Trim();
            current[k] = v;
        }
    }
}
