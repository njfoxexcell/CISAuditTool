using System.Diagnostics;
using CISAudit.Core.Models;
using Microsoft.Win32;

namespace CISAudit.Core.Checks;

/// <summary>
/// Reads a registry value and compares it against an expected value.
///
/// Parameters:
///   hive     : HKLM | HKCU | HKU | HKCR | HKCC
///   key      : subkey path (no hive prefix)
///   name     : value name (empty = default value)
///   type     : DWORD | QWORD | STRING | MULTI_STRING | EXPAND_STRING
///   op       : equals | notEquals | gte | lte | bitmaskSet | bitmaskClear | exists | absent | inList
///   expected : the value to compare against (for inList, pipe-delimited)
/// </summary>
public sealed class RegistryCheckExecutor : ICheckExecutor
{
    public CheckKind Kind => CheckKind.Registry;

    public CheckResult Evaluate(ControlDefinition def, AuditContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var p = def.Parameters;
        if (!p.TryGetValue("hive", out var hiveName) || !p.TryGetValue("key", out var subkey))
        {
            return new CheckResult
            {
                ControlId = def.Id,
                Status = CheckStatus.Error,
                Detail = "Registry check missing 'hive' or 'key' parameter",
                Duration = sw.Elapsed
            };
        }

        var name = p.GetValueOrDefault("name", "");
        var op = p.GetValueOrDefault("op", "equals");
        var expected = p.GetValueOrDefault("expected", "");

        RegistryHive hive;
        try { hive = ParseHive(hiveName); }
        catch (Exception ex) { return Err(def, ex.Message, sw); }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var k = baseKey.OpenSubKey(subkey);
            object? raw = k?.GetValue(name, null);

            if (op.Equals("absent", StringComparison.OrdinalIgnoreCase))
            {
                return new CheckResult
                {
                    ControlId = def.Id,
                    Status = raw is null ? CheckStatus.Pass : CheckStatus.Fail,
                    ExpectedValue = "(value absent)",
                    ActualValue = raw?.ToString() ?? "(absent)",
                    Evidence = $"{hiveName}\\{subkey} :: {name}",
                    Duration = sw.Elapsed
                };
            }

            if (raw is null)
            {
                // CIS treats a missing value as not-configured. For most policies "not configured"
                // !=  the hardened state, so a missing value FAILS unless op==absent (handled above).
                return new CheckResult
                {
                    ControlId = def.Id,
                    Status = CheckStatus.Fail,
                    ExpectedValue = def.ExpectedDisplay ?? expected,
                    ActualValue = "(value not present)",
                    Evidence = $"{hiveName}\\{subkey} :: {name}",
                    Detail = "Registry value is not present — policy not configured.",
                    Duration = sw.Elapsed
                };
            }

            var (pass, actualDisplay, detail) = Compare(raw, op, expected);
            return new CheckResult
            {
                ControlId = def.Id,
                Status = pass ? CheckStatus.Pass : CheckStatus.Fail,
                ExpectedValue = def.ExpectedDisplay ?? expected,
                ActualValue = actualDisplay,
                Evidence = $"{hiveName}\\{subkey} :: {name} ({raw.GetType().Name})",
                Detail = detail,
                Duration = sw.Elapsed
            };
        }
        catch (Exception ex)
        {
            return Err(def, ex.Message, sw);
        }
    }

    private static RegistryHive ParseHive(string s) => s.ToUpperInvariant() switch
    {
        "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
        "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
        "HKU"  or "HKEY_USERS"        => RegistryHive.Users,
        "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
        "HKCC" or "HKEY_CURRENT_CONFIG" => RegistryHive.CurrentConfig,
        _ => throw new ArgumentException($"Unknown hive '{s}'")
    };

    private static (bool pass, string actual, string? detail) Compare(object raw, string op, string expected)
    {
        string actualStr = raw switch
        {
            string[] arr => string.Join("|", arr),
            byte[] b => BitConverter.ToString(b),
            _ => raw.ToString() ?? ""
        };

        switch (op.ToLowerInvariant())
        {
            case "exists":
                return (true, actualStr, null);
            case "notempty":
                return (actualStr.Length > 0, actualStr, null);
            case "equals":
                return (NumOrStringEquals(raw, expected), actualStr, null);
            case "notequals":
                return (!NumOrStringEquals(raw, expected), actualStr, null);
            case "gte":
                return (TryLong(raw, out var a1) && long.TryParse(expected, out var e1) && a1 >= e1, actualStr, null);
            case "lte":
                return (TryLong(raw, out var a2) && long.TryParse(expected, out var e2) && a2 <= e2, actualStr, null);
            case "bitmaskset":
                if (TryLong(raw, out var av) && long.TryParse(expected, out var bm))
                    return ((av & bm) == bm, actualStr, $"actual & {bm} = {av & bm}");
                return (false, actualStr, "non-numeric for bitmask");
            case "bitmaskclear":
                if (TryLong(raw, out var av2) && long.TryParse(expected, out var bm2))
                    return ((av2 & bm2) == 0, actualStr, $"actual & {bm2} = {av2 & bm2}");
                return (false, actualStr, "non-numeric for bitmask");
            case "inlist":
                var allowed = expected.Split('|', StringSplitOptions.RemoveEmptyEntries);
                return (allowed.Any(a => string.Equals(a.Trim(), actualStr, StringComparison.OrdinalIgnoreCase)), actualStr, null);
            default:
                return (false, actualStr, $"Unknown op '{op}'");
        }
    }

    private static bool TryLong(object raw, out long val)
    {
        switch (raw)
        {
            case int i: val = i; return true;
            case long l: val = l; return true;
            case uint ui: val = ui; return true;
            case ulong ul: val = (long)ul; return true;
            case string s when long.TryParse(s, out var sv): val = sv; return true;
        }
        val = 0; return false;
    }

    private static bool NumOrStringEquals(object raw, string expected)
    {
        if (TryLong(raw, out var lv) && long.TryParse(expected, out var le)) return lv == le;
        if (raw is string[] arr) return string.Join("|", arr).Equals(expected, StringComparison.OrdinalIgnoreCase);
        return (raw.ToString() ?? "").Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static CheckResult Err(ControlDefinition def, string msg, Stopwatch sw) => new()
    {
        ControlId = def.Id,
        Status = CheckStatus.Error,
        Detail = msg,
        Duration = sw.Elapsed
    };
}
