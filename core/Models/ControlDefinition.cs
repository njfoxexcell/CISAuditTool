using System.Text.Json.Serialization;

namespace CISAudit.Core.Models;

/// <summary>
/// One CIS recommendation. Captures the identification metadata plus the
/// machine-checkable parameters needed to evaluate it on this device.
/// </summary>
public sealed class ControlDefinition
{
    public string Id { get; set; } = "";              // e.g. "18.10.5.1"
    public string Title { get; set; } = "";
    public int Level { get; set; } = 2;
    public string Section { get; set; } = "";          // e.g. "Administrative Templates: System"
    public string? Description { get; set; }
    public string? Rationale { get; set; }
    public string? Remediation { get; set; }
    public string? Impact { get; set; }
    public string? DefaultValue { get; set; }

    /// <summary>Profile codes parsed from the benchmark: "L1", "L2", "BL", "NG".
    /// A control can apply to multiple profiles (e.g. ["L2","BL"]). The scan
    /// includes a control if any of its profiles is selected.</summary>
    public List<string> Profiles { get; set; } = new();

    /// <summary>The kind of check (drives which executor handles it).</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public CheckKind Kind { get; set; }

    /// <summary>Free-form parameters keyed by check kind. See CheckParameters helpers.</summary>
    public Dictionary<string, string> Parameters { get; set; } = new();

    /// <summary>Human-readable expected value (for display in the report).</summary>
    public string? ExpectedDisplay { get; set; }
}
