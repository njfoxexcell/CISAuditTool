using System.Text.Json.Serialization;

namespace CISAudit.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CheckStatus
{
    Pass,
    Fail,
    ManualReview,
    NotApplicable,
    Error
}

public sealed class CheckResult
{
    public required string ControlId { get; init; }
    public required CheckStatus Status { get; init; }
    public string? ActualValue { get; init; }
    public string? ExpectedValue { get; init; }
    public string? Detail { get; init; }     // free-form explanation / error message
    public string? Evidence { get; init; }   // raw output (registry value, secpol line, etc.)
    public TimeSpan Duration { get; init; }
}
