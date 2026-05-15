namespace CISAudit.Core.Models;

public sealed class AuditReport
{
    public string BenchmarkName { get; init; } = "CIS Microsoft Windows 11 Enterprise Benchmark v5.0.1";
    public string ProfileLevel { get; init; } = "Level 2";
    public DateTime StartedUtc { get; init; }
    public DateTime CompletedUtc { get; set; }
    public string MachineName { get; init; } = Environment.MachineName;
    public string UserName { get; init; } = Environment.UserName;
    public string OsVersion { get; init; } = Environment.OSVersion.VersionString;
    public bool IsElevated { get; init; }
    public bool IsDomainJoined { get; init; }

    public List<EvaluatedControl> Controls { get; init; } = new();

    // Scoring excludes Manual + NotApplicable from the denominator per design choice.
    public int ScoredTotal => Controls.Count(c => c.Result.Status is CheckStatus.Pass or CheckStatus.Fail or CheckStatus.Error);
    public int Passed => Controls.Count(c => c.Result.Status == CheckStatus.Pass);
    public int Failed => Controls.Count(c => c.Result.Status == CheckStatus.Fail);
    public int Errored => Controls.Count(c => c.Result.Status == CheckStatus.Error);
    public int Manual => Controls.Count(c => c.Result.Status == CheckStatus.ManualReview);
    public int NotApplicable => Controls.Count(c => c.Result.Status == CheckStatus.NotApplicable);
    public double ScorePercent => ScoredTotal == 0 ? 0 : 100.0 * Passed / ScoredTotal;
}

public sealed class EvaluatedControl
{
    public required ControlDefinition Definition { get; init; }
    public required CheckResult Result { get; init; }
}
