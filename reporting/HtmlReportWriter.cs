using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using CISAudit.Core.Models;

namespace CISAudit.Reporting;

/// <summary>
/// Writes a single self-contained HTML file with embedded CSS/JS.
/// Layout: header (score + summary) — filters — collapsible per-section listing.
/// </summary>
public static class HtmlReportWriter
{
    public static void Write(string outputPath, AuditReport report, IEnumerable<string> profileFilter)
    {
        var sb = new StringBuilder(256 * 1024);

        sb.Append("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8" />
        <title>CIS Audit Report</title>
        <style>
        :root {
          --bg:#0f172a; --surface:#1e293b; --surface2:#334155; --text:#f1f5f9;
          --muted:#94a3b8; --accent:#3b82f6; --pass:#10b981; --fail:#ef4444;
          --manual:#f59e0b; --na:#6b7280; --error:#a855f7; --border:#334155;
        }
        @media (prefers-color-scheme: light) {
          :root { --bg:#f8fafc; --surface:#ffffff; --surface2:#f1f5f9; --text:#0f172a; --muted:#64748b; --border:#e2e8f0; }
        }
        * { box-sizing:border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
               background:var(--bg); color:var(--text); margin:0; padding:24px; line-height:1.5; }
        h1 { margin:0 0 4px 0; font-size:1.8rem; }
        h2 { margin:32px 0 8px 0; font-size:1.2rem; color:var(--text); border-bottom:1px solid var(--border); padding-bottom:6px; }
        .subtitle { color:var(--muted); margin-bottom:24px; font-size:0.95rem; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:24px; }
        .card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:16px; }
        .card .label { color:var(--muted); font-size:0.85rem; text-transform:uppercase; letter-spacing:0.5px; }
        .card .value { font-size:1.6rem; font-weight:600; margin-top:4px; }
        .score-card { grid-column: span 2; background:linear-gradient(135deg, var(--accent), #2563eb); color:white; border:none; }
        .score-card .value { font-size:2.4rem; }
        .score-card .label { color:rgba(255,255,255,0.85); }
        .badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:0.75rem; font-weight:600;
                 color:white; text-transform:uppercase; letter-spacing:0.5px; }
        .badge.pass    { background:var(--pass); }
        .badge.fail    { background:var(--fail); }
        .badge.manual  { background:var(--manual); }
        .badge.na      { background:var(--na); }
        .badge.error   { background:var(--error); }
        .filters { display:flex; flex-wrap:wrap; gap:8px; margin:16px 0 8px 0; align-items:center; }
        .filters input[type="text"] { background:var(--surface); color:var(--text); border:1px solid var(--border);
                                       border-radius:6px; padding:8px 12px; font-size:0.95rem; flex:1; min-width:240px; }
        .filters .chip { background:var(--surface2); color:var(--text); border:1px solid var(--border);
                         border-radius:14px; padding:5px 12px; font-size:0.85rem; cursor:pointer; user-select:none; }
        .filters .chip.active { background:var(--accent); color:white; border-color:var(--accent); }
        details { margin-bottom:6px; border:1px solid var(--border); border-radius:6px; background:var(--surface); }
        details > summary { padding:10px 14px; cursor:pointer; list-style:none; display:flex; gap:12px;
                            align-items:center; user-select:none; }
        details > summary::-webkit-details-marker { display:none; }
        details > summary::before { content:"›"; display:inline-block; transform:rotate(0deg); transition:transform .15s;
                                     color:var(--muted); font-weight:bold; }
        details[open] > summary::before { transform:rotate(90deg); }
        .section { margin-top:8px; }
        .section > summary { background:var(--surface2); font-weight:600; }
        .section .section-stats { color:var(--muted); font-size:0.85rem; margin-left:auto; }
        .control { margin:4px 12px 4px 24px; }
        .control summary { font-size:0.95rem; }
        .control .ctl-id { font-family:Consolas, "Cascadia Code", monospace; font-size:0.85rem; color:var(--muted);
                            min-width:80px; }
        .control .ctl-title { flex:1; }
        .control .ctl-profiles { font-size:0.75rem; color:var(--muted); }
        .ctl-body { padding:8px 16px 16px 16px; border-top:1px solid var(--border); }
        .kvrow { display:grid; grid-template-columns:140px 1fr; gap:8px; margin:4px 0; font-size:0.9rem; }
        .kvrow .k { color:var(--muted); }
        .kvrow .v { word-break:break-word; }
        .kvrow .v.code { font-family:Consolas, "Cascadia Code", monospace; font-size:0.85rem; background:var(--surface2);
                          padding:2px 6px; border-radius:4px; }
        .prose { white-space:pre-wrap; font-size:0.88rem; color:var(--text); margin-top:6px;
                  background:var(--surface2); padding:8px 12px; border-radius:4px; max-height:220px; overflow:auto; }
        .hidden { display:none !important; }
        .footer { color:var(--muted); font-size:0.8rem; margin-top:32px; padding-top:12px; border-top:1px solid var(--border); }
        </style>
        </head>
        <body>
        """);

        WriteHeader(sb, report, profileFilter);
        WriteFilters(sb, report);
        WriteSections(sb, report);
        WriteFooter(sb, report);

        sb.Append("""
        <script>
        (function(){
          const search = document.getElementById('searchBox');
          const chips = document.querySelectorAll('.chip');
          const activeStatusFilters = new Set();

          chips.forEach(c => c.addEventListener('click', () => {
            const s = c.dataset.status;
            if (c.classList.toggle('active')) activeStatusFilters.add(s); else activeStatusFilters.delete(s);
            applyFilter();
          }));
          search.addEventListener('input', applyFilter);

          function applyFilter() {
            const term = (search.value || '').toLowerCase();
            document.querySelectorAll('.control').forEach(c => {
              const status = c.dataset.status;
              const text = c.dataset.searchText || '';
              const statusOk = activeStatusFilters.size === 0 || activeStatusFilters.has(status);
              const textOk = !term || text.includes(term);
              c.classList.toggle('hidden', !(statusOk && textOk));
            });
            // Hide empty sections
            document.querySelectorAll('.section').forEach(sec => {
              const anyVisible = sec.querySelectorAll('.control:not(.hidden)').length > 0;
              sec.classList.toggle('hidden', !anyVisible);
            });
          }
        })();
        </script>
        </body>
        </html>
        """);

        File.WriteAllText(outputPath, sb.ToString(), new UTF8Encoding(false));
    }

    private static void WriteHeader(StringBuilder sb, AuditReport report, IEnumerable<string> profileFilter)
    {
        var profiles = string.Join(" + ", profileFilter.DefaultIfEmpty("L1 + L2"));
        var duration = (report.CompletedUtc - report.StartedUtc).TotalSeconds;
        var elevation = report.IsElevated ? "Elevated" : "Non-elevated (some checks may have been skipped)";

        sb.Append($"<h1>CIS Windows Audit</h1>\n");
        sb.Append($"<div class=\"subtitle\">{Esc(report.BenchmarkName)} &mdash; Profile: <strong>{Esc(profiles)}</strong></div>\n");

        sb.Append("<div class=\"grid\">\n");
        sb.Append($"  <div class=\"card score-card\"><div class=\"label\">Compliance Score</div><div class=\"value\">{report.ScorePercent:F1}%</div><div style=\"opacity:.85;font-size:.9rem;margin-top:4px;\">{report.Passed} of {report.ScoredTotal} scored checks passed</div></div>\n");
        sb.Append($"  <div class=\"card\"><div class=\"label\">Passed</div><div class=\"value\" style=\"color:var(--pass)\">{report.Passed}</div></div>\n");
        sb.Append($"  <div class=\"card\"><div class=\"label\">Failed</div><div class=\"value\" style=\"color:var(--fail)\">{report.Failed}</div></div>\n");
        sb.Append($"  <div class=\"card\"><div class=\"label\">Manual Review</div><div class=\"value\" style=\"color:var(--manual)\">{report.Manual}</div></div>\n");
        sb.Append($"  <div class=\"card\"><div class=\"label\">Errored</div><div class=\"value\" style=\"color:var(--error)\">{report.Errored}</div></div>\n");
        sb.Append($"  <div class=\"card\"><div class=\"label\">Not Applicable</div><div class=\"value\" style=\"color:var(--na)\">{report.NotApplicable}</div></div>\n");
        sb.Append("</div>\n");

        sb.Append("<h2>Environment</h2>\n");
        sb.Append("<div class=\"card\" style=\"margin-bottom:24px;\">\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">Machine</div><div class=\"v\">{Esc(report.MachineName)}</div></div>\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">Logged-in user</div><div class=\"v\">{Esc(report.UserName)}</div></div>\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">OS version</div><div class=\"v\">{Esc(report.OsVersion)}</div></div>\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">Elevation</div><div class=\"v\">{Esc(elevation)}</div></div>\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">Domain joined</div><div class=\"v\">{(report.IsDomainJoined ? "Yes" : "No")}</div></div>\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">Started</div><div class=\"v\">{report.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}</div></div>\n");
        sb.Append($"  <div class=\"kvrow\"><div class=\"k\">Duration</div><div class=\"v\">{duration:F1}s</div></div>\n");
        sb.Append("</div>\n");
    }

    private static void WriteFilters(StringBuilder sb, AuditReport report)
    {
        sb.Append("<h2>Controls</h2>\n");
        sb.Append("<div class=\"filters\">\n");
        sb.Append("  <input id=\"searchBox\" type=\"text\" placeholder=\"Search by ID, title, or registry path…\" />\n");
        sb.Append("  <span class=\"chip\" data-status=\"Pass\">Pass</span>\n");
        sb.Append("  <span class=\"chip\" data-status=\"Fail\">Fail</span>\n");
        sb.Append("  <span class=\"chip\" data-status=\"ManualReview\">Manual</span>\n");
        sb.Append("  <span class=\"chip\" data-status=\"Error\">Error</span>\n");
        sb.Append("  <span class=\"chip\" data-status=\"NotApplicable\">N/A</span>\n");
        sb.Append("</div>\n");
    }

    private static void WriteSections(StringBuilder sb, AuditReport report)
    {
        // Group by top-level section (first numeric segment, mapped to a friendly name).
        var groups = report.Controls
            .GroupBy(c => TopLevel(c.Definition.Id, c.Definition.Section))
            .OrderBy(g => SortKey(g.Key.id));

        foreach (var g in groups)
        {
            var passed = g.Count(c => c.Result.Status == CheckStatus.Pass);
            var failed = g.Count(c => c.Result.Status == CheckStatus.Fail);
            var total = g.Count();
            sb.Append("<details class=\"section\" open>\n");
            sb.Append($"  <summary><strong>{Esc(g.Key.id)} &mdash; {Esc(g.Key.name)}</strong>");
            sb.Append($"<span class=\"section-stats\">{passed} pass / {failed} fail / {total} total</span></summary>\n");

            foreach (var c in g.OrderBy(c => SortKey(c.Definition.Id)))
            {
                WriteControl(sb, c);
            }

            sb.Append("</details>\n");
        }
    }

    private static void WriteControl(StringBuilder sb, EvaluatedControl c)
    {
        var def = c.Definition;
        var r = c.Result;
        var (badge, badgeText) = r.Status switch
        {
            CheckStatus.Pass         => ("pass",   "Pass"),
            CheckStatus.Fail         => ("fail",   "Fail"),
            CheckStatus.ManualReview => ("manual", "Manual"),
            CheckStatus.NotApplicable=> ("na",     "N/A"),
            _                        => ("error",  "Error")
        };
        var searchText = $"{def.Id} {def.Title} {def.Description} {r.ActualValue} {def.ExpectedDisplay}".ToLowerInvariant();
        var profilesAttr = def.Profiles.Count > 0 ? string.Join("+", def.Profiles) : $"L{def.Level}";

        sb.Append($"<details class=\"control\" data-status=\"{r.Status}\" data-search-text=\"{Esc(searchText)}\">\n");
        sb.Append("  <summary>");
        sb.Append($"<span class=\"badge {badge}\">{badgeText}</span>");
        sb.Append($"<span class=\"ctl-id\">{Esc(def.Id)}</span>");
        sb.Append($"<span class=\"ctl-title\">{Esc(def.Title)}</span>");
        sb.Append($"<span class=\"ctl-profiles\">{Esc(profilesAttr)}</span>");
        sb.Append("</summary>\n");

        sb.Append("  <div class=\"ctl-body\">\n");
        if (!string.IsNullOrWhiteSpace(def.ExpectedDisplay) || !string.IsNullOrWhiteSpace(r.ExpectedValue))
            sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Expected</div><div class=\"v code\">{Esc(def.ExpectedDisplay ?? r.ExpectedValue ?? "")}</div></div>\n");
        if (!string.IsNullOrWhiteSpace(r.ActualValue))
            sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Actual</div><div class=\"v code\">{Esc(r.ActualValue)}</div></div>\n");
        if (!string.IsNullOrWhiteSpace(r.Evidence))
            sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Evidence</div><div class=\"v code\">{Esc(r.Evidence)}</div></div>\n");
        if (!string.IsNullOrWhiteSpace(r.Detail))
            sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Detail</div><div class=\"v\">{Esc(r.Detail)}</div></div>\n");
        if (!string.IsNullOrWhiteSpace(def.Section))
            sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Section</div><div class=\"v\">{Esc(def.Section)}</div></div>\n");
        sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Check type</div><div class=\"v\">{def.Kind}</div></div>\n");

        if (!string.IsNullOrWhiteSpace(def.Description))
        {
            sb.Append("    <div class=\"kvrow\"><div class=\"k\">Description</div><div class=\"v\"></div></div>\n");
            sb.Append($"    <div class=\"prose\">{Esc(def.Description.Trim())}</div>\n");
        }
        if (!string.IsNullOrWhiteSpace(def.Rationale))
        {
            sb.Append("    <div class=\"kvrow\"><div class=\"k\">Rationale</div><div class=\"v\"></div></div>\n");
            sb.Append($"    <div class=\"prose\">{Esc(def.Rationale.Trim())}</div>\n");
        }
        if (!string.IsNullOrWhiteSpace(def.Remediation))
        {
            sb.Append("    <div class=\"kvrow\"><div class=\"k\">Remediation</div><div class=\"v\"></div></div>\n");
            sb.Append($"    <div class=\"prose\">{Esc(def.Remediation.Trim())}</div>\n");
        }
        if (!string.IsNullOrWhiteSpace(def.Impact))
        {
            sb.Append("    <div class=\"kvrow\"><div class=\"k\">Impact</div><div class=\"v\"></div></div>\n");
            sb.Append($"    <div class=\"prose\">{Esc(def.Impact.Trim())}</div>\n");
        }
        if (!string.IsNullOrWhiteSpace(def.DefaultValue))
            sb.Append($"    <div class=\"kvrow\"><div class=\"k\">Default value</div><div class=\"v\">{Esc(def.DefaultValue)}</div></div>\n");

        sb.Append("  </div>\n</details>\n");
    }

    private static void WriteFooter(StringBuilder sb, AuditReport report)
    {
        sb.Append("<div class=\"footer\">");
        sb.Append($"Generated by CIS Audit Tool at {report.CompletedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}. ");
        sb.Append("Manual-review controls and Not-Applicable controls are excluded from the compliance score.");
        sb.Append("</div>\n");
    }

    private static (string id, string name) TopLevel(string id, string section)
    {
        var top = id.Split('.')[0];
        var named = SectionName(top);
        if (!string.IsNullOrEmpty(section) && string.IsNullOrEmpty(named)) named = section;
        return (top, named ?? section ?? "");
    }

    private static string SectionName(string top) => top switch
    {
        "1"  => "Account Policies",
        "2"  => "Local Policies",
        "5"  => "System Services",
        "9"  => "Windows Firewall with Advanced Security",
        "17" => "Advanced Audit Policy",
        "18" => "Administrative Templates (Computer)",
        "19" => "Administrative Templates (User)",
        _    => $"Section {top}"
    };

    private static string SortKey(string id) =>
        string.Join(".", id.Split('.').Select(s => int.TryParse(s, out var n) ? n.ToString("D4", CultureInfo.InvariantCulture) : s));

    private static string Esc(string? s) => s is null ? "" : WebUtility.HtmlEncode(s);
}
