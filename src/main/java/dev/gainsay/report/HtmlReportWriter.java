package dev.gainsay.report;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.score.CategoryScore;
import dev.gainsay.core.verdict.Verdict;
import dev.gainsay.core.verdict.VerdictKind;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Renders a single-file, self-contained {@code report.html}: inline CSS, no JavaScript, no external
 * resources. A Content-Security-Policy of {@code default-src 'none'} guarantees the page cannot make
 * network requests when opened. Every data-derived string is HTML-escaped by {@link #esc(String)}.
 */
public final class HtmlReportWriter {

    private HtmlReportWriter() {
    }

    private static final String CSS = """
            :root{--bg:#fbfaf7;--fg:#1d1c1a;--muted:#6b6862;--line:#e4e0d8;--card:#ffffff;--code:#f2efe8;
            --fail:#b42318;--warn:#a15c07;--pass:#2f7d4f;--unk:#5d6b7a;--accent:#3c4a9e}
            @media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--muted:#a19e97;--line:#2e2d2a;--card:#1e1e1c;
            --code:#262523;--fail:#f07065;--warn:#e6a23c;--pass:#5cc08a;--unk:#9aa8b6;--accent:#9aa6ff}}
            *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
            main{max-width:1080px;margin:0 auto;padding:32px 16px 64px}
            h1{font-size:28px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:20px;margin:40px 0 12px;padding-top:8px;border-top:1px solid var(--line)}
            h3{font-size:16px;margin:28px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
            .meta{color:var(--muted);font-size:13px}.meta li{margin:2px 0}
            .headline{font-size:18px;background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent);padding:14px 16px;border-radius:6px}
            .warnbox{border-left-color:var(--warn)}
            table{border-collapse:collapse;width:100%;font-size:13.5px;background:var(--card)}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
            th{font-weight:600;color:var(--muted)}.scroll{overflow-x:auto}
            .pill{display:inline-block;font-size:11.5px;font-weight:700;letter-spacing:.03em;padding:1px 7px;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
            .FAIL,.CONTRADICTED{color:var(--fail)}.WARN,.UNCLAIMED{color:var(--warn)}.PASS,.CORROBORATED{color:var(--pass)}.UNKNOWN,.UNTESTED,.NOT_APPLICABLE{color:var(--unk)}
            .score{display:flex;gap:24px;flex-wrap:wrap;align-items:baseline}.big{font-size:40px;font-weight:700}.grade{color:var(--muted)}
            details{background:var(--card);border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:0 12px}
            summary{cursor:pointer;padding:10px 0;list-style-position:outside}details[open] summary{border-bottom:1px solid var(--line);margin-bottom:8px}
            .id{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:var(--muted)}
            dl{margin:0 0 12px}dt{font-weight:600;margin-top:8px}dd{margin:2px 0 0}
            code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:var(--code);padding:1px 4px;border-radius:3px;word-break:break-all}
            ul.proof{padding-left:18px}ul.proof li{margin:4px 0}.small{font-size:13px;color:var(--muted)}
            ol.fix li{margin:0 0 14px;line-height:1.5}
            pre{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:var(--code);padding:8px 10px;border-radius:4px;white-space:pre-wrap;word-break:break-all;margin:6px 0}
            """;

    public static String render(Report r) {
        StringBuilder b = new StringBuilder(32_768);
        b.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">")
                .append("<title>Gainsay report</title><style>").append(CSS).append("</style></head><body><main>");
        b.append("<h1>Gainsay report</h1><ul class=\"meta\"><li>Generated ").append(esc(String.valueOf(r.generatedAt)))
                .append(" · Gainsay ").append(esc(r.tool.get("version"))).append(" · planes: ").append(esc(String.join(", ", r.kinds))).append("</li>");
        for (Report.HostInfo h : r.hosts) {
            b.append("<li>Host <b>").append(esc(h.identity().label())).append("</b> (").append(esc(h.os())).append(") ")
                    .append(esc(String.join(", ", h.identity().ips()))).append(" · collected ").append(esc(String.valueOf(h.collectedAt())))
                    .append(h.elevated() ? " · elevated" : " · not elevated").append(" · ").append(esc(h.source())).append("</li>");
        }
        for (Report.CaptureInfo c : r.captures) {
            b.append("<li>Capture ").append(esc(c.source())).append(": ").append(c.packets()).append(" packets, ")
                    .append(c.malformed()).append(" malformed · ").append(esc(String.valueOf(c.start()))).append(" → ")
                    .append(esc(String.valueOf(c.end()))).append("</li>");
        }
        b.append("</ul>");

        if (r.trial != null) {
            b.append("<h2>Testimony vs evidence</h2><p class=\"headline\">").append(esc(ReportText.trialHeadline(r))).append("</p>");
            for (String w : r.trial.warnings()) {
                b.append("<p class=\"headline warnbox\">⚠ ").append(esc(w)).append("</p>");
            }
            b.append("<div class=\"scroll\"><table><tr><th>Verdict</th><th>Claim</th><th>Host</th><th>Testimony</th><th>Evidence</th><th>Blast radius</th></tr>");
            for (Verdict v : r.verdicts) {
                b.append("<tr><td>").append(pill(ReportText.verdictLabel(v.kind()))).append("</td><td>").append(esc(v.claimType().title()))
                        .append("</td><td>").append(esc(v.hostLabel())).append("</td><td>").append(esc(ReportText.testimony(v)))
                        .append("</td><td>").append(esc(ReportText.evidenceSummary(v))).append("</td><td>")
                        .append(v.dependants().isEmpty() ? "—" : esc(String.join(", ", v.dependants()))).append("</td></tr>");
            }
            b.append("</table></div>");
            for (Verdict v : r.verdicts) {
                if (v.kind() == VerdictKind.CONTRADICTED || v.kind() == VerdictKind.UNCLAIMED) {
                    b.append("<details><summary>").append(pill(ReportText.verdictLabel(v.kind()))).append(" <b>")
                            .append(esc(v.claimType().title())).append("</b> on ").append(esc(v.hostLabel()))
                            .append(" <span class=\"small\">surprise ").append(v.surprise()).append("</span></summary><p>")
                            .append(esc(v.explanation())).append("</p><ul class=\"proof\">");
                    v.evidence().forEach(o -> {
                        if (o.proof() != null) {
                            proof(b, o.proof());
                        }
                    });
                    b.append("</ul></details>");
                }
            }
        }

        if (!r.fixPlan.isEmpty()) {
            b.append("<h2>Fix these first</h2><p class=\"small\">Ranked by how much risk each action removes. Gainsay never runs these "
                    + "commands; review them and run them yourself in an elevated PowerShell.</p><ol class=\"fix\">");
            for (Report.FixItem i : r.fixPlan.subList(0, Math.min(ReportText.FIX_PLAN_SIZE, r.fixPlan.size()))) {
                b.append("<li><span class=\"pill ").append(i.kind().equals("INVESTIGATE") ? "CONTRADICTED" : i.kind().equals("FIX") ? "FAIL" : "WARN")
                        .append("\">").append(esc(i.kind())).append("</span> <b>").append(esc(i.title())).append("</b> <span class=\"small\">— ")
                        .append(esc(i.host())).append(" · risk ").append(i.weight()).append(" · clears ").append(i.resolves().size())
                        .append("</span><br>").append(esc(i.why()));
                if (i.fix() != null && i.fix().command() != null) {
                    b.append("<pre>").append(esc(i.fix().command())).append("</pre>");
                }
                if (i.fix() != null && (i.fix().reboot() || i.fix().note() != null)) {
                    b.append("<div class=\"small\">").append(i.fix().reboot() ? "Takes effect after a restart. " : "")
                            .append(esc(i.fix().note() == null ? "" : i.fix().note())).append("</div>");
                }
                if (!i.mayBreak().isEmpty()) {
                    b.append("<div class=\"small\">⚠ May break: ").append(esc(String.join(", ", i.mayBreak())))
                            .append(" (seen relying on the weak behaviour)</div>");
                }
                b.append("</li>");
            }
            b.append("</ol>");
        }

        b.append("<h2>Executive summary</h2><ul>");
        ReportText.executiveSummary(r).forEach(l -> b.append("<li>").append(esc(l)).append("</li>"));
        b.append("</ul>");

        if (r.score != null) {
            b.append("<h2>Score and coverage</h2><div class=\"score\"><div><span class=\"big\">")
                    .append(r.score.score() == null ? "n/a" : r.score.score()).append("</span> <span class=\"grade\">/ 100 · grade ")
                    .append(esc(r.score.grade())).append("</span></div><div>worst case <b>")
                    .append(r.score.worstCase() == null ? "n/a" : r.score.worstCase()).append("</b></div><div>coverage <b>")
                    .append(r.score.coverage()).append("%</b> (").append(r.score.ran()).append(" ran, ").append(r.score.unknown())
                    .append(" could not run)</div></div>");
            b.append("<div class=\"scroll\"><table><tr><th>Category</th><th>Score</th><th>Worst case</th><th>Pass</th><th>Warn</th><th>Fail</th><th>Unknown</th></tr>");
            for (CategoryScore c : r.score.categories()) {
                b.append("<tr><td>").append(esc(c.category())).append("</td><td>").append(c.score() == null ? "n/a" : c.score())
                        .append("</td><td>").append(c.worstCase() == null ? "n/a" : c.worstCase()).append("</td><td>").append(c.pass())
                        .append("</td><td>").append(c.warn()).append("</td><td>").append(c.fail()).append("</td><td>").append(c.unknown()).append("</td></tr>");
            }
            b.append("</table></div><p class=\"small\">").append(esc(r.score.formula())).append(" See docs/SCORING.md.</p>");
        }

        b.append("<h2>Top risks</h2>");
        List<Finding> top = ReportText.topRisks(r);
        if (top.isEmpty()) {
            b.append("<p>No failing or warning findings.</p>");
        } else {
            b.append("<ol>");
            for (Finding f : top) {
                b.append("<li>").append(pill(f.status().name())).append(" <span class=\"id\">").append(esc(f.id())).append("</span> <b>")
                        .append(esc(f.title())).append("</b>").append(subject(f)).append(" — ").append(esc(f.summary())).append("</li>");
            }
            b.append("</ol>");
        }

        b.append("<h2>Findings by category</h2>");
        for (Map.Entry<String, List<Finding>> e : ReportText.byCategory(r).entrySet()) {
            b.append("<h3>").append(esc(e.getKey())).append("</h3>");
            for (Finding f : e.getValue()) {
                finding(b, f);
            }
        }

        if (!r.boundaries.isEmpty()) {
            b.append("<h2>Segment boundary crossings</h2><div class=\"scroll\"><table><tr><th>From</th><th>To</th><th>Protocol</th><th>Port</th><th>Flows</th><th>Cleartext</th></tr>");
            for (Report.BoundaryCrossing c : r.boundaries) {
                b.append("<tr><td>").append(esc(c.fromSegment())).append("</td><td>").append(esc(c.toSegment())).append("</td><td>")
                        .append(esc(c.protocol())).append("</td><td>").append(c.port()).append("</td><td>").append(c.flows())
                        .append("</td><td>").append(c.cleartext() ? pill("FAIL") : "no").append("</td></tr>");
            }
            b.append("</table></div>");
        }

        if (r.baseline != null) {
            var d = r.baseline;
            b.append("<h2>Compared with baseline</h2><p>Baseline from ").append(esc(d.baselineGeneratedAt())).append(": score ")
                    .append(d.previousScore()).append(" → ").append(d.currentScore()).append("</p>");
            changes(b, "Regressed", d.regressed());
            changes(b, "Improved", d.improved());
            changes(b, "New problems", d.appeared());
            changes(b, "Problems no longer present", d.disappeared());
        }

        b.append("<h2>Appendix: checks that could not run</h2>");
        List<Finding> unknown = ReportText.couldNotRun(r);
        if (unknown.isEmpty()) {
            b.append("<p>All applicable checks ran.</p>");
        } else {
            b.append("<ul>");
            for (Finding f : unknown) {
                b.append("<li><span class=\"id\">").append(esc(f.id())).append("</span> ").append(esc(f.title())).append(subject(f))
                        .append(" — ").append(esc(f.summary())).append("</li>");
            }
            b.append("</ul>");
        }
        if (!r.notes.isEmpty()) {
            b.append("<h2>Notes</h2><ul>");
            r.notes.forEach(n -> b.append("<li>").append(esc(n)).append("</li>"));
            b.append("</ul>");
        }
        b.append("<p class=\"small\">Gainsay is read-only and passive by default. Evidence is redacted; no payloads, passwords, cookies or tokens are stored.</p>");
        b.append("</main></body></html>\n");
        return b.toString();
    }

    private static void finding(StringBuilder b, Finding f) {
        b.append("<details><summary>").append(pill(f.status().name())).append(" <span class=\"id\">").append(esc(f.id()))
                .append(" · ").append(esc(f.severity().name().toLowerCase(Locale.ROOT))).append("</span> <b>").append(esc(f.title()))
                .append("</b>").append(subject(f)).append("</summary><p>").append(esc(f.summary())).append("</p>");
        if (f.occurrences() > 1 || f.firstSeen() != null) {
            b.append("<p class=\"small\">Seen ").append(f.occurrences()).append("×");
            if (f.firstSeen() != null) {
                b.append(" between ").append(esc(String.valueOf(f.firstSeen()))).append(" and ").append(esc(String.valueOf(f.lastSeen())));
            }
            b.append("</p>");
        }
        b.append("<dl><dt>Why it matters</dt><dd>").append(esc(f.rationale())).append("</dd>")
                .append("<dt>How it was verified</dt><dd>").append(esc(f.howVerified())).append("</dd>");
        if (!f.evidence().isEmpty()) {
            b.append("<dt>Proof</dt><dd><ul class=\"proof\">");
            f.evidence().forEach(e -> proof(b, e));
            b.append("</ul></dd>");
        }
        b.append("<dt>How to fix</dt><dd>").append(esc(f.remediation()));
        if (f.fix() != null && f.fix().command() != null) {
            b.append("<pre>").append(esc(f.fix().command())).append("</pre><span class=\"small\">Elevated PowerShell; Gainsay never runs it")
                    .append(f.fix().reboot() ? " · restart needed" : "").append(".</span>");
        }
        b.append("</dd>");
        if (!f.references().isEmpty()) {
            b.append("<dt>References</dt><dd>").append(esc(String.join(" · ", f.references()))).append("</dd>");
        }
        b.append("</dl></details>");
    }

    private static void proof(StringBuilder b, Evidence e) {
        b.append("<li><i>").append(esc(e.kind())).append("</i> ").append(esc(e.source())).append(": <code>")
                .append(esc(e.detail())).append("</code>");
        if (e.reproduce() != null) {
            b.append("<br><span class=\"small\">reproduce by hand:</span> <code>").append(esc(e.reproduce())).append("</code>");
        }
        b.append("</li>");
    }

    private static void changes(StringBuilder b, String title, List<Report.Change> list) {
        if (list.isEmpty()) {
            return;
        }
        b.append("<h3>").append(esc(title)).append("</h3><ul>");
        for (Report.Change c : list) {
            b.append("<li><span class=\"id\">").append(esc(c.key())).append("</span> ").append(esc(c.title())).append(": ")
                    .append(esc(c.from())).append(" → ").append(esc(c.to())).append("</li>");
        }
        b.append("</ul>");
    }

    private static String pill(String label) {
        return "<span class=\"pill " + esc(label) + "\">" + esc(label) + "</span>";
    }

    private static String subject(Finding f) {
        return f.subject().isEmpty() ? "" : " <span class=\"small\">— " + esc(f.subject()) + "</span>";
    }

    /** HTML-escapes untrusted text (element content and quoted attribute values). */
    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<' -> b.append("&lt;");
                case '>' -> b.append("&gt;");
                case '&' -> b.append("&amp;");
                case '"' -> b.append("&quot;");
                case '\'' -> b.append("&#39;");
                default -> b.append(c);
            }
        }
        return b.toString();
    }
}
