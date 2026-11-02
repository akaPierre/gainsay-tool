package dev.gainsay.report;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.score.CategoryScore;
import dev.gainsay.core.verdict.Verdict;

import java.util.List;
import java.util.Map;

/** Renders {@code report.md}. All data-derived text goes through {@link #md(String)}. */
public final class MarkdownReportWriter {

    private MarkdownReportWriter() {
    }

    public static String render(Report r) {
        StringBuilder b = new StringBuilder(16_384);
        b.append("# Gainsay report\n\n");
        b.append("Generated ").append(r.generatedAt).append(" · Gainsay ").append(r.tool.get("version"))
                .append(" · planes: ").append(String.join(", ", r.kinds)).append("\n\n");
        for (Report.HostInfo h : r.hosts) {
            b.append("- Host **").append(md(h.identity().label())).append("** (").append(md(h.os())).append(") — ")
                    .append(md(String.join(", ", h.identity().ips()))).append(" — collected ").append(h.collectedAt())
                    .append(h.elevated() ? " (elevated)" : " (not elevated)").append(" from ").append(md(h.source())).append('\n');
        }
        for (Report.CaptureInfo c : r.captures) {
            b.append("- Capture ").append(md(c.source())).append(": ").append(c.packets()).append(" packets, ")
                    .append(c.malformed()).append(" malformed, ").append(c.start()).append(" → ").append(c.end()).append('\n');
        }
        b.append('\n');

        if (r.trial != null) {
            b.append("## Testimony vs evidence\n\n");
            b.append("> ").append(md(ReportText.trialHeadline(r))).append("\n\n");
            for (String w : r.trial.warnings()) {
                b.append("> ⚠ ").append(md(w)).append("\n\n");
            }
            b.append("| Verdict | Claim | Host | Testimony | Evidence | Blast radius |\n|---|---|---|---|---|---|\n");
            for (Verdict v : r.verdicts) {
                b.append("| ").append(ReportText.verdictLabel(v.kind())).append(" | ").append(md(v.claimType().title()))
                        .append(" | ").append(md(v.hostLabel())).append(" | ").append(md(ReportText.testimony(v)))
                        .append(" | ").append(md(ReportText.evidenceSummary(v))).append(" | ")
                        .append(v.dependants().isEmpty() ? "—" : md(String.join(", ", v.dependants()))).append(" |\n");
            }
            b.append('\n');
            for (Verdict v : r.verdicts) {
                if (v.kind() == dev.gainsay.core.verdict.VerdictKind.CONTRADICTED
                        || v.kind() == dev.gainsay.core.verdict.VerdictKind.UNCLAIMED) {
                    b.append("- **").append(ReportText.verdictLabel(v.kind())).append(" — ").append(md(v.claimType().title()))
                            .append(" on ").append(md(v.hostLabel())).append("** (surprise ").append(v.surprise()).append("): ")
                            .append(md(v.explanation())).append('\n');
                }
            }
            b.append('\n');
        }

        if (!r.fixPlan.isEmpty()) {
            b.append("## Fix these first\n\n");
            b.append("Ranked by how much risk each action removes. Gainsay never runs these commands; review them and run them yourself in an "
                    + "elevated PowerShell.\n\n");
            for (Report.FixItem i : r.fixPlan.subList(0, Math.min(ReportText.FIX_PLAN_SIZE, r.fixPlan.size()))) {
                b.append(i.rank()).append(". **").append(i.kind()).append("** · ").append(md(i.host())).append(" — **").append(md(i.title()))
                        .append("** (risk ").append(i.weight()).append(", clears ").append(i.resolves().size()).append(" finding")
                        .append(i.resolves().size() == 1 ? "" : "s").append(")\n");
                b.append("   ").append(md(i.why())).append('\n');
                if (i.fix() != null && i.fix().command() != null) {
                    b.append("\n   ```powershell\n   ").append(i.fix().command().replace("```", "'''")).append("\n   ```\n");
                }
                if (i.fix() != null && i.fix().reboot()) {
                    b.append("   _Takes effect after a restart._\n");
                }
                if (i.fix() != null && i.fix().note() != null) {
                    b.append("   _Note: ").append(md(i.fix().note())).append("_\n");
                }
                if (!i.mayBreak().isEmpty()) {
                    b.append("   ⚠ May break: ").append(md(String.join(", ", i.mayBreak()))).append(" (seen relying on the weak behaviour)\n");
                }
                b.append('\n');
            }
        }

        b.append("## Executive summary\n\n");
        for (String line : ReportText.executiveSummary(r)) {
            b.append("- ").append(md(line)).append('\n');
        }
        b.append('\n');

        if (r.score != null) {
            b.append("## Score and coverage\n\n");
            b.append("Measured score: **").append(r.score.score() == null ? "n/a" : r.score.score()).append("** (grade ")
                    .append(r.score.grade()).append(") · worst case: ").append(r.score.worstCase() == null ? "n/a" : r.score.worstCase())
                    .append(" · coverage: ").append(r.score.coverage()).append("% (").append(r.score.ran()).append(" ran, ")
                    .append(r.score.unknown()).append(" could not run)\n\n");
            b.append("| Category | Score | Worst case | Pass | Warn | Fail | Unknown |\n|---|---|---|---|---|---|---|\n");
            for (CategoryScore c : r.score.categories()) {
                b.append("| ").append(md(c.category())).append(" | ").append(c.score() == null ? "n/a" : c.score())
                        .append(" | ").append(c.worstCase() == null ? "n/a" : c.worstCase()).append(" | ").append(c.pass())
                        .append(" | ").append(c.warn()).append(" | ").append(c.fail()).append(" | ").append(c.unknown()).append(" |\n");
            }
            b.append("\nFormula: ").append(md(r.score.formula())).append(" See docs/SCORING.md.\n\n");
        }

        List<Finding> top = ReportText.topRisks(r);
        b.append("## Top risks\n\n");
        if (top.isEmpty()) {
            b.append("No failing or warning findings.\n\n");
        }
        int i = 1;
        for (Finding f : top) {
            b.append(i++).append(". **").append(f.status()).append(" / ").append(f.severity()).append("** `").append(f.id())
                    .append("` ").append(md(f.title())).append(subject(f)).append(" — ").append(md(f.summary())).append('\n');
        }
        b.append('\n');

        b.append("## Findings by category\n\n");
        for (Map.Entry<String, List<Finding>> e : ReportText.byCategory(r).entrySet()) {
            b.append("### ").append(md(e.getKey())).append("\n\n");
            for (Finding f : e.getValue()) {
                finding(b, f);
            }
        }

        if (!r.boundaries.isEmpty()) {
            b.append("## Segment boundary crossings\n\n| From | To | Protocol | Port | Flows | Cleartext |\n|---|---|---|---|---|---|\n");
            for (Report.BoundaryCrossing c : r.boundaries) {
                b.append("| ").append(md(c.fromSegment())).append(" | ").append(md(c.toSegment())).append(" | ")
                        .append(md(c.protocol())).append(" | ").append(c.port()).append(" | ").append(c.flows()).append(" | ")
                        .append(c.cleartext() ? "**yes**" : "no").append(" |\n");
            }
            b.append('\n');
        }

        if (r.baseline != null) {
            var d = r.baseline;
            b.append("## Compared with baseline\n\n");
            b.append("Baseline from ").append(d.baselineGeneratedAt()).append(": score ").append(d.previousScore())
                    .append(" → ").append(d.currentScore()).append("\n\n");
            changes(b, "Regressed", d.regressed());
            changes(b, "Improved", d.improved());
            changes(b, "New problems", d.appeared());
            changes(b, "Problems no longer present", d.disappeared());
        }

        List<Finding> unknown = ReportText.couldNotRun(r);
        b.append("## Appendix: checks that could not run\n\n");
        if (unknown.isEmpty()) {
            b.append("All applicable checks ran.\n");
        }
        for (Finding f : unknown) {
            b.append("- `").append(f.id()).append("` ").append(md(f.title())).append(subject(f)).append(" — ")
                    .append(md(f.summary())).append('\n');
        }
        if (!r.notes.isEmpty()) {
            b.append("\n## Notes\n\n");
            r.notes.forEach(n -> b.append("- ").append(md(n)).append('\n'));
        }
        return b.toString();
    }

    private static void finding(StringBuilder b, Finding f) {
        b.append("#### ").append(f.status()).append(" · ").append(f.severity()).append(" · `").append(f.id()).append("` ")
                .append(md(f.title())).append(subject(f)).append("\n\n");
        b.append(md(f.summary())).append("\n\n");
        if (f.occurrences() > 1 || f.firstSeen() != null) {
            b.append("Seen ").append(f.occurrences()).append("×");
            if (f.firstSeen() != null) {
                b.append(" between ").append(f.firstSeen()).append(" and ").append(f.lastSeen());
            }
            b.append("\n\n");
        }
        b.append("- **Why it matters:** ").append(md(f.rationale())).append('\n');
        b.append("- **How it was verified:** ").append(md(f.howVerified())).append('\n');
        if (!f.evidence().isEmpty()) {
            b.append("- **Proof:**\n");
            for (Evidence e : f.evidence()) {
                b.append("  - _").append(md(e.kind())).append("_ ").append(md(e.source())).append(": `")
                        .append(code(e.detail())).append("`\n");
                if (e.reproduce() != null) {
                    b.append("    - reproduce by hand: `").append(code(e.reproduce())).append("`\n");
                }
            }
        }
        b.append("- **How to fix:** ").append(md(f.remediation())).append('\n');
        if (f.fix() != null && f.fix().command() != null) {
            b.append("- **Fix command** (elevated PowerShell, not run by Gainsay): `").append(code(f.fix().command())).append("`")
                    .append(f.fix().reboot() ? " — restart needed" : "").append('\n');
        }
        if (!f.references().isEmpty()) {
            b.append("- **References:** ").append(md(String.join(" · ", f.references()))).append('\n');
        }
        b.append('\n');
    }

    private static void changes(StringBuilder b, String title, List<Report.Change> list) {
        if (list.isEmpty()) {
            return;
        }
        b.append("**").append(title).append("**\n\n");
        for (Report.Change c : list) {
            b.append("- `").append(code(c.key())).append("` ").append(md(c.title())).append(": ").append(c.from())
                    .append(" → ").append(c.to()).append('\n');
        }
        b.append('\n');
    }

    private static String subject(Finding f) {
        return f.subject().isEmpty() ? "" : " — " + md(f.subject());
    }

    /** Escapes Markdown/HTML-significant characters in untrusted text and flattens newlines. */
    static String md(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '|' -> b.append("\\|");
                case '<' -> b.append("&lt;");
                case '>' -> b.append("&gt;");
                case '&' -> b.append("&amp;");
                case '`' -> b.append('\'');
                case '*', '_', '[', ']', '\\', '#' -> b.append('\\').append(c);
                case '\n', '\r' -> b.append(' ');
                default -> b.append(c);
            }
        }
        return b.toString();
    }

    /** Text inside an inline code span: only backticks and newlines need neutralising. */
    static String code(String s) {
        if (s == null) {
            return "";
        }
        return s.replace('`', '\'').replace('\n', ' ').replace('\r', ' ');
    }
}
