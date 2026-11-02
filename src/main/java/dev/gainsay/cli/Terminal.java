package dev.gainsay.cli;

import dev.gainsay.core.Report;
import dev.gainsay.report.ReportText;
import picocli.CommandLine.Help.Ansi;

import java.io.PrintWriter;
import java.util.List;

/**
 * Human-friendly terminal output: a short headline, the score, and the top "fix these first" actions.
 * Colours are used only when the terminal supports them (picocli's Ansi.AUTO; NO_COLOR is respected).
 */
final class Terminal {

    static final int TOP_FIXES = 5;
    static final int MAX_INLINE_COMMAND = 100;

    private Terminal() {
    }

    static String style(String styles, String text) {
        // picocli markup uses @|style text|@; neutralise any markup characters in data-derived text
        return Ansi.AUTO.string("@|" + styles + " " + text.replace("|@", "| @").replace("@|", "@ |") + "|@");
    }

    static void step(PrintWriter out, int n, int total, String what) {
        out.println(style("faint", "[" + n + "/" + total + "]") + " " + what);
        out.flush();
    }

    static void summary(Report r, PrintWriter out) {
        String trial = ReportText.trialHeadline(r);
        if (trial != null) {
            out.println(style("bold", trial));
        }
        for (String line : ReportText.executiveSummary(r)) {
            if (!line.equals(trial)) {
                out.println(line);
            }
        }
        List<Report.FixItem> plan = r.fixPlan;
        if (plan.isEmpty()) {
            out.println(style("green,bold", "Nothing to fix in what was checked."));
            return;
        }
        out.println();
        out.println(style("bold,underline", "Fix these first"));
        for (Report.FixItem i : plan.subList(0, Math.min(TOP_FIXES, plan.size()))) {
            String kind = switch (i.kind()) {
                case "INVESTIGATE" -> style("magenta,bold", "INVESTIGATE");
                case "FIX" -> style("red,bold", "FIX        ");
                default -> style("yellow,bold", "NETWORK    ");
            };
            out.println(" " + i.rank() + ". " + kind + " " + i.title() + style("faint", "  (" + i.host() + ", clears " + i.resolves().size() + ")"));
            if (i.fix() != null && i.fix().command() != null) {
                String cmd = i.fix().command();
                String shown = cmd.length() <= MAX_INLINE_COMMAND ? style("cyan", cmd)
                        : style("faint", "fix command: ") + style("cyan", "gainsay explain " + i.checkId());
                out.println("      " + shown + (i.fix().reboot() ? style("faint", "  [restart]") : ""));
            } else if (i.kind().equals("INVESTIGATE")) {
                out.println("      " + style("faint", "why this may happen: ") + style("cyan", "gainsay explain " + i.checkId()));
            }
            if (!i.mayBreak().isEmpty()) {
                out.println("      " + style("yellow", "may break: " + String.join(", ", i.mayBreak())));
            }
        }
        if (plan.size() > TOP_FIXES) {
            out.println(style("faint", "   … " + (plan.size() - TOP_FIXES) + " more in the report. Commands are never run by Gainsay."));
        }
    }
}
