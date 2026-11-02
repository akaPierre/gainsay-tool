package dev.gainsay.report;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.Verdict;
import dev.gainsay.core.verdict.VerdictKind;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Wording shared by the Markdown and HTML writers, so both say exactly the same thing. */
public final class ReportText {

    static final int TOP_RISKS = 10;
    public static final int FIX_PLAN_SIZE = 10;

    private ReportText() {
    }

    public static String trialHeadline(Report r) {
        if (r.trial == null) {
            return null;
        }
        var t = r.trial;
        return String.format("Trial coverage: %d of %d claims were put to the test by traffic (%.0f%%). "
                        + "%d contradicted, %d corroborated, %d untested; %d unclaimed behaviours.",
                t.tested(), t.claims(), t.coverage() * 100, t.contradicted(), t.corroborated(), t.untested(), t.unclaimed());
    }

    public static List<String> executiveSummary(Report r) {
        List<String> lines = new ArrayList<>();
        long fail = r.findings.stream().filter(f -> f.status() == Status.FAIL && f.severity().weight() > 0).count();
        long warn = r.findings.stream().filter(f -> f.status() == Status.WARN).count();
        long unknown = r.findings.stream().filter(f -> f.status() == Status.UNKNOWN).count();
        if (r.trial != null) {
            lines.add(trialHeadline(r));
            if (r.trial.contradicted() > 0) {
                lines.add("Contradictions mean a setting is configured but not in effect (or another device answers for the host). "
                        + "They are listed first because a configuration audit alone would have reported them as fine.");
            } else if (r.trial.tested() == 0) {
                lines.add("No claim was tested: the capture contained no traffic that exercises the audited settings. "
                        + "Treat the host results as unverified testimony.");
            }
        } else if (!r.hosts.isEmpty() && r.captures.isEmpty()) {
            lines.add("Host testimony only: no capture was provided, so none of the " + r.claims.size()
                    + " network-testable claims could be verified against real traffic. Run `gainsay audit` from an elevated prompt (it captures "
                    + "traffic too), or `gainsay net --claims-from` with a capture, to put them on trial.");
        } else if (r.hosts.isEmpty() && !r.captures.isEmpty()) {
            lines.add("Network evidence only: no host report was provided, so observed behaviour cannot be compared with configuration.");
        }
        if (r.score != null && r.score.score() != null) {
            lines.add(String.format("Measured score %.1f/100 (grade %s) over %d checks that ran; coverage %.0f%% (%d could not run); "
                            + "worst case if every unknown failed: %s.",
                    r.score.score(), r.score.grade(), r.score.ran(), r.score.coverage(), r.score.unknown(),
                    r.score.worstCase() == null ? "n/a" : String.format("%.1f", r.score.worstCase())));
        }
        lines.add(String.format("%d failing and %d warning findings; %d checks could not run.", fail, warn, unknown));
        return lines;
    }

    static List<Finding> topRisks(Report r) {
        return r.findings.stream()
                .filter(f -> f.status().isProblem() && f.severity().weight() > 0)
                .limit(TOP_RISKS)
                .toList();
    }

    static Map<String, List<Finding>> byCategory(Report r) {
        Map<String, List<Finding>> m = new LinkedHashMap<>();
        r.findings.stream()
                .filter(f -> f.status() != Status.UNKNOWN)
                .sorted((a, b) -> a.category().compareTo(b.category()))
                .forEach(f -> m.computeIfAbsent(f.category(), k -> new ArrayList<>()).add(f));
        m.values().forEach(l -> l.sort(ReportComposer.FINDING_ORDER));
        return m;
    }

    static List<Finding> couldNotRun(Report r) {
        return r.findings.stream().filter(f -> f.status() == Status.UNKNOWN).toList();
    }

    static String verdictLabel(VerdictKind k) {
        return switch (k) {
            case CONTRADICTED -> "CONTRADICTED";
            case CORROBORATED -> "CORROBORATED";
            case UNTESTED -> "UNTESTED";
            case UNCLAIMED -> "UNCLAIMED";
        };
    }

    static String testimony(Verdict v) {
        return v.claim() == null ? "(no claim)" : v.claim().statement() + " [" + v.claim().strength() + "]";
    }

    static String evidenceSummary(Verdict v) {
        if (v.evidence().isEmpty()) {
            return "â€”";
        }
        var o = v.evidence().get(0);
        long n = v.evidence().stream().mapToLong(x -> x.count()).sum();
        return o.type().meaning() + " Ã—" + n + (o.proof() != null ? " (" + o.proof().source() + ")" : "");
    }
}
