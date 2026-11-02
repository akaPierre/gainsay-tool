package dev.gainsay.core.score;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Transparent scoring. Documented in {@code docs/SCORING.md}; the formula string is also embedded in
 * every report.
 *
 * <ol>
 *   <li>Findings are grouped by check id (per host for host and trial checks). A check's status is the worst status of its findings
 *       (FAIL &gt; WARN &gt; PASS &gt; UNKNOWN &gt; NOT_APPLICABLE); its weight is the weight of its highest severity.</li>
 *   <li>PASS earns the full weight, WARN half, FAIL nothing.</li>
 *   <li>UNKNOWN is never a pass: it is left out of the measured score, counted against coverage, and
 *       counted as a FAIL in the worst-case score shown next to it.</li>
 *   <li>NOT_APPLICABLE and INFO-severity checks are excluded.</li>
 *   <li>score = 100 × Σ earned / Σ weight, per category and overall.</li>
 * </ol>
 */
public final class Scorer {

    public static final String FORMULA =
            "score = 100 × Σ earned / Σ weight over checks that ran; weight: LOW 1, MEDIUM 3, HIGH 6, CRITICAL 10 (INFO 0); "
                    + "earned: PASS = weight, WARN = weight/2, FAIL = 0; UNKNOWN is excluded from the measured score and "
                    + "counted as FAIL in the worst-case score; coverage = checks that ran / checks that apply.";

    private Scorer() {
    }

    /** One graded check after aggregation. */
    record CheckOutcome(String id, String category, Status status, Severity severity) {
    }

    public static ScoreCard score(List<Finding> findings) {
        Map<String, CheckOutcome> checks = new LinkedHashMap<>();
        for (Finding f : findings) {
            checks.merge(scoringKey(f), new CheckOutcome(f.id(), f.category(), f.status(), f.severity()), (a, b) -> new CheckOutcome(
                    a.id(), a.category(),
                    a.status().badness() >= b.status().badness() ? a.status() : b.status(),
                    Severity.max(a.severity(), b.severity())));
        }
        Map<String, Acc> byCategory = new TreeMap<>();
        Acc total = new Acc();
        for (CheckOutcome c : checks.values()) {
            Acc cat = byCategory.computeIfAbsent(c.category(), k -> new Acc());
            cat.add(c);
            total.add(c);
        }
        List<CategoryScore> categories = new ArrayList<>();
        for (Map.Entry<String, Acc> e : byCategory.entrySet()) {
            categories.add(e.getValue().toCategory(e.getKey()));
        }
        Double overall = total.score();
        return new ScoreCard(overall, overall == null ? "n/a" : grade(overall), total.worstCase(), total.ran, total.unknown,
                total.applicable(), total.coverage(), categories, FORMULA);
    }

    /**
     * Host and trial checks are graded once per host (two audited machines are two sets of checks);
     * network checks are graded once per check id across all subjects (the network is one system).
     */
    static String scoringKey(Finding f) {
        return switch (f.plane()) {
            case HOST, TRIAL -> f.key();
            case NET, SCAN -> f.id();
        };
    }

    public static String grade(double score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }

    private static final class Acc {
        double earned;
        double weight;
        double unknownWeight;
        int ran;
        int unknown;
        int pass;
        int warn;
        int fail;

        void add(CheckOutcome c) {
            int w = c.severity().weight();
            if (w == 0) {
                return; // INFO checks inform; they never move the score or coverage
            }
            switch (c.status()) {
                case NOT_APPLICABLE -> {
                    return;
                }
                case UNKNOWN -> {
                    unknown++;
                    unknownWeight += w;
                    return;
                }
                case PASS -> {
                    pass++;
                    earned += w;
                }
                case WARN -> {
                    warn++;
                    earned += w / 2.0;
                }
                case FAIL -> fail++;
            }
            ran++;
            weight += w;
        }

        int applicable() {
            return ran + unknown;
        }

        Double score() {
            return weight == 0 ? null : round(100.0 * earned / weight);
        }

        Double worstCase() {
            double w = weight + unknownWeight;
            return w == 0 ? null : round(100.0 * earned / w);
        }

        double coverage() {
            return applicable() == 0 ? 0.0 : round(100.0 * ran / applicable());
        }

        CategoryScore toCategory(String name) {
            return new CategoryScore(name, score(), worstCase(), round(earned), round(weight), pass, warn, fail, unknown, coverage());
        }
    }

    static double round(double d) {
        return Math.round(d * 10.0) / 10.0;
    }
}
