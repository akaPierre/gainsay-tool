package dev.gainsay.report;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.Report.BaselineDiff;
import dev.gainsay.core.Report.Change;
import dev.gainsay.core.Status;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Compares two reports finding-by-finding (keyed by check id + subject). */
public final class BaselineComparator {

    private BaselineComparator() {
    }

    public static BaselineDiff compare(Report before, Report after) {
        Map<String, Finding> old = index(before.findings);
        Map<String, Finding> now = index(after.findings);
        List<Change> regressed = new ArrayList<>();
        List<Change> improved = new ArrayList<>();
        List<Change> appeared = new ArrayList<>();
        List<Change> disappeared = new ArrayList<>();
        for (Finding f : now.values()) {
            Finding o = old.get(f.key());
            if (o == null) {
                if (f.status().isProblem()) {
                    appeared.add(new Change(f.key(), f.title(), "-", f.status().name()));
                }
                continue;
            }
            int delta = rank(f.status()) - rank(o.status());
            Change c = new Change(f.key(), f.title(), o.status().name(), f.status().name());
            if (delta > 0) {
                regressed.add(c);
            } else if (delta < 0) {
                improved.add(c);
            }
        }
        for (Finding o : old.values()) {
            if (!now.containsKey(o.key()) && o.status().isProblem()) {
                disappeared.add(new Change(o.key(), o.title(), o.status().name(), "-"));
            }
        }
        Double prev = before.score == null ? null : before.score.score();
        Double cur = after.score == null ? null : after.score.score();
        return new BaselineDiff(before.generatedAt == null ? null : before.generatedAt.toString(), prev, cur,
                regressed, improved, appeared, disappeared);
    }

    /** Ordering for "got worse": PASS/NA &lt; UNKNOWN &lt; WARN &lt; FAIL. */
    private static int rank(Status s) {
        return switch (s) {
            case PASS, NOT_APPLICABLE -> 0;
            case UNKNOWN -> 1;
            case WARN -> 2;
            case FAIL -> 3;
        };
    }

    private static Map<String, Finding> index(List<Finding> findings) {
        Map<String, Finding> m = new LinkedHashMap<>();
        for (Finding f : findings) {
            m.merge(f.key(), f, Finding::mergedWith);
        }
        return m;
    }
}
