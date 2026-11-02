package dev.gainsay.core.score;

import java.util.List;

/**
 * Overall and per-category scores. {@code score} is null when nothing scorable ran.
 *
 * @param score         measured score 0–100 over checks that ran
 * @param grade         letter grade of {@code score} (secondary; the trial coverage is the headline)
 * @param worstCase     score if every UNKNOWN check had failed
 * @param ran           checks that produced PASS/WARN/FAIL
 * @param unknown       checks that could not run
 * @param applicable    ran + unknown
 * @param coverage      percentage of applicable checks that ran
 */
public record ScoreCard(
        Double score,
        String grade,
        Double worstCase,
        int ran,
        int unknown,
        int applicable,
        double coverage,
        List<CategoryScore> categories,
        String formula) {
}
