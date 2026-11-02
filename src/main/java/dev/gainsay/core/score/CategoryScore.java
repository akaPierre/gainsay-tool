package dev.gainsay.core.score;

/** Sub-score of one category; see {@link Scorer} for the formula. */
public record CategoryScore(
        String category,
        Double score,
        Double worstCase,
        double earned,
        double weight,
        int pass,
        int warn,
        int fail,
        int unknown,
        double coverage) {
}
