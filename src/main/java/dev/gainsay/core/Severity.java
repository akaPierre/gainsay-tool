package dev.gainsay.core;

/**
 * How bad a failing finding is. Each level carries the weight used by the transparent scoring
 * model (see {@code docs/SCORING.md}); {@link #INFO} has weight 0 and never moves the score.
 */
public enum Severity {
    INFO(0), LOW(1), MEDIUM(3), HIGH(6), CRITICAL(10);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }

    public boolean atLeast(Severity other) {
        return compareTo(other) >= 0;
    }

    public static Severity max(Severity a, Severity b) {
        return a.compareTo(b) >= 0 ? a : b;
    }
}
