package dev.gainsay.core;

/**
 * Outcome of one check or analyzer.
 * <ul>
 *   <li>{@link #PASS} the best practice is in place.</li>
 *   <li>{@link #WARN} partially in place, or relying on an OS default that varies by build.</li>
 *   <li>{@link #FAIL} the best practice is not in place.</li>
 *   <li>{@link #UNKNOWN} the check could not run (permission, missing feature, command failed).
 *       Never counted as a pass.</li>
 *   <li>{@link #NOT_APPLICABLE} the check does not apply (e.g. no TLS traffic to judge).</li>
 * </ul>
 */
public enum Status {
    PASS, WARN, FAIL, UNKNOWN, NOT_APPLICABLE;

    /** Rank for "worst status wins" aggregation: FAIL &gt; WARN &gt; PASS &gt; UNKNOWN &gt; NOT_APPLICABLE. */
    public int badness() {
        return switch (this) {
            case FAIL -> 4;
            case WARN -> 3;
            case PASS -> 2;
            case UNKNOWN -> 1;
            case NOT_APPLICABLE -> 0;
        };
    }

    public boolean isProblem() {
        return this == FAIL || this == WARN;
    }
}
