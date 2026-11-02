package dev.gainsay.core.verdict;

import java.util.List;

/**
 * Headline numbers of the trial. {@code coverage} is the share of network-testable claims that
 * traffic actually put to the test: (corroborated + contradicted) / claims.
 */
public record TrialSummary(
        int claims,
        int contradicted,
        int corroborated,
        int untested,
        int unclaimed,
        double coverage,
        List<String> warnings) {

    public TrialSummary {
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }

    public int tested() {
        return contradicted + corroborated;
    }
}
