package dev.gainsay.core.verdict;

import java.util.List;

/**
 * Result of one cross-examination.
 *
 * @param kind        contradicted / corroborated / untested / unclaimed
 * @param claimType   the behaviour under test
 * @param hostLabel   hostname (audited host) or IP (unclaimed behaviour)
 * @param claim       the testimony; null for {@link VerdictKind#UNCLAIMED}
 * @param evidence    the observations that decided the verdict (bounded)
 * @param matchedBy   how the evidence was tied to the host: "ip", "mac" or "" if none
 * @param dependants  peers seen relying on the weak behaviour; they may break if it is fixed
 * @param surprise    ranking score; higher = more surprising contradiction (see SCORING.md)
 * @param explanation plain-language reading of the verdict, including what could explain it
 */
public record Verdict(
        VerdictKind kind,
        ClaimType claimType,
        String hostLabel,
        Claim claim,
        List<Observation> evidence,
        String matchedBy,
        List<String> dependants,
        double surprise,
        String explanation) {

    public static final int MAX_EVIDENCE = 5;

    public Verdict {
        evidence = evidence == null ? List.of() : List.copyOf(evidence.subList(0, Math.min(evidence.size(), MAX_EVIDENCE)));
        dependants = dependants == null ? List.of() : List.copyOf(dependants);
        matchedBy = matchedBy == null ? "" : matchedBy;
    }
}
