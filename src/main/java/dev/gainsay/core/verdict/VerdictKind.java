package dev.gainsay.core.verdict;

/** The outcome of cross-examining one claim (or one unclaimed behaviour) against the evidence. */
public enum VerdictKind {
    /** Configuration and traffic disagree. */
    CONTRADICTED,
    /** Traffic was seen that could have disagreed, and it agreed. */
    CORROBORATED,
    /** No traffic was seen that could test the claim. Absence of evidence is not evidence. */
    UNTESTED,
    /** Risky behaviour was seen for which no audited host made a claim. */
    UNCLAIMED
}
