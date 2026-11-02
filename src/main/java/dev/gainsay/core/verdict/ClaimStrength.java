package dev.gainsay.core.verdict;

/**
 * How firmly a host asserts a setting. A contradiction against a Group Policy value is more
 * surprising (and more worth investigating) than one against an undocumented OS default.
 */
public enum ClaimStrength {
    /** Set by Group Policy / MDM (HKLM\SOFTWARE\Policies or equivalent). */
    POLICY(1.0),
    /** Reported as the effective state by a Windows cmdlet or WMI provider. */
    MEASURED(0.9),
    /** An explicit local registry value. */
    LOCAL(0.8),
    /** Nothing configured; the claim is the OS default, which varies by build. */
    DEFAULT(0.5);

    private final double weight;

    ClaimStrength(double weight) {
        this.weight = weight;
    }

    public double weight() {
        return weight;
    }
}
