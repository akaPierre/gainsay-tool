package dev.gainsay.host;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * One Windows best practice, verified by reading (never changing) the host.
 *
 * <p>Implementations document in comments exactly how the setting is implemented in Windows
 * (registry path/value, WMI class or cmdlet), which is the learning goal of this module.
 */
public interface Check {

    /** Stable id, e.g. {@code HOST-CRED-001}. */
    String id();

    String title();

    String category();

    Severity severity();

    /** Why the practice matters. */
    String rationale();

    /** How Gainsay verifies it. */
    String howVerified();

    /** How to fix it. */
    String remediation();

    List<String> references();

    /** Evaluates the check. Must not throw; a check that cannot run returns status UNKNOWN with the reason. */
    Finding evaluate(HostDataSource ds);

    /**
     * Network-testable testimony derived from the same reads, for the trial. Most checks have no
     * network signature and return nothing.
     */
    default List<Claim> claims(HostDataSource ds) {
        return List.of();
    }
}
