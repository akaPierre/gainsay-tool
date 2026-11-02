package dev.gainsay.host;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.host.source.HostDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs every check against a data source and gathers findings and testimony into a partial report.
 * A check that throws is isolated: it becomes UNKNOWN and the run continues.
 */
public final class HostAuditor {

    private HostAuditor() {
    }

    public static Report audit(HostDataSource ds, List<Check> checks) {
        Report r = new Report();
        r.kinds.add("host");
        r.hosts.add(new Report.HostInfo(ds.identity(), ds.collectedAt(), ds.elevated(), ds.os(), ds.sourceLabel()));
        List<Claim> claims = new ArrayList<>();
        for (Check c : checks) {
            r.findings.add(safeEvaluate(c, ds));
            try {
                claims.addAll(c.claims(ds));
            } catch (RuntimeException e) {
                // no testimony from a check that failed internally; its finding already says UNKNOWN
            }
        }
        r.claims.addAll(claims);
        if (!ds.elevated()) {
            r.notes.add("Host checks ran without elevation; reads that need an administrator prompt (BitLocker, TPM, audit policy) are reported as UNKNOWN.");
        }
        return r;
    }

    /** Runs a check without letting it crash the audit. */
    static Finding safeEvaluate(Check c, HostDataSource ds) {
        try {
            Finding f = c.evaluate(ds);
            if (f != null) {
                return f;
            }
            return failed(c, ds, "check returned no result");
        } catch (RuntimeException e) {
            return failed(c, ds, "internal error in check: " + e.getClass().getSimpleName());
        }
    }

    private static Finding failed(Check c, HostDataSource ds, String why) {
        return Finding.builder(c.id(), Plane.HOST).category(c.category()).title(c.title())
                .severity(c.severity() == null ? Severity.INFO : c.severity()).status(Status.UNKNOWN)
                .subject(ds.identity().label()).summary("Could not run: " + why).rationale(c.rationale())
                .howVerified(c.howVerified()).remediation(c.remediation()).references(c.references()).build();
    }

    /** Lets the live collector discover every read the checks perform (see RecordingHostDataSource). */
    public static void dryRun(HostDataSource recorder, List<Check> checks) {
        for (Check c : checks) {
            safeEvaluate(c, recorder);
            try {
                c.claims(recorder);
            } catch (RuntimeException ignored) {
                // recording only
            }
        }
    }
}
