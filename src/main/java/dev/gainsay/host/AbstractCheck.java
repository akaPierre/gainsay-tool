package dev.gainsay.host;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/** Holds a check's static metadata and offers concise result builders. */
public abstract class AbstractCheck implements Check {

    private final String id;
    private final String title;
    private final String category;
    private final Severity severity;
    private final String rationale;
    private final String howVerified;
    private final String remediation;
    private final List<String> references;

    protected AbstractCheck(String id, String title, String category, Severity severity, String rationale,
                            String howVerified, String remediation, List<String> references) {
        this.id = id;
        this.title = title;
        this.category = category;
        this.severity = severity;
        this.rationale = rationale;
        this.howVerified = howVerified;
        this.remediation = remediation;
        this.references = references;
    }

    @Override public String id() { return id; }
    @Override public String title() { return title; }
    @Override public String category() { return category; }
    @Override public Severity severity() { return severity; }
    @Override public String rationale() { return rationale; }
    @Override public String howVerified() { return howVerified; }
    @Override public String remediation() { return remediation; }
    @Override public List<String> references() { return references; }

    protected Finding result(HostDataSource ds, Status status, String summary, List<Evidence> evidence) {
        return Finding.builder(id, Plane.HOST)
                .category(category)
                .title(title)
                .severity(severity)
                .status(status)
                .subject(ds.identity().label())
                .summary(summary)
                .evidence(evidence)
                .rationale(rationale)
                .howVerified(howVerified)
                .remediation(remediation)
                .fix(status.isProblem() ? FixCommands.forCheck(id) : null)
                .references(references)
                .seen(ds.collectedAt(), ds.collectedAt())
                .build();
    }

    protected Finding pass(HostDataSource ds, String summary, List<Evidence> evidence) {
        return result(ds, Status.PASS, summary, evidence);
    }

    protected Finding warn(HostDataSource ds, String summary, List<Evidence> evidence) {
        return result(ds, Status.WARN, summary, evidence);
    }

    protected Finding fail(HostDataSource ds, String summary, List<Evidence> evidence) {
        return result(ds, Status.FAIL, summary, evidence);
    }

    protected Finding unknown(HostDataSource ds, String reason, List<Evidence> evidence) {
        return result(ds, Status.UNKNOWN, "Could not run: " + reason, evidence);
    }

    protected Finding notApplicable(HostDataSource ds, String reason, List<Evidence> evidence) {
        return result(ds, Status.NOT_APPLICABLE, reason, evidence);
    }

    /** Evidence for a structured query, with a by-hand reproduction command. */
    protected static Evidence queryEvidence(String queryId, String detail, String reproduce) {
        return new Evidence(queryId.startsWith("av.") || queryId.equals("bitlocker") || queryId.equals("tpm")
                || queryId.equals("deviceguard") || queryId.equals("os.info") || queryId.equals("service.state") ? "wmi" : "cmdlet",
                queryId, detail, reproduce);
    }

    protected static String reason(QueryResult q) {
        return q.why();
    }
}
