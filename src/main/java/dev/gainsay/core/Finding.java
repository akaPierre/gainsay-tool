package dev.gainsay.core;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * One graded result. Host checks produce exactly one finding per check; network analyzers produce
 * one finding per (check id, subject) pair plus, where traffic was seen, a summary finding.
 *
 * <p>Every finding teaches: {@code rationale} says why it matters, {@code howVerified} says how
 * Gainsay checked it, {@code remediation} says how to fix it, and {@code evidence} holds the proof.
 */
public record Finding(
        String id,
        Plane plane,
        String category,
        String title,
        Severity severity,
        Status status,
        String subject,
        String summary,
        List<Evidence> evidence,
        String rationale,
        String howVerified,
        String remediation,
        Fix fix,
        List<String> references,
        Instant firstSeen,
        Instant lastSeen,
        long occurrences) {

    /** Hard cap on evidence items kept per finding, so repeated observations cannot grow memory. */
    public static final int MAX_EVIDENCE = 5;

    public Finding {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(plane, "plane");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(status, "status");
        subject = subject == null ? "" : Redactor.sanitize(subject);
        summary = Redactor.sanitize(summary);
        evidence = evidence == null ? List.of() : List.copyOf(evidence.subList(0, Math.min(evidence.size(), MAX_EVIDENCE)));
        references = references == null ? List.of() : List.copyOf(references);
        occurrences = Math.max(occurrences, 1);
    }

    /** Identity used for merging and baseline comparison. */
    @JsonIgnore
    public String key() {
        return subject.isEmpty() ? id : id + "@" + subject;
    }

    /** Combines two findings with the same key: counts add up, time window widens, evidence is kept bounded. */
    public Finding mergedWith(Finding other) {
        List<Evidence> ev = new ArrayList<>(evidence);
        for (Evidence e : other.evidence) {
            if (ev.size() >= MAX_EVIDENCE) {
                break;
            }
            if (!ev.contains(e)) {
                ev.add(e);
            }
        }
        Status worst = status.badness() >= other.status.badness() ? status : other.status;
        return new Finding(id, plane, category, title, Severity.max(severity, other.severity), worst, subject,
                worst == status ? summary : other.summary, ev, rationale, howVerified, remediation, fix != null ? fix : other.fix, references,
                min(firstSeen, other.firstSeen), max(lastSeen, other.lastSeen), occurrences + other.occurrences);
    }

    public Finding withStatus(Status newStatus, String newSummary) {
        return new Finding(id, plane, category, title, severity, newStatus, subject, newSummary, evidence, rationale,
                howVerified, remediation, fix, references, firstSeen, lastSeen, occurrences);
    }

    private static Instant min(Instant a, Instant b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.isBefore(b) ? a : b;
    }

    private static Instant max(Instant a, Instant b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.isAfter(b) ? a : b;
    }

    public static Builder builder(String id, Plane plane) {
        return new Builder(id, plane);
    }

    /** Fluent builder; checks and analyzers fill the static metadata once and vary status/summary/evidence. */
    public static final class Builder {
        private final String id;
        private final Plane plane;
        private String category = "";
        private String title = "";
        private Severity severity = Severity.INFO;
        private Status status = Status.UNKNOWN;
        private String subject = "";
        private String summary = "";
        private final List<Evidence> evidence = new ArrayList<>();
        private String rationale = "";
        private String howVerified = "";
        private String remediation = "";
        private Fix fix;
        private List<String> references = List.of();
        private Instant firstSeen;
        private Instant lastSeen;
        private long occurrences = 1;

        private Builder(String id, Plane plane) {
            this.id = id;
            this.plane = plane;
        }

        public Builder category(String v) { this.category = v; return this; }
        public Builder title(String v) { this.title = v; return this; }
        public Builder severity(Severity v) { this.severity = v; return this; }
        public Builder status(Status v) { this.status = v; return this; }
        public Builder subject(String v) { this.subject = v; return this; }
        public Builder summary(String v) { this.summary = v; return this; }
        public Builder evidence(Evidence e) { if (e != null && evidence.size() < MAX_EVIDENCE) evidence.add(e); return this; }
        public Builder evidence(List<Evidence> es) { es.forEach(this::evidence); return this; }
        public Builder rationale(String v) { this.rationale = v; return this; }
        public Builder howVerified(String v) { this.howVerified = v; return this; }
        public Builder remediation(String v) { this.remediation = v; return this; }
        public Builder fix(Fix v) { this.fix = v; return this; }
        public Builder references(List<String> v) { this.references = v; return this; }
        public Builder seen(Instant first, Instant last) { this.firstSeen = first; this.lastSeen = last; return this; }
        public Builder occurrences(long v) { this.occurrences = v; return this; }

        public Finding build() {
            return new Finding(id, plane, category, title, severity, status, subject, summary, evidence, rationale,
                    howVerified, remediation, fix, references, firstSeen, lastSeen, occurrences);
        }
    }
}
