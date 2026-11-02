package dev.gainsay.report;

import dev.gainsay.core.Finding;
import dev.gainsay.core.HostIdentity;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report;
import dev.gainsay.core.Report.BoundaryCrossing;
import dev.gainsay.core.Report.CaptureInfo;
import dev.gainsay.core.Report.HostInfo;
import dev.gainsay.core.score.Scorer;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.Observation;
import dev.gainsay.core.verdict.Tribunal;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Merges one or more partial reports (host runs, captures, scans) into one, puts the claims on
 * trial when both testimony and evidence are present, scores the result and compares a baseline.
 * Every CLI command ends here, so all outputs are produced the same way.
 */
public final class ReportComposer {

    /** Testimony and evidence further apart than this get a warning on the trial. */
    static final Duration MAX_SKEW = Duration.ofHours(24);

    private ReportComposer() {
    }

    public static Report compose(List<Report> inputs, Report baseline) {
        Report out = new Report();
        Set<String> kinds = new LinkedHashSet<>();
        Map<String, Finding> findings = new LinkedHashMap<>();
        Map<String, Claim> claims = new LinkedHashMap<>();
        Map<String, Observation> observations = new LinkedHashMap<>();
        Map<String, BoundaryCrossing> boundaries = new LinkedHashMap<>();
        Set<String> notes = new LinkedHashSet<>();
        Set<HostIdentity> seenHosts = new LinkedHashSet<>();

        for (Report in : inputs) {
            in.kinds.stream().filter(k -> !k.equals("trial")).forEach(kinds::add);
            for (HostInfo h : in.hosts) {
                if (seenHosts.add(h.identity())) {
                    out.hosts.add(h);
                }
            }
            out.captures.addAll(in.captures);
            for (Finding f : in.findings) {
                if (f.plane() == Plane.TRIAL) {
                    continue; // trial findings are always recomputed from claims + observations
                }
                findings.merge(f.key(), f, Finding::mergedWith);
            }
            for (Claim c : in.claims) {
                claims.putIfAbsent(c.type() + "|" + c.host().label() + "|" + c.host().ips(), c);
            }
            for (Observation o : in.observations) {
                observations.merge(o.key(), o, Observation::mergedWith);
            }
            for (BoundaryCrossing b : in.boundaries) {
                String key = b.fromSegment() + "|" + b.toSegment() + "|" + b.protocol() + "|" + b.port();
                boundaries.merge(key, b, (x, y) -> new BoundaryCrossing(x.fromSegment(), x.toSegment(), x.protocol(),
                        x.port(), x.flows() + y.flows(), x.cleartext() || y.cleartext()));
            }
            notes.addAll(in.notes);
        }

        out.claims.addAll(claims.values());
        out.observations.addAll(observations.values());
        out.boundaries.addAll(boundaries.values());
        out.notes.addAll(notes);

        boolean haveEvidence = !out.captures.isEmpty() || kinds.contains("scan");
        if (!out.claims.isEmpty() && haveEvidence) {
            List<HostIdentity> audited = out.hosts.stream().map(HostInfo::identity).toList();
            Tribunal.Result trial = Tribunal.judge(out.claims, out.observations, audited, skewWarnings(out));
            out.verdicts.addAll(trial.verdicts());
            out.trial = trial.summary();
            for (Finding f : trial.findings()) {
                findings.merge(f.key(), f, Finding::mergedWith);
            }
            kinds.add("trial");
        }

        out.kinds.addAll(kinds);
        out.findings.addAll(findings.values());
        out.findings.sort(FINDING_ORDER);
        out.score = Scorer.score(out.findings);
        out.fixPlan = FixPlanner.plan(out);
        if (baseline != null) {
            out.baseline = BaselineComparator.compare(baseline, out);
        }
        return out;
    }

    /** Problems first (FAIL, WARN), then by severity, then id. */
    public static final Comparator<Finding> FINDING_ORDER = Comparator
            .comparingInt((Finding f) -> -f.status().badness())
            .thenComparing(Comparator.comparing(Finding::severity).reversed())
            .thenComparing(Finding::id)
            .thenComparing(Finding::subject);

    private static List<String> skewWarnings(Report r) {
        List<String> warnings = new ArrayList<>();
        for (HostInfo h : r.hosts) {
            if (h.collectedAt() == null) {
                continue;
            }
            for (CaptureInfo c : r.captures) {
                if (c.start() == null || c.end() == null) {
                    continue;
                }
                Duration gap = gap(h.collectedAt(), c.start(), c.end());
                if (gap.compareTo(MAX_SKEW) > 0) {
                    warnings.add(String.format("Testimony from %s (%s) and evidence from %s are %d hours apart; "
                                    + "a contradiction may reflect a change made in between.",
                            h.identity().label(), h.collectedAt(), c.source(), gap.toHours()));
                }
            }
        }
        return warnings;
    }

    private static Duration gap(Instant t, Instant start, Instant end) {
        if (t.isBefore(start)) {
            return Duration.between(t, start);
        }
        if (t.isAfter(end)) {
            return Duration.between(end, t);
        }
        return Duration.ZERO;
    }
}
