package dev.gainsay.core.verdict;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.HostIdentity;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Cross-examines host testimony ({@link Claim}s) against network evidence ({@link Observation}s).
 *
 * <p>Decision table for one claim:
 * <pre>
 *                     violating evidence     only conforming evidence   no relevant evidence
 *  claim secure       CONTRADICTED (fail)    CORROBORATED (pass)        UNTESTED
 *  claim insecure     CORROBORATED (info)    CONTRADICTED (warn, low)   UNTESTED
 * </pre>
 * Violating evidence about an address that no audited host claims becomes {@link VerdictKind#UNCLAIMED}.
 * Matching is by IP first, then MAC, and the method used is recorded in the verdict.
 */
public final class Tribunal {

    public static final String CATEGORY = "Testimony vs evidence";
    static final int MAX_UNCLAIMED = 500;
    static final int MAX_DEPENDANTS = 20;

    /** Everything a trial produces. */
    public record Result(List<Verdict> verdicts, TrialSummary summary, List<Finding> findings) {
    }

    private Tribunal() {
    }

    public static Result judge(List<Claim> claims, List<Observation> observations, List<HostIdentity> auditedHosts,
                               List<String> warnings) {
        List<Verdict> verdicts = new ArrayList<>();
        for (Claim claim : claims) {
            verdicts.add(judgeClaim(claim, observations));
        }
        verdicts.addAll(unclaimed(claims, observations, auditedHosts));
        verdicts.sort(Comparator.comparingInt((Verdict v) -> order(v.kind()))
                .thenComparing(Comparator.comparingDouble(Verdict::surprise).reversed())
                .thenComparing(Verdict::hostLabel));

        int contradicted = 0, corroborated = 0, untested = 0, unclaimed = 0;
        for (Verdict v : verdicts) {
            switch (v.kind()) {
                case CONTRADICTED -> contradicted++;
                case CORROBORATED -> corroborated++;
                case UNTESTED -> untested++;
                case UNCLAIMED -> unclaimed++;
            }
        }
        double coverage = claims.isEmpty() ? 0.0 : (double) (contradicted + corroborated) / claims.size();
        TrialSummary summary = new TrialSummary(claims.size(), contradicted, corroborated, untested, unclaimed,
                coverage, warnings);
        List<Finding> findings = new ArrayList<>();
        for (Verdict v : verdicts) {
            Finding f = toFinding(v);
            if (f != null) {
                findings.add(f);
            }
        }
        return new Result(verdicts, summary, findings);
    }

    private static int order(VerdictKind k) {
        return switch (k) {
            case CONTRADICTED -> 0;
            case UNCLAIMED -> 1;
            case CORROBORATED -> 2;
            case UNTESTED -> 3;
        };
    }

    static Verdict judgeClaim(Claim claim, List<Observation> observations) {
        ClaimType type = claim.type();
        List<Observation> violating = new ArrayList<>();
        List<Observation> conforming = new ArrayList<>();
        Set<String> dependants = new LinkedHashSet<>();
        String matchedBy = "";
        for (Observation o : observations) {
            if (type.isDependant(o) && claim.host().hasIp(o.peerIp()) && dependants.size() < MAX_DEPENDANTS) {
                dependants.add(o.ip());
            }
            String m = claim.host().matchMethod(o.ip(), o.mac());
            if (m == null) {
                continue;
            }
            if (type.violatedBy(o)) {
                violating.add(o);
                matchedBy = preferIp(matchedBy, m);
            } else if (type.conformedBy(o)) {
                conforming.add(o);
                matchedBy = preferIp(matchedBy, m);
            }
        }
        String host = claim.host().label();
        List<String> deps = new ArrayList<>(dependants);
        if (!violating.isEmpty()) {
            double conf = violating.stream().mapToDouble(o -> o.type().confidence()).max().orElse(0);
            if (claim.secure()) {
                double surprise = type.severity().weight() * claim.strength().weight() * conf;
                return new Verdict(VerdictKind.CONTRADICTED, type, host, claim, violating, matchedBy, deps, round(surprise),
                        String.format("%s claims \"%s\", but the wire shows that the %s (%s). Possible explanations: %s.",
                                host, claim.statement(), violating.get(0).type().meaning(), countText(violating),
                                String.join("; ", type.explanations())));
            }
            return new Verdict(VerdictKind.CORROBORATED, type, host, claim, violating, matchedBy, deps, 0,
                    String.format("%s is configured weak (\"%s\") and the wire confirms it is live: the %s (%s).",
                            host, claim.statement(), violating.get(0).type().meaning(), countText(violating)));
        }
        if (!conforming.isEmpty()) {
            if (claim.secure()) {
                return new Verdict(VerdictKind.CORROBORATED, type, host, claim, conforming, matchedBy, deps, 0,
                        String.format("%s claims \"%s\" and the wire agrees: the %s (%s).",
                                host, claim.statement(), conforming.get(0).type().meaning(), countText(conforming)));
            }
            double conf = conforming.stream().mapToDouble(o -> o.type().confidence()).max().orElse(0);
            return new Verdict(VerdictKind.CONTRADICTED, type, host, claim, conforming, matchedBy, deps,
                    round(0.5 * claim.strength().weight() * conf),
                    String.format("%s is configured weak (\"%s\") yet behaved securely: the %s (%s). The setting may not be in effect, "
                                    + "or an upstream control is compensating. Possible explanations: %s.",
                            host, claim.statement(), conforming.get(0).type().meaning(), countText(conforming),
                            String.join("; ", type.explanations())));
        }
        return new Verdict(VerdictKind.UNTESTED, type, host, claim, List.of(), "", deps, 0,
                String.format("No traffic in the capture could have tested \"%s\" on %s. Generate traffic that exercises it "
                        + "(see docs/CHECKS.md) to put this claim on trial.", claim.statement(), host));
    }

    private static List<Verdict> unclaimed(List<Claim> claims, List<Observation> observations, List<HostIdentity> audited) {
        Map<String, List<Observation>> groups = new LinkedHashMap<>();
        Map<String, ClaimType> groupType = new LinkedHashMap<>();
        Map<String, HostIdentity> groupHost = new LinkedHashMap<>();
        for (ClaimType type : ClaimType.values()) {
            for (Observation o : observations) {
                if (!type.violatedBy(o)) {
                    continue;
                }
                HostIdentity owner = null;
                boolean claimed = false;
                for (HostIdentity h : audited) {
                    if (h.matchMethod(o.ip(), o.mac()) != null) {
                        owner = h;
                        for (Claim c : claims) {
                            if (c.type() == type && c.host().equals(h)) {
                                claimed = true;
                                break;
                            }
                        }
                    }
                }
                if (claimed) {
                    continue;
                }
                String key = type + "|" + o.ip();
                if (!groups.containsKey(key) && groups.size() >= MAX_UNCLAIMED) {
                    continue;
                }
                groups.computeIfAbsent(key, k -> new ArrayList<>()).add(o);
                groupType.put(key, type);
                if (owner != null) {
                    groupHost.put(key, owner);
                }
            }
        }
        List<Verdict> out = new ArrayList<>();
        for (Map.Entry<String, List<Observation>> e : groups.entrySet()) {
            ClaimType type = groupType.get(e.getKey());
            List<Observation> obs = e.getValue();
            String ip = obs.get(0).ip();
            HostIdentity owner = groupHost.get(e.getKey());
            Set<String> deps = new LinkedHashSet<>();
            for (Observation o : observations) {
                if (type.isDependant(o) && ip.equals(o.peerIp()) && deps.size() < MAX_DEPENDANTS) {
                    deps.add(o.ip());
                }
            }
            String why = owner == null
                    ? "no host report covers this address, so nobody testified about it. Audit it with `gainsay host` to put it on trial"
                    : owner.label() + " was audited but its check for this setting could not run (see the appendix of checks that could not run)";
            out.add(new Verdict(VerdictKind.UNCLAIMED, type, owner == null ? ip : owner.label(), null, obs,
                    owner == null ? "" : "ip", new ArrayList<>(deps), 0,
                    String.format("%s: the %s (%s), and %s.", ip, obs.get(0).type().meaning(), countText(obs), why)));
        }
        return out;
    }

    static Finding toFinding(Verdict v) {
        if (v.kind() == VerdictKind.UNTESTED || v.kind() == VerdictKind.UNCLAIMED) {
            return null; // shown in the testimony-vs-evidence matrix; the NET findings already grade the behaviour
        }
        ClaimType t = v.claimType();
        Claim c = v.claim();
        Status status;
        Severity severity;
        String summary;
        if (v.kind() == VerdictKind.CONTRADICTED && c.secure()) {
            status = Status.FAIL;
            severity = t.severity();
            summary = "Contradiction: configured \"" + c.statement() + "\" but observed otherwise on the wire.";
        } else if (v.kind() == VerdictKind.CONTRADICTED) {
            status = Status.WARN;
            severity = Severity.LOW;
            summary = "Configured weak (\"" + c.statement() + "\") but behaved securely; the setting may not be in effect.";
        } else if (c.secure()) {
            status = Status.PASS;
            severity = t.severity();
            summary = "Corroborated: \"" + c.statement() + "\" is borne out by observed traffic.";
        } else {
            status = Status.FAIL;
            severity = Severity.INFO;
            summary = "Weakness confirmed live: \"" + c.statement() + "\" is visible on the wire.";
        }
        Finding.Builder b = Finding.builder(t.trialId(), Plane.TRIAL)
                .category(CATEGORY)
                .title("Claim on trial: " + t.title())
                .severity(severity)
                .status(status)
                .subject(v.hostLabel())
                .summary(summary)
                .rationale(v.explanation())
                .howVerified("The host check " + c.checkId() + " read the setting (" + c.basis() + ", strength "
                        + c.strength() + "). The network module independently recorded protocol facts for the host's "
                        + "addresses (matched by " + (v.matchedBy().isEmpty() ? "n/a" : v.matchedBy()) + "). The tribunal compared them.")
                .remediation(remediation(v))
                .references(List.of("docs/CHECKS.md#" + t.trialId().toLowerCase()));
        b.evidence(new Evidence("trial", c.basis(), "testimony: " + c.statement(), null));
        for (Observation o : v.evidence()) {
            if (o.proof() != null) {
                b.evidence(o.proof());
            }
        }
        if (!v.evidence().isEmpty()) {
            b.seen(v.evidence().get(0).firstSeen(), v.evidence().get(0).lastSeen());
            b.occurrences(v.evidence().stream().mapToLong(Observation::count).sum());
        }
        return b.build();
    }

    private static String remediation(Verdict v) {
        StringBuilder s = new StringBuilder();
        if (v.kind() == VerdictKind.CONTRADICTED) {
            s.append("Find out which of these applies: ").append(String.join("; ", v.claimType().explanations()))
                    .append(". Then capture again and re-run the trial to confirm the contradiction is gone.");
        } else if (!v.claim().secure()) {
            s.append("Fix the host setting (see the matching HOST finding), then re-run the trial.");
        } else {
            s.append("No action needed; keep capturing periodically so this claim stays tested.");
        }
        if (!v.dependants().isEmpty()) {
            s.append(" Blast radius: these peers were seen relying on the weak behaviour and may break when it is fixed: ")
                    .append(String.join(", ", v.dependants())).append('.');
        }
        return s.toString();
    }

    private static String preferIp(String current, String candidate) {
        return "ip".equals(current) ? current : candidate;
    }

    private static String countText(List<Observation> obs) {
        long n = obs.stream().mapToLong(Observation::count).sum();
        Observation first = obs.get(0);
        String where = first.proof() != null ? ", e.g. " + first.proof().source() : "";
        return n + (n == 1 ? " time" : " times") + where;
    }

    private static double round(double d) {
        return Math.round(d * 100.0) / 100.0;
    }
}
