package dev.gainsay.report;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report;
import dev.gainsay.core.Report.FixItem;
import dev.gainsay.core.Report.HostInfo;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.core.verdict.Verdict;
import dev.gainsay.core.verdict.VerdictKind;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns a report into a short, ranked list of actions. Each action is credited with every problem it
 * should clear: the host finding itself, the trial verdicts built on that check, and the network
 * findings about the same host that the setting governs. Contradictions become INVESTIGATE items (no
 * setting change will help until you know why the setting is not in effect). Network problems with no
 * audited host behind them become NETWORK items. Peers seen depending on a weak behaviour are listed
 * as "may break".
 */
public final class FixPlanner {

    /** Which network checks a claim type's host setting governs. */
    static final Map<ClaimType, List<String>> NET_LINKS = new EnumMap<>(ClaimType.class);

    static {
        NET_LINKS.put(ClaimType.SMB1_SERVER_DISABLED, List.of("NET-SMB-001"));
        NET_LINKS.put(ClaimType.SMB1_CLIENT_DISABLED, List.of("NET-SMB-001"));
        NET_LINKS.put(ClaimType.SMB_SERVER_SIGNING_REQUIRED, List.of("NET-SMB-002"));
        NET_LINKS.put(ClaimType.TLS_LEGACY_SERVER_DISABLED, List.of("NET-TLS-001"));
        NET_LINKS.put(ClaimType.TLS_LEGACY_CLIENT_DISABLED, List.of("NET-TLS-001"));
        NET_LINKS.put(ClaimType.LLMNR_DISABLED, List.of("NET-NAME-001"));
        NET_LINKS.put(ClaimType.NETBIOS_DISABLED, List.of("NET-NAME-002"));
        NET_LINKS.put(ClaimType.RDP_DISABLED, List.of("NET-EXPOSE-001", "NET-EXPOSE-002"));
        NET_LINKS.put(ClaimType.RDP_NLA_REQUIRED, List.of("NET-EXPOSE-002"));
        NET_LINKS.put(ClaimType.WINRM_NOT_EXPOSED, List.of("NET-EXPOSE-001"));
        NET_LINKS.put(ClaimType.NTLMV1_DISABLED, List.of("NET-SMB-003"));
    }

    static final int MAX_ITEMS = 50;

    private FixPlanner() {
    }

    public static List<FixItem> plan(Report r) {
        List<Draft> drafts = new ArrayList<>();
        Set<String> claimedNet = new LinkedHashSet<>();

        for (Verdict v : r.verdicts) {
            if (v.kind() == VerdictKind.CONTRADICTED && v.claim() != null && v.claim().secure()) {
                Draft d = new Draft("INVESTIGATE", v.claimType().trialId(), v.hostLabel(), "Find out why \"" + v.claim().statement() + "\" is not in effect",
                        "Configured correctly, yet the wire disagrees. Check whether: " + String.join("; ", v.claimType().explanations()) + ".", null);
                d.resolves.add(v.claimType().trialId() + "@" + v.hostLabel());
                d.weight += v.claimType().severity().weight() * 1.5; // surprising failures deserve attention first
                d.mayBreak.addAll(v.dependants());
                linkNet(r, v.claimType(), hostIps(r, v.hostLabel()), d, claimedNet);
                drafts.add(d);
            }
        }

        for (Finding f : r.findings) {
            if (f.plane() != Plane.HOST || !f.status().isProblem() || f.severity().weight() == 0) {
                continue;
            }
            Draft d = new Draft("FIX", f.id(), f.subject(), stripDot(f.summary()), "Goal: " + f.title() + ". " + f.rationale(), f.fix());
            d.resolves.add(f.key());
            d.weight += weight(f);
            List<String> ips = hostIps(r, f.subject());
            for (Verdict v : r.verdicts) {
                if (v.claim() == null || !v.claim().checkId().equals(f.id()) || !v.hostLabel().equals(f.subject())) {
                    continue;
                }
                d.mayBreak.addAll(v.dependants());
                if (v.kind() != VerdictKind.UNTESTED) {
                    d.resolves.add(v.claimType().trialId() + "@" + v.hostLabel()); // INFO weight: already counted via the host finding
                }
                if (v.kind() == VerdictKind.CORROBORATED && !v.claim().secure()) {
                    d.why = d.why + " Confirmed live on the wire.";
                }
                linkNet(r, v.claimType(), ips, d, claimedNet);
            }
            drafts.add(d);
        }

        Map<String, Draft> network = new LinkedHashMap<>();
        for (Finding f : r.findings) {
            if (f.plane() != Plane.NET && f.plane() != Plane.SCAN || !f.status().isProblem() || claimedNet.contains(f.key())) {
                continue;
            }
            Draft d = network.computeIfAbsent(f.id(), id -> new Draft("NETWORK", f.id(), "network", f.title(), f.remediation(), null));
            d.resolves.add(f.key());
            d.weight += weight(f);
        }
        drafts.addAll(network.values());

        drafts.sort(Comparator.comparingDouble((Draft d) -> -d.weight).thenComparing(d -> d.kind).thenComparing(d -> d.title));
        List<FixItem> out = new ArrayList<>();
        for (Draft d : drafts) {
            if (out.size() >= MAX_ITEMS) {
                break;
            }
            out.add(new FixItem(out.size() + 1, d.kind, d.checkId, d.host, d.title, d.why, List.copyOf(d.resolves), Math.round(d.weight * 10) / 10.0,
                    d.fix, List.copyOf(d.mayBreak)));
        }
        return out;
    }

    private static void linkNet(Report r, ClaimType t, List<String> ips, Draft d, Set<String> claimedNet) {
        for (String netId : NET_LINKS.getOrDefault(t, List.of())) {
            for (Finding n : r.findings) {
                if (n.id().equals(netId) && n.status().isProblem() && aboutHost(n.subject(), ips) && d.resolves.add(n.key())) {
                    d.weight += weight(n);
                    claimedNet.add(n.key());
                }
            }
        }
    }

    static boolean aboutHost(String subject, List<String> ips) {
        for (String ip : ips) {
            if (subject.equals(ip) || subject.startsWith(ip + ":") || subject.startsWith("[" + ip + "]")) {
                return true;
            }
        }
        return false;
    }

    private static List<String> hostIps(Report r, String label) {
        for (HostInfo h : r.hosts) {
            if (h.identity().label().equals(label)) {
                return h.identity().ips();
            }
        }
        return List.of();
    }

    private static String stripDot(String s) {
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }

    private static double weight(Finding f) {
        return f.status() == Status.WARN ? f.severity().weight() / 2.0 : f.severity().weight();
    }

    private static final class Draft {
        final String kind;
        final String checkId;
        final String host;
        final String title;
        String why;
        final dev.gainsay.core.Fix fix;
        final Set<String> resolves = new LinkedHashSet<>();
        final Set<String> mayBreak = new LinkedHashSet<>();
        double weight;

        Draft(String kind, String checkId, String host, String title, String why, dev.gainsay.core.Fix fix) {
            this.checkId = checkId;
            this.kind = kind;
            this.host = host;
            this.title = title;
            this.why = why;
            this.fix = fix;
        }
    }
}
