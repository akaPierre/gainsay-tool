package dev.gainsay.net.analyze;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report.BoundaryCrossing;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.Observation;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.NetChecks;
import dev.gainsay.net.Segments;
import dev.gainsay.net.decode.DecodedPacket;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Collects what analyzers report, with hard caps on every collection so memory is bounded no matter
 * how large or hostile the capture is. Findings and observations are aggregated (counts and time
 * windows) instead of stored per packet.
 */
public final class AnalysisContext {

    static final int MAX_FINDINGS = 5_000;
    static final int MAX_OBSERVATIONS = 20_000;
    static final int MAX_CROSSINGS = 5_000;
    static final int MAX_MACS = 50_000;

    public final Segments segments;
    private final String captureName;
    private final Map<String, Finding> findings = new LinkedHashMap<>();
    private final Map<String, Observation> observations = new LinkedHashMap<>();
    private final Map<String, Long> relevant = new HashMap<>();
    private final Map<String, long[]> crossings = new LinkedHashMap<>();
    private final Map<String, Set<String>> macToIps = new HashMap<>();
    private long dropped;

    public AnalysisContext(Segments segments, String captureName) {
        this.segments = segments;
        this.captureName = captureName;
    }

    /** Records (or aggregates) a finding for a NET check id and subject. */
    public void finding(String id, String subject, Status status, String summary, Evidence evidence, Instant ts) {
        NetChecks.Info info = NetChecks.get(id);
        String key = id + "@" + subject;
        Finding f = Finding.builder(id, Plane.NET).category(info.category()).title(info.title()).severity(info.severity())
                .status(status).subject(subject).summary(summary).evidence(evidence).rationale(info.rationale())
                .howVerified(info.howVerified()).remediation(info.remediation()).references(info.references())
                .seen(ts, ts).build();
        Finding prev = findings.get(key);
        if (prev != null) {
            findings.put(key, prev.mergedWith(f));
        } else if (findings.size() < MAX_FINDINGS) {
            findings.put(key, f);
        } else {
            dropped++;
        }
        relevant(id);
    }

    /** Notes that traffic relevant to a check was seen (so "no problem found" can be a PASS, not N/A). */
    public void relevant(String id) {
        relevant.merge(id, 1L, Long::sum);
    }

    public long relevantCount(String id) {
        return relevant.getOrDefault(id, 0L);
    }

    /** Records evidence about an address for the trial. */
    public void observe(ObservationType type, String ip, String mac, String peerIp, int port, Instant ts, Evidence proof) {
        Observation o = new Observation(type, ip, mac, peerIp, port, ts, ts, 1, proof);
        Observation prev = observations.get(o.key());
        if (prev != null) {
            observations.put(o.key(), prev.mergedWith(o));
        } else if (observations.size() < MAX_OBSERVATIONS) {
            observations.put(o.key(), o);
        } else {
            dropped++;
        }
    }

    /** Learns which IPs each MAC sends from; a MAC with many IPs is a router and is not trusted for host matching. */
    public void learn(DecodedPacket p) {
        if (p.srcMac == null || p.srcIp == null) {
            return;
        }
        Set<String> ips = macToIps.get(p.srcMac);
        if (ips == null) {
            if (macToIps.size() >= MAX_MACS) {
                return;
            }
            ips = new LinkedHashSet<>();
            macToIps.put(p.srcMac, ips);
        }
        if (ips.size() < 4) {
            ips.add(p.srcIp);
        }
    }

    /** Registers an established flow for the segment-boundary view. */
    public void flowSeen(Flow f, String protocol, boolean cleartext) {
        String from = segments.of(f.clientIp);
        String to = segments.of(f.serverIp);
        if (from.equals(to)) {
            return;
        }
        String key = from + "|" + to + "|" + protocol + "|" + f.serverPort;
        long[] v = crossings.get(key);
        if (v == null) {
            if (crossings.size() >= MAX_CROSSINGS) {
                return;
            }
            v = new long[2];
            crossings.put(key, v);
        }
        v[0]++;
        if (cleartext) {
            v[1] = 1;
        }
    }

    public List<BoundaryCrossing> crossings() {
        List<BoundaryCrossing> out = new ArrayList<>();
        for (Map.Entry<String, long[]> e : crossings.entrySet()) {
            String[] k = e.getKey().split("\\|", 4);
            out.add(new BoundaryCrossing(k[0], k[1], k[2], Integer.parseInt(k[3]), e.getValue()[0], e.getValue()[1] == 1));
        }
        return out;
    }

    public List<Finding> findings() {
        return new ArrayList<>(findings.values());
    }

    public boolean hasFinding(String id) {
        for (Finding f : findings.values()) {
            if (f.id().equals(id)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Observations, with MACs removed where the MAC was seen sending from several IPs: that is a router
     * (or the monitoring host itself), and matching hosts by its MAC would misattribute routed traffic.
     */
    public List<Observation> observations() {
        List<Observation> out = new ArrayList<>();
        for (Observation o : observations.values()) {
            Set<String> ips = o.mac() == null ? null : macToIps.get(o.mac());
            boolean trustworthy = ips != null && ips.size() == 1 && !Addresses.isGroup(Addresses.parse(o.ip()));
            out.add(trustworthy ? o : new Observation(o.type(), o.ip(), null, o.peerIp(), o.port(), o.firstSeen(), o.lastSeen(),
                    o.count(), o.proof()));
        }
        return out;
    }

    public long dropped() {
        return dropped;
    }

    /** tshark one-liner to find the same packets by hand. */
    public String tshark(String displayFilter) {
        return "tshark -r " + (captureName.startsWith("file ") ? captureName.substring(5) : "<capture.pcap>") + " -Y \"" + displayFilter + "\"";
    }

    /** Evidence for one packet, with frame number and a reproduce filter. */
    public Evidence packetEvidence(DecodedPacket p, String detail, String displayFilter) {
        return new Evidence("packet", p.src() + " → " + p.dst() + " (frame " + p.frame + ")", detail, tshark(displayFilter));
    }
}
