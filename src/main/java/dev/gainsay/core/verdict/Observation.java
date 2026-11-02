package dev.gainsay.core.verdict;

import com.fasterxml.jackson.annotation.JsonIgnore;
import dev.gainsay.core.Evidence;

import java.time.Instant;

/**
 * Aggregated evidence that address {@code ip} did something ({@link #type()}), optionally towards
 * {@code peerIp} on {@code port}. Repeats are folded into {@code count}; one redacted proof is kept.
 */
public record Observation(
        ObservationType type,
        String ip,
        String mac,
        String peerIp,
        int port,
        Instant firstSeen,
        Instant lastSeen,
        long count,
        Evidence proof) {

    @JsonIgnore
    public String key() {
        return type + "|" + ip + "|" + (peerIp == null ? "" : peerIp) + "|" + port;
    }

    public Observation mergedWith(Observation o) {
        Instant first = firstSeen == null ? o.firstSeen : (o.firstSeen != null && o.firstSeen.isBefore(firstSeen) ? o.firstSeen : firstSeen);
        Instant last = lastSeen == null ? o.lastSeen : (o.lastSeen != null && o.lastSeen.isAfter(lastSeen) ? o.lastSeen : lastSeen);
        return new Observation(type, ip, mac != null ? mac : o.mac, peerIp, port, first, last, count + o.count,
                proof != null ? proof : o.proof);
    }
}
