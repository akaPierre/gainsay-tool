package dev.gainsay.net.analyze;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Report.BoundaryCrossing;
import dev.gainsay.core.Status;
import dev.gainsay.net.decode.Bytes;
import dev.gainsay.net.decode.DecodedPacket;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * NET-HYG-001..003: duplicate IP addresses seen in ARP, more than one DHCP server, and cleartext
 * protocols that cross a segment boundary. These are posture/hygiene signals, not attack verdicts.
 */
public final class HygieneAnalyzer implements Analyzer {

    static final int MAX_ARP_IPS = 10_000;
    static final int MAX_MACS_PER_IP = 4;
    static final int DHCP_MAGIC = 0x63825363;

    private final Map<String, Set<String>> ipToMacs = new HashMap<>();
    private final Map<String, Instant> conflictsReported = new HashMap<>();
    private final Map<String, String> dhcpServers = new LinkedHashMap<>();
    private Instant lastDhcp;

    @Override
    public List<String> checkIds() {
        return List.of("NET-HYG-001", "NET-HYG-002", "NET-HYG-003");
    }

    @Override
    public void onPacket(DecodedPacket p, Flow f, AnalysisContext ctx) {
        if (p.arpOp > 0) {
            arp(p, ctx);
        } else if (p.isUdp() && p.srcPort == 67 && p.dstPort == 68) {
            dhcp(p, ctx);
        }
    }

    private void arp(DecodedPacket p, AnalysisContext ctx) {
        ctx.relevant("NET-HYG-001");
        String ip = p.arpSenderIp;
        if (ip == null || ip.equals("0.0.0.0")) {
            return; // ARP probes (RFC 5227) carry no sender address
        }
        Set<String> macs = ipToMacs.get(ip);
        if (macs == null) {
            if (ipToMacs.size() >= MAX_ARP_IPS) {
                return;
            }
            macs = new LinkedHashSet<>();
            ipToMacs.put(ip, macs);
        }
        if (macs.size() < MAX_MACS_PER_IP) {
            macs.add(p.arpSenderMac);
        }
        if (macs.size() > 1 && conflictsReported.putIfAbsent(ip, p.ts) == null) {
            ctx.finding("NET-HYG-001", ip, Status.FAIL, "IP " + ip + " is claimed by " + macs.size() + " MAC addresses: " + String.join(", ", macs) + ".",
                    ctx.packetEvidence(p, "ARP " + (p.arpOp == 1 ? "request" : "reply") + ": " + ip + " is-at " + p.arpSenderMac
                            + " (previously " + macs.iterator().next() + ")", "arp.src.proto_ipv4==" + ip), p.ts);
        }
    }

    private void dhcp(DecodedPacket p, AnalysisContext ctx) {
        byte[] b = p.data;
        int off = p.payloadOffset;
        int end = off + p.payloadLength;
        try {
            if (Bytes.u8(b, off, end) != 2 || Bytes.u32(b, off + 236, end) != DHCP_MAGIC) {
                return; // not a BOOTREPLY with DHCP options
            }
            int type = -1;
            String serverId = null;
            int o = off + 240;
            for (int i = 0; i < 64 && o < end; i++) {
                int code = Bytes.u8(b, o, end);
                if (code == 255) {
                    break;
                }
                if (code == 0) {
                    o++;
                    continue;
                }
                int len = Bytes.u8(b, o + 1, end);
                if (code == 53 && len == 1) {
                    type = Bytes.u8(b, o + 2, end);
                } else if (code == 54 && len == 4) {
                    Bytes.need(b, o + 2, 4, end);
                    serverId = dev.gainsay.core.Addresses.format(b, o + 2, 4);
                }
                o += 2 + len;
            }
            if (type != 2 && type != 5) {
                return; // only OFFER and ACK identify a server
            }
            ctx.relevant("NET-HYG-002");
            String server = serverId != null ? serverId : p.srcIp;
            if (dhcpServers.size() < 64) {
                dhcpServers.putIfAbsent(server, p.srcMac + " (frame " + p.frame + ")");
            }
            lastDhcp = p.ts;
        } catch (Bytes.Malformed e) {
            // truncated DHCP: ignore
        }
    }

    @Override
    public void finish(AnalysisContext ctx) {
        if (dhcpServers.size() > 1) {
            ctx.finding("NET-HYG-002", "DHCP", Status.FAIL, dhcpServers.size() + " DHCP servers answered: " + String.join(", ", dhcpServers.keySet()) + ".",
                    new Evidence("packet", "DHCP OFFER/ACK", dhcpServers.toString(), ctx.tshark("dhcp.option.dhcp == 2 || dhcp.option.dhcp == 5")),
                    lastDhcp);
        }
        for (BoundaryCrossing c : ctx.crossings()) {
            ctx.relevant("NET-HYG-003");
            if (c.cleartext()) {
                ctx.finding("NET-HYG-003", c.fromSegment() + " → " + c.toSegment() + " " + c.protocol(), Status.FAIL,
                        c.flows() + " " + c.protocol() + " flow(s) cross from " + c.fromSegment() + " to " + c.toSegment() + " in clear (port " + c.port() + ").",
                        new Evidence("packet", c.fromSegment() + " → " + c.toSegment(), c.protocol() + " on port " + c.port() + ", " + c.flows() + " flow(s)",
                                ctx.tshark("tcp.port==" + c.port())), null);
            }
        }
    }
}
