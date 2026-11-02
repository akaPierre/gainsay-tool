package dev.gainsay.net.analyze;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.DnsParser;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * NET-NAME-001..004: LLMNR, NBT-NS, mDNS, cleartext DNS to public/unexpected resolvers, plus the
 * name-resolution evidence for the trial (LLMNR/NBNS queries; DNS NXDOMAIN answers, after which a
 * Windows host with LLMNR/NBT-NS enabled would normally fall back to multicast).
 */
public final class NameResolutionAnalyzer implements Analyzer {

    static final int MAX_CLIENTS = 10_000;
    private final Set<String> expectedResolvers;
    private final Map<String, Long> dnsQueries = new HashMap<>();

    public NameResolutionAnalyzer(Set<String> expectedResolvers) {
        this.expectedResolvers = expectedResolvers;
    }

    @Override
    public List<String> checkIds() {
        return List.of("NET-NAME-001", "NET-NAME-002", "NET-NAME-003", "NET-NAME-004");
    }

    @Override
    public void onPacket(DecodedPacket p, Flow f, AnalysisContext ctx) {
        if (!p.isUdp() || p.payloadLength < 12) {
            return;
        }
        if (p.dstPort == 5355) {
            DnsParser.Header h = DnsParser.parse(p.data, p.payloadOffset, p.payloadLength);
            ctx.relevant("NET-NAME-001");
            if (h != null && !h.response()) {
                String detail = "LLMNR query for '" + h.firstName() + "' to " + p.dstIp;
                ctx.observe(ObservationType.LLMNR_QUERY_SENT, p.srcIp, p.srcMac, p.dstIp, 5355, p.ts,
                        ctx.packetEvidence(p, detail, Filters.host(p.srcIp) + " && llmnr"));
                ctx.finding("NET-NAME-001", p.srcIp, Status.FAIL, "Host " + p.srcIp + " uses LLMNR.",
                        ctx.packetEvidence(p, detail, Filters.host(p.srcIp) + " && llmnr"), p.ts);
            }
        } else if (p.dstPort == 137) {
            DnsParser.Header h = DnsParser.parse(p.data, p.payloadOffset, p.payloadLength);
            ctx.relevant("NET-NAME-002");
            if (h != null && !h.response() && h.opcode() == 0) {
                String detail = "NBNS name query for '" + DnsParser.netbiosName(h.firstName()) + "' to " + p.dstIp;
                ctx.observe(ObservationType.NBNS_QUERY_SENT, p.srcIp, p.srcMac, p.dstIp, 137, p.ts,
                        ctx.packetEvidence(p, detail, Filters.host(p.srcIp) + " && nbns"));
                ctx.finding("NET-NAME-002", p.srcIp, Status.FAIL, "Host " + p.srcIp + " uses NetBIOS name resolution.",
                        ctx.packetEvidence(p, detail, Filters.host(p.srcIp) + " && nbns"), p.ts);
            }
        } else if (p.dstPort == 5353 || p.srcPort == 5353) {
            ctx.relevant("NET-NAME-003");
            DnsParser.Header h = DnsParser.parse(p.data, p.payloadOffset, p.payloadLength);
            if (h != null) {
                ctx.finding("NET-NAME-003", p.srcIp, Status.WARN, "Host " + p.srcIp + " uses mDNS.",
                        ctx.packetEvidence(p, (h.response() ? "mDNS response" : "mDNS query") + (h.firstName() == null ? "" : " '" + h.firstName() + "'"),
                                Filters.host(p.srcIp) + " && mdns"), p.ts);
            }
        } else if (p.dstPort == 53) {
            dnsQuery(p, ctx);
        } else if (p.srcPort == 53) {
            DnsParser.Header h = DnsParser.parse(p.data, p.payloadOffset, p.payloadLength);
            if (h != null && h.response() && h.rcode() == 3) {
                ctx.observe(ObservationType.DNS_NXDOMAIN_RECEIVED, p.dstIp, p.dstMac, p.srcIp, 53, p.ts,
                        ctx.packetEvidence(p, "NXDOMAIN for '" + h.firstName() + "'", Filters.host(p.dstIp) + " && dns.flags.rcode==3"));
            }
        }
    }

    private void dnsQuery(DecodedPacket p, AnalysisContext ctx) {
        DnsParser.Header h = DnsParser.parse(p.data, p.payloadOffset, p.payloadLength);
        if (h == null || h.response()) {
            return;
        }
        ctx.relevant("NET-NAME-004");
        if (dnsQueries.size() < MAX_CLIENTS || dnsQueries.containsKey(p.srcIp)) {
            dnsQueries.merge(p.srcIp, 1L, Long::sum);
        }
        boolean isPublic = !Addresses.isPrivate(p.dstIp);
        boolean unexpected = !expectedResolvers.isEmpty() && !expectedResolvers.contains(Addresses.canonical(p.dstIp));
        if (isPublic || unexpected) {
            ctx.finding("NET-NAME-004", p.srcIp + " → " + p.dstIp, Status.WARN,
                    "Host " + p.srcIp + " sends cleartext DNS to " + (isPublic ? "public" : "unexpected") + " resolver " + p.dstIp + ".",
                    ctx.packetEvidence(p, "DNS query for '" + h.firstName() + "'", Filters.host(p.dstIp) + " && dns"), p.ts);
        }
    }
}
