package dev.gainsay.net.analyze;

import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.RdpParser;

import java.util.List;

/**
 * NET-EXPOSE-002 and RDP/NLA evidence for the trial, from the X.224 connection exchange. The
 * mstshash cookie (which contains a user name) is skipped by the parser and never recorded.
 */
public final class RdpAnalyzer implements Analyzer {

    @Override
    public List<String> checkIds() {
        return List.of("NET-EXPOSE-002");
    }

    @Override
    public void onStream(Flow f, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
        if (f.marked(toServer ? "rdp.req" : "rdp.rsp") || head.length() < 11) {
            return;
        }
        RdpParser.X224 x = RdpParser.parse(head.bytes(), head.length());
        if (x == null) {
            f.mark(toServer ? "rdp.req" : "rdp.rsp");
            return;
        }
        String filter = Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && rdp";
        if (toServer && x.request() && f.mark("rdp.req")) {
            if (!x.nla(x.requestedProtocols())) {
                ctx.observe(ObservationType.RDP_NON_NLA_CLIENT_REQUEST, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                        ctx.packetEvidence(p, "X.224 Connection Request: requestedProtocols=0x" + Long.toHexString(x.requestedProtocols())
                                + " (no CredSSP)", filter));
            }
        } else if (!toServer && x.confirm() && f.mark("rdp.rsp")) {
            ctx.relevant("NET-EXPOSE-002");
            if (x.failureCode() == RdpParser.HYBRID_REQUIRED_BY_SERVER) {
                ctx.observe(ObservationType.RDP_NLA_ENFORCED, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                        ctx.packetEvidence(p, "RDP_NEG_FAILURE HYBRID_REQUIRED_BY_SERVER: the server demands NLA", filter));
            } else if (x.selectedProtocol() >= 0) {
                String detail = "X.224 Connection Confirm: selectedProtocol=0x" + Long.toHexString(x.selectedProtocol()) + " ("
                        + protocolName(x.selectedProtocol()) + ")";
                if (x.nla(x.selectedProtocol())) {
                    ctx.observe(ObservationType.RDP_NLA_ENFORCED, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                            ctx.packetEvidence(p, detail, filter));
                } else {
                    ctx.observe(ObservationType.RDP_NLA_NOT_ENFORCED, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                            ctx.packetEvidence(p, detail, filter));
                    ctx.finding("NET-EXPOSE-002", f.server(), Status.FAIL, "RDP server " + f.server() + " accepted a session without NLA.",
                            ctx.packetEvidence(p, detail, filter), p.ts);
                }
            }
        }
    }

    static String protocolName(long p) {
        if (p == RdpParser.PROTOCOL_RDP) {
            return "standard RDP security";
        }
        if (p == RdpParser.PROTOCOL_SSL) {
            return "TLS only";
        }
        if ((p & RdpParser.PROTOCOL_HYBRID_EX) != 0) {
            return "CredSSP with early user authorization";
        }
        if ((p & RdpParser.PROTOCOL_HYBRID) != 0) {
            return "CredSSP (NLA)";
        }
        return "other";
    }
}
