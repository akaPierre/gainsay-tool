package dev.gainsay.net.analyze;

import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.SmbParser;
import dev.gainsay.net.decode.SmbParser.Kind;
import dev.gainsay.net.decode.SmbParser.Message;

import java.util.List;
import java.util.Set;

/**
 * NET-SMB-001/002/004 and the SMB evidence for the trial. Reads only NEGOTIATE messages (dialects and
 * SecurityMode); file names, shares and data are never inspected.
 */
public final class SmbAnalyzer implements Analyzer {

    static final Set<Integer> SMB_PORTS = Set.of(445, 139);

    @Override
    public List<String> checkIds() {
        return List.of("NET-SMB-001", "NET-SMB-002", "NET-SMB-004");
    }

    @Override
    public void onPacket(DecodedPacket p, Flow f, AnalysisContext ctx) {
        // A server that resets the connection after an SMB1-only offer has refused SMB1.
        if (f != null && p.isTcp() && p.has(DecodedPacket.RST) && !f.fromClient(p)
                && f.marked("smb.smb1only") && !f.marked("smb.s1resp") && f.mark("smb.refused")) {
            ctx.observe(ObservationType.SMB1_REFUSED_BY_SERVER, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, "server reset the connection after an SMB1-only NEGOTIATE", Filters.hostPort(f.serverIp, "tcp", f.serverPort)));
        }
    }

    @Override
    public void onStream(Flow f, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
        if (!SMB_PORTS.contains(f.serverPort)) {
            return;
        }
        if (f.mark("smb.seen")) {
            boundary(f, p, ctx);
        }
        String filter = Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && (smb2.cmd==0 || smb.cmd==0x72)";
        for (Message m : SmbParser.parse(head.bytes(), head.length())) {
            if (toServer) {
                client(f, m, p, ctx, filter);
            } else {
                server(f, m, p, ctx, filter);
            }
        }
    }

    private void client(Flow f, Message m, DecodedPacket p, AnalysisContext ctx, String filter) {
        if (m.kind() == Kind.SMB1_NEGOTIATE_REQUEST && f.mark("smb.c1")) {
            ctx.relevant("NET-SMB-001");
            boolean smb1 = m.dialects().stream().anyMatch(SmbParser::isSmb1Dialect);
            boolean smb2 = m.dialects().stream().anyMatch(d -> !SmbParser.isSmb1Dialect(d));
            String dialects = "SMB1 NEGOTIATE dialects: " + String.join(", ", m.dialects());
            if (smb1) {
                ctx.observe(ObservationType.SMB1_OFFERED_BY_CLIENT, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                        ctx.packetEvidence(p, dialects, filter));
                ctx.finding("NET-SMB-001", f.clientIp, Status.WARN, "Client " + f.clientIp + " offers SMB1 dialects to " + f.server() + ".",
                        ctx.packetEvidence(p, dialects, filter), p.ts);
            }
            if (smb1 && !smb2) {
                f.mark("smb.smb1only");
                ctx.observe(ObservationType.SMB1_ONLY_CLIENT_OFFER, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                        ctx.packetEvidence(p, dialects + " (no SMB2/3 dialect offered)", filter));
            }
        } else if (m.kind() == Kind.SMB2_NEGOTIATE_REQUEST && !f.marked("smb.c1") && f.mark("smb.c2")) {
            ctx.relevant("NET-SMB-001");
            ctx.observe(ObservationType.SMB2_DIRECT_NEGOTIATE_BY_CLIENT, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, "first message is an SMB2 NEGOTIATE (no SMB1 hello)", filter));
        }
    }

    private void server(Flow f, Message m, DecodedPacket p, AnalysisContext ctx, String filter) {
        if (m.kind() == Kind.SMB1_NEGOTIATE_RESPONSE && f.mark("smb.s1resp")) {
            ctx.relevant("NET-SMB-001");
            if (m.dialectIndex() != 0xFFFF) {
                String detail = "SMB1 NEGOTIATE response: DialectIndex=" + m.dialectIndex()
                        + (m.securityMode() >= 0 ? String.format(", SecurityMode=0x%02x", m.securityMode()) : "");
                ctx.observe(ObservationType.SMB1_ACCEPTED_BY_SERVER, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                        ctx.packetEvidence(p, detail, filter));
                ctx.finding("NET-SMB-001", f.server(), Status.FAIL, "Server " + f.server() + " accepted SMB1 from " + f.clientIp + ".",
                        ctx.packetEvidence(p, detail, filter), p.ts);
                if (m.securityMode() >= 0) {
                    signing(f, (m.securityMode() & 0x08) != 0, String.format("SMB1 SecurityMode=0x%02x (bit 0x08 = signatures required)", m.securityMode()), p, ctx, filter);
                }
            } else if (f.marked("smb.smb1only")) {
                ctx.observe(ObservationType.SMB1_REFUSED_BY_SERVER, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                        ctx.packetEvidence(p, "SMB1 NEGOTIATE response: DialectIndex=0xFFFF (no dialect acceptable)", filter));
            }
        } else if (m.kind() == Kind.SMB2_NEGOTIATE_RESPONSE && m.dialect() != 0x02FF && f.mark("smb.s2resp")) {
            boolean required = (m.securityMode() & 0x02) != 0;
            signing(f, required, String.format("SMB2 NEGOTIATE response: dialect %s, SecurityMode=0x%04x (bit 0x02 = signing required)",
                    SmbParser.smb2DialectName(m.dialect()), m.securityMode()), p, ctx, filter);
        }
    }

    private void signing(Flow f, boolean required, String detail, DecodedPacket p, AnalysisContext ctx, String filter) {
        ctx.relevant("NET-SMB-002");
        ctx.observe(required ? ObservationType.SMB_SIGNING_REQUIRED_BY_SERVER : ObservationType.SMB_SIGNING_NOT_REQUIRED_BY_SERVER,
                f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts, ctx.packetEvidence(p, detail, filter));
        if (!required) {
            ctx.finding("NET-SMB-002", f.server(), Status.FAIL, "SMB server " + f.server() + " does not require signing.",
                    ctx.packetEvidence(p, detail, filter), p.ts);
        }
    }

    private void boundary(Flow f, DecodedPacket p, AnalysisContext ctx) {
        ctx.relevant("NET-SMB-004");
        String from = ctx.segments.of(f.clientIp);
        String to = ctx.segments.of(f.serverIp);
        f.classify("SMB", false);
        if (!from.equals(to)) {
            boolean publicEnd = from.equals("public") || to.equals("public");
            ctx.finding("NET-SMB-004", from + " → " + to, Status.FAIL,
                    "SMB flows from segment " + from + " to " + to + (publicEnd ? " (involves a public address)" : "") + ".",
                    ctx.packetEvidence(p, "SMB " + f.label(), Filters.hostPort(f.serverIp, "tcp", f.serverPort)), p.ts);
        }
    }
}
