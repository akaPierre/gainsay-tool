package dev.gainsay.net.analyze;

import dev.gainsay.core.Redactor;
import dev.gainsay.core.Status;
import dev.gainsay.net.decode.Ber;
import dev.gainsay.net.decode.Bytes;
import dev.gainsay.net.decode.DecodedPacket;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * NET-LEGACY-001..007: Telnet, FTP, POP3/IMAP/SMTP without TLS, TFTP, SNMP v1/v2c, r-services, LDAP
 * simple bind. Text protocols are recognised by port plus content; credentials are never recorded
 * (commands are reduced to their verbs and masked).
 */
public final class LegacyProtocolAnalyzer implements Analyzer {

    static final Set<Integer> R_SERVICES = Set.of(512, 513, 514);
    static final Set<Integer> MAIL = Set.of(25, 110, 143, 587);

    @Override
    public List<String> checkIds() {
        return List.of("NET-LEGACY-001", "NET-LEGACY-002", "NET-LEGACY-003", "NET-LEGACY-004", "NET-LEGACY-005", "NET-LEGACY-006",
                "NET-LEGACY-007");
    }

    @Override
    public void onPacket(DecodedPacket p, Flow f, AnalysisContext ctx) {
        if (p.isTcp() && f != null && p.has(DecodedPacket.SYN) && p.has(DecodedPacket.ACK) && R_SERVICES.contains(f.serverPort)
                && f.mark("legacy.r")) {
            f.mark("cleartext");
            f.classify("r-services", true);
            ctx.finding("NET-LEGACY-006", f.server(), Status.FAIL, "Berkeley r-service listening and used on " + f.server() + ".",
                    ctx.packetEvidence(p, "SYN-ACK from TCP/" + f.serverPort + " (" + rName(f.serverPort) + ")",
                            Filters.hostPort(f.serverIp, "tcp", f.serverPort)), p.ts);
        }
        if (!p.isUdp() || p.payloadLength <= 0) {
            return;
        }
        if (p.dstPort == 69) {
            tftp(p, ctx);
        } else if (p.dstPort == 161 || p.dstPort == 162) {
            snmp(p, ctx);
        }
    }

    private void tftp(DecodedPacket p, AnalysisContext ctx) {
        try {
            int op = Bytes.u16(p.data, p.payloadOffset, p.payloadOffset + p.payloadLength);
            if (op != 1 && op != 2) {
                return;
            }
            int s = p.payloadOffset + 2;
            int end = p.payloadOffset + p.payloadLength;
            int z = s;
            while (z < end && p.data[z] != 0 && z - s < 128) {
                z++;
            }
            String file = Bytes.ascii(p.data, s, z - s);
            ctx.finding("NET-LEGACY-004", DecodedPacket.endpoint(p.dstIp, 69), Status.FAIL,
                    "TFTP " + (op == 1 ? "read" : "write") + " request from " + p.srcIp + ".",
                    ctx.packetEvidence(p, (op == 1 ? "RRQ " : "WRQ ") + file, Filters.host(p.dstIp) + " && tftp"), p.ts);
        } catch (Bytes.Malformed e) {
            // not TFTP
        }
    }

    private void snmp(DecodedPacket p, AnalysisContext ctx) {
        int end = p.payloadOffset + p.payloadLength;
        try {
            Ber.Tlv seq = Ber.read(p.data, p.payloadOffset, end);
            if (seq.tag() != 0x30) {
                return;
            }
            Ber.Tlv ver = Ber.read(p.data, seq.valueOffset(), end);
            if (ver.tag() != 0x02) {
                return;
            }
            long v = Ber.integer(p.data, ver, end);
            ctx.relevant("NET-LEGACY-005");
            if (v == 0 || v == 1) {
                Ber.Tlv community = Ber.read(p.data, ver.next(), end);
                if (community.tag() != 0x04) {
                    return;
                }
                String agent = p.dstPort == 161 ? p.dstIp : p.srcIp;
                ctx.finding("NET-LEGACY-005", DecodedPacket.endpoint(agent, p.dstPort), Status.FAIL,
                        "SNMP" + (v == 0 ? "v1" : "v2c") + " with a cleartext community string (" + p.src() + " → " + p.dst() + ").",
                        ctx.packetEvidence(p, "SNMP version=" + (v == 0 ? "1" : "2c") + ", community=" + Redactor.MASK
                                + " (" + community.valueLength() + " chars)", Filters.host(agent) + " && snmp"), p.ts);
            }
        } catch (Bytes.Malformed e) {
            // not SNMP
        }
    }

    @Override
    public void onStream(Flow f, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
        int port = f.serverPort;
        byte[] b = head.bytes();
        int n = head.length();
        if (!toServer && !f.marked("legacy.telnet") && (port == 23 || isTelnetNegotiation(b, n))) {
            f.mark("legacy.telnet");
            f.mark("cleartext");
            f.classify("Telnet", true);
            String detail = n > 0 && (b[0] & 0xff) == 0xFF ? "server option negotiation: " + Redactor.hex(b, 0, n, 12) : "TCP/23 session, " + n + " bytes from server";
            ctx.finding("NET-LEGACY-001", f.server(), Status.FAIL, "Telnet session " + f.label() + ".",
                    ctx.packetEvidence(p, detail, Filters.hostPort(f.serverIp, "tcp", port) + " && telnet"), p.ts);
        }
        if (R_SERVICES.contains(port) && f.mark("legacy.r")) {
            f.mark("cleartext");
            f.classify("r-services", true);
            ctx.finding("NET-LEGACY-006", f.server(), Status.FAIL, "Berkeley r-service session " + f.label() + ".",
                    ctx.packetEvidence(p, "data on TCP/" + port + " (" + rName(port) + ")", Filters.hostPort(f.serverIp, "tcp", port)), p.ts);
        }
        if (port == 21 || port == 110 || port == 143 || port == 25 || port == 587) {
            f.mark("legacy.text");
        }
        if (port == 389 && toServer) {
            ldap(f, b, n, p, ctx);
        }
    }

    @Override
    public void onFlowEnd(Flow f, AnalysisContext ctx) {
        if (!f.marked("legacy.text")) {
            return;
        }
        StreamHead c = f.head(true);
        String client = Bytes.ascii(c.bytes(), 0, Math.min(c.length(), 8192)).toUpperCase(Locale.ROOT);
        StreamHead s = f.head(false);
        String server = Bytes.ascii(s.bytes(), 0, Math.min(s.length(), 512));
        int port = f.serverPort;
        if (port == 21) {
            if (!server.startsWith("220") && !client.startsWith("USER ")) {
                return;
            }
            ctx.relevant("NET-LEGACY-002");
            int tls = indexOfCommand(client, "AUTH TLS", "AUTH SSL");
            if (tls >= 0) {
                return; // upgraded to FTPS
            }
            boolean pass = indexOfCommand(client, "PASS ") >= 0;
            f.mark("cleartext");
            f.classify("FTP", true);
            ctx.finding("NET-LEGACY-002", f.server(), Status.FAIL, "FTP without TLS " + f.label() + (pass ? "; a password was sent in clear." : "."),
                    new dev.gainsay.core.Evidence("packet", f.label(), pass ? "USER " + Redactor.MASK + " / PASS " + Redactor.MASK + " sent before any AUTH TLS"
                            : "FTP control session without AUTH TLS", ctx.tshark(Filters.hostPort(f.serverIp, "tcp", 21) + " && ftp")), f.start);
            return;
        }
        if (!MAIL.contains(port)) {
            return;
        }
        boolean looksLikeMail = server.startsWith("+OK") || server.startsWith("* OK") || server.startsWith("220");
        if (!looksLikeMail) {
            return;
        }
        ctx.relevant("NET-LEGACY-003");
        String proto = port == 110 ? "POP3" : port == 143 ? "IMAP" : "SMTP";
        int upgrade = indexOfCommand(client, "STARTTLS", "STLS");
        int auth = indexOfCommand(client, "AUTH ", "USER ", "PASS ", "APOP ", "LOGIN ");
        if (auth < 0 && client.length() > 0) {
            int sp = client.indexOf(" LOGIN ");
            auth = port == 143 && sp >= 0 ? sp : -1; // IMAP: "a1 LOGIN user pass"
        }
        if (upgrade >= 0 && (auth < 0 || upgrade < auth)) {
            return; // STARTTLS before any authentication: fine
        }
        f.mark("cleartext");
        f.classify(proto, true);
        String detail = auth >= 0 ? proto + " authentication command sent before STARTTLS (credentials " + Redactor.MASK + ")"
                : proto + " session without STARTTLS";
        ctx.finding("NET-LEGACY-003", f.server(), Status.FAIL, proto + " without TLS " + f.label() + ".",
                new dev.gainsay.core.Evidence("packet", f.label(), detail,
                        ctx.tshark(Filters.hostPort(f.serverIp, "tcp", port) + " && " + proto.toLowerCase(Locale.ROOT))), f.start);
    }

    /** Index of the first line starting with one of the commands (upper-cased input), or -1. */
    static int indexOfCommand(String upper, String... commands) {
        int best = -1;
        for (String c : commands) {
            int i = upper.startsWith(c) ? 0 : upper.indexOf("\n" + c);
            if (i < 0) {
                int tagged = upper.indexOf(" " + c); // IMAP tagged commands: "a1 STARTTLS"
                i = c.equals("STARTTLS") || c.equals("LOGIN ") ? tagged : -1;
            }
            if (i >= 0 && (best < 0 || i < best)) {
                best = i;
            }
        }
        return best;
    }

    private void ldap(Flow f, byte[] b, int n, DecodedPacket p, AnalysisContext ctx) {
        if (f.marked("ldap.done")) {
            return;
        }
        int off = 0;
        try {
            for (int msgs = 0; msgs < 4 && off + 2 <= n; msgs++) {
                Ber.Tlv msg = Ber.read(b, off, n);
                if (msg.tag() != 0x30) {
                    f.mark("ldap.done");
                    return;
                }
                Ber.Tlv id = Ber.read(b, msg.valueOffset(), n);
                Ber.Tlv op = Ber.read(b, id.next(), n);
                if (op.tag() == 0x77) { // ExtendedRequest: StartTLS (1.3.6.1.4.1.1466.20037) or other
                    String oid = Bytes.ascii(b, op.valueOffset(), Math.min(op.valueLength(), 40));
                    if (oid.contains("1.3.6.1.4.1.1466.20037")) {
                        f.mark("ldap.done");
                        ctx.relevant("NET-LEGACY-007");
                        return;
                    }
                }
                if (op.tag() == 0x60) { // BindRequest
                    ctx.relevant("NET-LEGACY-007");
                    Ber.Tlv version = Ber.read(b, op.valueOffset(), n);
                    Ber.Tlv name = Ber.read(b, version.next(), n);
                    Ber.Tlv authn = Ber.read(b, name.next(), n);
                    if (authn.tag() == 0x80 && authn.valueLength() > 0) {
                        f.mark("ldap.done");
                        f.mark("cleartext");
                        f.classify("LDAP", true);
                        ctx.finding("NET-LEGACY-007", f.server(), Status.FAIL, "LDAP simple bind with a password in clear " + f.label() + ".",
                                ctx.packetEvidence(p, "BindRequest: simple authentication, DN and password not recorded ("
                                        + authn.valueLength() + "-byte password " + Redactor.MASK + ")", Filters.hostPort(f.serverIp, "tcp", 389)
                                        + " && ldap.protocolOp==0"), p.ts);
                    }
                    f.mark("ldap.done");
                    return;
                }
                if (msg.next() > n) {
                    return; // wait for more bytes
                }
                off = msg.next();
            }
        } catch (Bytes.Malformed e) {
            // incomplete or not LDAP; try again when more bytes arrive
        }
    }

    static boolean isTelnetNegotiation(byte[] b, int n) {
        return n >= 3 && (b[0] & 0xff) == 0xFF && (b[1] & 0xff) >= 0xFB && (b[1] & 0xff) <= 0xFE;
    }

    private static String rName(int port) {
        return switch (port) {
            case 512 -> "rexec";
            case 513 -> "rlogin";
            default -> "rsh";
        };
    }
}
