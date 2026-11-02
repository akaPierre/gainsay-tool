package dev.gainsay.net.analyze;

import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.decode.CipherSuites;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.TlsParser;
import dev.gainsay.net.decode.TlsParser.ClientHello;
import dev.gainsay.net.decode.TlsParser.Handshake;
import dev.gainsay.net.decode.TlsParser.ServerHello;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * NET-TLS-001..004 and the TLS evidence for the trial, from handshake metadata only (never decrypts).
 */
public final class TlsAnalyzer implements Analyzer {

    @Override
    public List<String> checkIds() {
        return List.of("NET-TLS-001", "NET-TLS-002", "NET-TLS-003", "NET-TLS-004");
    }

    @Override
    public void onPacket(DecodedPacket p, Flow f, AnalysisContext ctx) {
        if (f != null && p.isTcp() && p.has(DecodedPacket.RST) && !f.fromClient(p) && f.marked("tls.legacyonly") && !f.marked("tls.sh")
                && f.mark("tls.refused")) {
            refused(f, p, ctx, "server reset the connection after a legacy-only ClientHello");
        }
    }

    @Override
    public void onStream(Flow f, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
        if (f.marked("tls.no") || (toServer ? f.marked("tls.ch") : f.marked("tls.sh") && f.marked("tls.cert"))) {
            return;
        }
        Handshake h = TlsParser.parse(head.bytes(), head.length());
        if (!h.tls()) {
            if (head.length() >= 5) {
                f.mark(toServer ? "tls.no" : "tls.noserver");
            }
            return;
        }
        String filter = Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && tls.handshake";
        if (toServer && h.clientHello() != null && f.mark("tls.ch")) {
            clientHello(f, h.clientHello(), p, ctx, filter);
        }
        if (!toServer) {
            if (h.serverHello() != null && f.mark("tls.sh")) {
                serverHello(f, h.serverHello(), p, ctx, filter);
            } else if (h.serverHello() == null && h.alert() && f.marked("tls.legacyonly") && f.mark("tls.refused")) {
                refused(f, p, ctx, "server answered a legacy-only ClientHello with an alert");
            }
            if (h.firstCertificate() != null && f.mark("tls.cert")) {
                certificate(f, h.firstCertificate(), p, ctx, filter);
            }
        }
    }

    private void clientHello(Flow f, ClientHello ch, DecodedPacket p, AnalysisContext ctx, String filter) {
        ctx.relevant("NET-TLS-001");
        ctx.relevant("NET-TLS-002");
        String versions = ch.supportedVersions().isEmpty() ? "legacy_version " + TlsParser.versionName(ch.legacyVersion())
                : "supported_versions " + ch.supportedVersions().stream().map(TlsParser::versionName).collect(Collectors.joining(", "));
        String detail = "ClientHello " + versions + (ch.sni() == null ? ", no SNI" : ", SNI " + ch.sni()) + (ch.sslv2() ? " (SSLv2-format hello)" : "");
        if (ch.offersLegacy()) {
            ctx.observe(ObservationType.TLS_LEGACY_OFFERED_BY_CLIENT, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, detail, filter + ".type==1"));
            if (!ch.legacyOnly()) {
                ctx.finding("NET-TLS-001", f.clientIp, Status.WARN, "Client " + f.clientIp + " still offers legacy TLS versions.",
                        ctx.packetEvidence(p, detail, filter + ".type==1"), p.ts);
            }
        } else if (ch.modernOnly()) {
            ctx.observe(ObservationType.TLS_MODERN_ONLY_OFFERED_BY_CLIENT, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, detail, filter + ".type==1"));
        }
        if (ch.legacyOnly()) {
            f.mark("tls.legacyonly");
            ctx.observe(ObservationType.TLS_LEGACY_ONLY_CLIENT_OFFER, f.clientIp, f.clientMac, f.serverIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, detail + " (cannot negotiate TLS 1.2+)", filter + ".type==1"));
        }
        List<String> weak = new ArrayList<>();
        for (int s : ch.cipherSuites()) {
            String w = CipherSuites.weakness(s);
            if (w != null && weak.size() < 6) {
                weak.add(CipherSuites.hex(s) + " " + w);
            }
        }
        if (!weak.isEmpty()) {
            ctx.finding("NET-TLS-002", f.clientIp, Status.WARN, "Client " + f.clientIp + " offers weak cipher suites.",
                    ctx.packetEvidence(p, "offered: " + String.join(", ", weak), filter + ".type==1"), p.ts);
        }
        if (f.serverPort == 443) {
            ctx.relevant("NET-TLS-004");
            if (ch.sni() == null && !ch.sslv2()) {
                ctx.finding("NET-TLS-004", f.clientIp, Status.WARN, "Client " + f.clientIp + " connects to " + f.server() + " without SNI.",
                        ctx.packetEvidence(p, detail, filter + ".type==1"), p.ts);
            }
        }
    }

    private void serverHello(Flow f, ServerHello sh, DecodedPacket p, AnalysisContext ctx, String filter) {
        ctx.relevant("NET-TLS-001");
        ctx.relevant("NET-TLS-002");
        int v = sh.selectedVersion();
        String detail = "ServerHello selected " + TlsParser.versionName(v) + ", cipher " + CipherSuites.hex(sh.cipherSuite())
                + (CipherSuites.weakness(sh.cipherSuite()) != null ? " (" + CipherSuites.weakness(sh.cipherSuite()) + ")" : "");
        if (v <= TlsParser.TLS11) {
            ctx.observe(ObservationType.TLS_LEGACY_NEGOTIATED_BY_SERVER, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, detail, filter + ".type==2"));
            ctx.finding("NET-TLS-001", f.server(), Status.FAIL, "Server " + f.server() + " negotiated " + TlsParser.versionName(v)
                    + " with " + f.clientIp + ".", ctx.packetEvidence(p, detail, filter + ".type==2"), p.ts);
        }
        if (CipherSuites.weakness(sh.cipherSuite()) != null) {
            ctx.finding("NET-TLS-002", f.server(), Status.FAIL, "Server " + f.server() + " selected a weak cipher suite.",
                    ctx.packetEvidence(p, detail, filter + ".type==2"), p.ts);
        }
    }

    private void certificate(Flow f, byte[] der, DecodedPacket p, AnalysisContext ctx, String filter) {
        try {
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            ctx.relevant("NET-TLS-003");
            List<String> problems = new ArrayList<>();
            java.util.Date when = java.util.Date.from(p.ts);
            if (c.getNotAfter().before(when)) {
                problems.add("expired " + c.getNotAfter().toInstant());
            }
            if (c.getNotBefore().after(when)) {
                problems.add("not valid before " + c.getNotBefore().toInstant());
            }
            if (c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
                problems.add("self-signed");
            }
            if (!problems.isEmpty()) {
                ctx.finding("NET-TLS-003", f.server(), Status.FAIL, "Certificate presented by " + f.server() + " is " + String.join(" and ", problems) + ".",
                        ctx.packetEvidence(p, "subject " + c.getSubjectX500Principal().getName() + ", issuer " + c.getIssuerX500Principal().getName()
                                + ", " + String.join(", ", problems), filter + ".type==11"), p.ts);
            }
        } catch (Exception e) {
            // unparseable certificate: ignore rather than guess
        }
    }

    private void refused(Flow f, DecodedPacket p, AnalysisContext ctx, String why) {
        ctx.observe(ObservationType.TLS_LEGACY_REFUSED_BY_SERVER, f.serverIp, f.serverMac, f.clientIp, f.serverPort, p.ts,
                ctx.packetEvidence(p, why, Filters.hostPort(f.serverIp, "tcp", f.serverPort)));
    }
}
