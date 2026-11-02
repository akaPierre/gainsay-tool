package dev.gainsay.net.analyze;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Json;
import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.Observation;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.NetAnalysis;
import dev.gainsay.net.synth.Capture;
import dev.gainsay.net.synth.Frames;
import dev.gainsay.net.synth.Payloads;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static dev.gainsay.net.synth.Payloads.ascii;
import static org.junit.jupiter.api.Assertions.*;

/** One synthetic capture per analyzer; each asserts the findings and trial observations it should produce. */
class AnalyzersTest {

    static final String C_MAC = "00:00:00:00:00:0c", S_MAC = "00:00:00:00:00:05";

    static Report run(Capture c) throws Exception {
        return NetAnalysis.analyze(c.source(), NetAnalysis.Options.defaults());
    }

    static Optional<Finding> find(Report r, String id, Status st) {
        return r.findings.stream().filter(f -> f.id().equals(id) && f.status() == st).findFirst();
    }

    static Status status(Report r, String id) {
        return r.findings.stream().filter(f -> f.id().equals(id)).map(Finding::status).reduce((a, b) -> a.badness() >= b.badness() ? a : b).orElseThrow();
    }

    static boolean observed(Report r, ObservationType t, String ip) {
        return r.observations.stream().anyMatch(o -> o.type() == t && o.ip().equals(ip));
    }

    static String json(Report r) throws Exception {
        return Json.MAPPER.writeValueAsString(r);
    }

    @Test
    void httpCleartextCredentialsAndCookiesAreRedacted() throws Exception {
        String req = "POST /login HTTP/1.1\r\nHost: app\r\nAuthorization: Basic dXNlcjpzM2NyZXQ=\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: 25\r\n\r\nuser=bob&password=s3cr3tX";
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.9", 40000, S_MAC, "10.0.0.5", 8080).handshake().clientSplit(ascii(req), 20)
                .server(ascii("HTTP/1.1 200 OK\r\nSet-Cookie: sid=abcdef123; Path=/\r\n\r\n"));
        Report r = run(c);
        assertTrue(find(r, "NET-HTTP-001", Status.FAIL).isPresent());
        Finding cred = find(r, "NET-HTTP-002", Status.FAIL).orElseThrow();
        assertTrue(cred.evidence().get(0).detail().contains("Authorization: Basic ****"));
        assertTrue(cred.evidence().get(0).detail().contains("form field password=****"));
        assertTrue(find(r, "NET-HTTP-003", Status.FAIL).isPresent());
        String all = json(r);
        assertFalse(all.contains("s3cr3tX"));
        assertFalse(all.contains("dXNlcjpzM2NyZXQ="));
        assertFalse(all.contains("abcdef123"));
    }

    @Test
    void winrmHttpIsNotCleartextHttp() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.9", 40001, S_MAC, "10.0.0.5", 5985).handshake().client(ascii("POST /wsman HTTP/1.1\r\nHost: x\r\n\r\n"));
        assertEquals(Status.NOT_APPLICABLE, status(run(c), "NET-HTTP-001"));
    }

    @Test
    void legacyTextProtocols() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.9", 40002, S_MAC, "10.0.0.7", 23).handshake().server(new byte[]{(byte) 0xFF, (byte) 0xFD, 0x18});
        c.tcp(C_MAC, "10.0.0.9", 40003, S_MAC, "10.0.0.7", 21).handshake().server(ascii("220 ftp ready\r\n"))
                .client(ascii("USER bob\r\n")).client(ascii("PASS secretftp\r\n"));
        c.tcp(C_MAC, "10.0.0.9", 40004, S_MAC, "10.0.0.8", 143).handshake().server(ascii("* OK IMAP ready\r\n"))
                .client(ascii("a1 LOGIN bob imappw\r\n"));
        c.tcp(C_MAC, "10.0.0.9", 40005, S_MAC, "10.0.0.8", 587).handshake().server(ascii("220 smtp ESMTP\r\n"))
                .client(ascii("EHLO me\r\n")).client(ascii("STARTTLS\r\n"));
        c.tcp(C_MAC, "10.0.0.9", 40006, S_MAC, "10.0.0.7", 513).handshake();
        c.tcp(C_MAC, "10.0.0.9", 40007, S_MAC, "10.0.0.10", 389).handshake().client(Payloads.ldapSimpleBind("cn=bob,dc=corp", "ldappw"));
        c.add(Frames.udpFrame(C_MAC, "10.0.0.9", 40008, S_MAC, "10.0.0.7", 69, Payloads.tftpRead("router.cfg")));
        c.add(Frames.udpFrame(C_MAC, "10.0.0.9", 40009, S_MAC, "10.0.0.7", 161, Payloads.snmpGet(1, "s3cretcommunity")));
        Report r = run(c);
        assertEquals(Status.FAIL, status(r, "NET-LEGACY-001"));
        Finding ftp = find(r, "NET-LEGACY-002", Status.FAIL).orElseThrow();
        assertTrue(ftp.summary().contains("password"));
        Finding mail = find(r, "NET-LEGACY-003", Status.FAIL).orElseThrow();
        assertTrue(mail.subject().contains("10.0.0.8:143"), "IMAP login without STARTTLS fails; SMTP with STARTTLS passes");
        assertEquals(1, r.findings.stream().filter(f -> f.id().equals("NET-LEGACY-003") && f.status() == Status.FAIL).count());
        assertEquals(Status.FAIL, status(r, "NET-LEGACY-004"));
        assertEquals(Status.FAIL, status(r, "NET-LEGACY-005"));
        assertEquals(Status.FAIL, status(r, "NET-LEGACY-006"));
        assertEquals(Status.FAIL, status(r, "NET-LEGACY-007"));
        String all = json(r);
        for (String secret : List.of("secretftp", "imappw", "ldappw", "s3cretcommunity", "cn=bob")) {
            assertFalse(all.contains(secret), secret + " must not appear in the report");
        }
    }

    @Test
    void smb1AcceptedAndRefusedAndSigning() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.42", 40010, S_MAC, "10.0.0.5", 445).handshake()
                .client(Payloads.smb1NegotiateRequest(List.of("NT LM 0.12"))).server(Payloads.smb1NegotiateResponse(0, 0x03));
        c.tcp(C_MAC, "10.0.0.42", 40011, "00:00:00:00:00:06", "10.0.0.6", 445).handshake()
                .client(Payloads.smb1NegotiateRequest(List.of("NT LM 0.12"))).serverReset();
        c.tcp(C_MAC, "10.0.0.9", 40012, "00:00:00:00:00:07", "10.0.0.7", 445).handshake()
                .client(Payloads.smb2NegotiateRequest()).server(Payloads.smb2NegotiateResponse(0x03, 0x0311));
        Report r = run(c);
        assertTrue(find(r, "NET-SMB-001", Status.FAIL).orElseThrow().subject().startsWith("10.0.0.5"));
        assertTrue(observed(r, ObservationType.SMB1_ACCEPTED_BY_SERVER, "10.0.0.5"));
        assertTrue(observed(r, ObservationType.SMB1_ONLY_CLIENT_OFFER, "10.0.0.42"));
        assertTrue(observed(r, ObservationType.SMB1_REFUSED_BY_SERVER, "10.0.0.6"));
        assertTrue(observed(r, ObservationType.SMB2_DIRECT_NEGOTIATE_BY_CLIENT, "10.0.0.9"));
        assertTrue(observed(r, ObservationType.SMB_SIGNING_NOT_REQUIRED_BY_SERVER, "10.0.0.5"), "SMB1 SecurityMode 0x03 lacks 0x08");
        assertTrue(observed(r, ObservationType.SMB_SIGNING_REQUIRED_BY_SERVER, "10.0.0.7"));
        assertEquals(Status.FAIL, status(r, "NET-SMB-002"));
    }

    @Test
    void smbAcrossSegmentsIsFlagged() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.9.9", 40013, S_MAC, "10.0.0.5", 445).handshake().client(Payloads.smb2NegotiateRequest());
        Finding f = find(run(c), "NET-SMB-004", Status.FAIL).orElseThrow();
        assertEquals("10.0.9.0/24 → 10.0.0.0/24", f.subject());
    }

    @Test
    void ntlmVersions() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.20", 40014, S_MAC, "10.0.0.5", 445).handshake().client(Payloads.ntlmAuthenticate(24));
        c.tcp("00:00:00:00:00:21", "10.0.0.21", 40015, S_MAC, "10.0.0.5", 445).handshake().client(Payloads.ntlmAuthenticate(300));
        Report r = run(c);
        assertTrue(find(r, "NET-SMB-003", Status.FAIL).orElseThrow().subject().equals("10.0.0.20"));
        assertTrue(observed(r, ObservationType.NTLMV1_SENT, "10.0.0.20"));
        assertTrue(observed(r, ObservationType.NTLMV2_SENT, "10.0.0.21"));
    }

    @Test
    void tlsVersionsCiphersCertificatesAndSni() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.20", 40016, S_MAC, "10.0.0.5", 443).handshake()
                .client(Payloads.tlsClientHello(0x0301, null, List.of(0x000A), null))
                .server(concat(Payloads.tlsServerHello(0x0301, 0x000A, false), Payloads.tlsCertificate(0x0301, Payloads.EXPIRED_SELF_SIGNED_CERT)));
        c.tcp("00:00:00:00:00:22", "10.0.0.22", 40017, "00:00:00:00:00:08", "10.0.0.8", 443).handshake()
                .client(Payloads.tlsClientHello(0x0303, List.of(0x0304, 0x0303), List.of(0x1301), "ok.test"))
                .server(Payloads.tlsServerHello(0x0304, 0x1301, true));
        c.tcp("00:00:00:00:00:23", "10.0.0.23", 40018, "00:00:00:00:00:09", "10.0.0.9", 443).handshake()
                .client(Payloads.tlsClientHello(0x0302, null, List.of(0x002F), "x.test")).server(Payloads.tlsAlert());
        Report r = run(c);
        assertTrue(find(r, "NET-TLS-001", Status.FAIL).orElseThrow().subject().equals("10.0.0.5:443"));
        assertTrue(find(r, "NET-TLS-002", Status.FAIL).isPresent());
        Finding cert = find(r, "NET-TLS-003", Status.FAIL).orElseThrow();
        assertTrue(cert.summary().contains("expired") && cert.summary().contains("self-signed"));
        assertTrue(find(r, "NET-TLS-004", Status.WARN).isPresent());
        assertTrue(observed(r, ObservationType.TLS_LEGACY_NEGOTIATED_BY_SERVER, "10.0.0.5"));
        assertTrue(observed(r, ObservationType.TLS_LEGACY_ONLY_CLIENT_OFFER, "10.0.0.20"));
        assertTrue(observed(r, ObservationType.TLS_MODERN_ONLY_OFFERED_BY_CLIENT, "10.0.0.22"));
        assertTrue(observed(r, ObservationType.TLS_LEGACY_REFUSED_BY_SERVER, "10.0.0.9"));
    }

    @Test
    void rdpNla() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.30", 40019, S_MAC, "10.0.0.20", 3389).handshake()
                .client(Payloads.rdpConnectionRequest(0x1)).server(Payloads.rdpConnectionConfirm(0x1));
        c.tcp(C_MAC, "10.0.0.30", 40020, "00:00:00:00:00:31", "10.0.0.31", 3389).handshake()
                .client(Payloads.rdpConnectionRequest(0x3)).server(Payloads.rdpConnectionConfirm(0x2));
        Report r = run(c);
        assertEquals(Status.FAIL, status(r, "NET-EXPOSE-002"));
        assertTrue(observed(r, ObservationType.RDP_NLA_NOT_ENFORCED, "10.0.0.20"));
        assertTrue(observed(r, ObservationType.RDP_NON_NLA_CLIENT_REQUEST, "10.0.0.30"));
        assertTrue(observed(r, ObservationType.RDP_NLA_ENFORCED, "10.0.0.31"));
        assertFalse(json(r).contains("alice"), "the mstshash cookie (user name) is never recorded");
    }

    @Test
    void nameResolution() throws Exception {
        Capture c = new Capture();
        c.add(Frames.udpFrame(C_MAC, "10.0.0.20", 50000, "01:00:5e:00:00:fc", "224.0.0.252", 5355, Payloads.dnsQuery(1, "wpad")));
        c.add(Frames.udpFrame(C_MAC, "10.0.0.20", 137, "ff:ff:ff:ff:ff:ff", "10.0.0.255", 137, Payloads.nbnsQuery("WPAD")));
        c.add(Frames.udpFrame(C_MAC, "10.0.0.20", 5353, "01:00:5e:00:00:fb", "224.0.0.251", 5353, Payloads.dnsQuery(0, "printer.local")));
        c.add(Frames.udpFrame(C_MAC, "10.0.0.20", 50001, S_MAC, "1.1.1.1", 53, Payloads.dnsQuery(2, "example.com")));
        c.add(Frames.udpFrame(S_MAC, "10.0.0.1", 53, C_MAC, "10.0.0.20", 50002, Payloads.dnsNxdomain(3, "nope.test")));
        Report r = run(c);
        assertEquals(Status.FAIL, status(r, "NET-NAME-001"));
        assertEquals(Status.FAIL, status(r, "NET-NAME-002"));
        assertEquals(Status.WARN, status(r, "NET-NAME-003"));
        assertEquals(Status.WARN, status(r, "NET-NAME-004"));
        assertTrue(observed(r, ObservationType.LLMNR_QUERY_SENT, "10.0.0.20"));
        assertTrue(observed(r, ObservationType.NBNS_QUERY_SENT, "10.0.0.20"));
        assertTrue(observed(r, ObservationType.DNS_NXDOMAIN_RECEIVED, "10.0.0.20"));
    }

    @Test
    void expectedResolversOption() throws Exception {
        Capture c = new Capture();
        c.add(Frames.udpFrame(C_MAC, "10.0.0.20", 50001, S_MAC, "10.0.0.53", 53, Payloads.dnsQuery(2, "example.com")));
        NetAnalysis.Options o = NetAnalysis.Options.defaults().with(null, Set.of("10.0.0.1"), null);
        Report r = NetAnalysis.analyze(c.source(), o);
        assertEquals(Status.WARN, status(r, "NET-NAME-004"));
    }

    @Test
    void exposureIsPassiveAndSegmentAware() throws Exception {
        Capture c = new Capture();
        c.tcp(C_MAC, "10.0.0.9", 40021, S_MAC, "10.0.0.5", 3389).handshake();
        c.tcp(C_MAC, "10.0.1.9", 40022, S_MAC, "10.0.0.5", 1433).handshake();
        c.tcp(C_MAC, "10.0.0.9", 40023, S_MAC, "10.0.0.5", 6379).handshake();
        c.tcp(C_MAC, "10.0.0.9", 40024, "00:00:00:00:00:06", "10.0.0.6", 3389).refused();
        Report r = run(c);
        List<Finding> fs = r.findings.stream().filter(f -> f.id().equals("NET-EXPOSE-001")).toList();
        assertEquals(Status.WARN, fs.stream().filter(f -> f.subject().contains(":3389")).findFirst().orElseThrow().status());
        assertEquals(Status.FAIL, fs.stream().filter(f -> f.subject().contains(":1433")).findFirst().orElseThrow().status(), "reached from another segment");
        assertEquals(Status.FAIL, fs.stream().filter(f -> f.subject().contains(":6379")).findFirst().orElseThrow().status(), "Redis is never OK to expose");
        assertTrue(r.observations.stream().anyMatch(o -> o.type() == ObservationType.SERVICE_LISTENING && o.port() == 3389));
        assertTrue(r.observations.stream().anyMatch(o -> o.type() == ObservationType.PORT_CLOSED && o.ip().equals("10.0.0.6")));
    }

    @Test
    void hygieneArpDhcpAndBoundary() throws Exception {
        Capture c = new Capture();
        c.add(Frames.arp(2, "00:00:aa:00:00:99", "10.0.0.99", C_MAC, "10.0.0.1"));
        c.add(Frames.arp(2, "00:00:bb:00:00:99", "10.0.0.99", C_MAC, "10.0.0.1"));
        c.add(Frames.arp(1, "00:00:cc:00:00:01", "0.0.0.0", "00:00:00:00:00:00", "10.0.0.99")); // ARP probe: ignored
        c.add(Frames.udpFrame(S_MAC, "10.0.0.1", 67, "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68, Payloads.dhcpOffer("10.0.0.1")));
        c.add(Frames.udpFrame("00:00:00:00:00:66", "10.0.0.66", 67, "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68, Payloads.dhcpOffer("10.0.0.66")));
        c.tcp(C_MAC, "10.0.5.5", 40025, S_MAC, "10.0.0.7", 23).handshake().server(new byte[]{(byte) 0xFF, (byte) 0xFB, 0x01});
        Report r = run(c);
        assertEquals(Status.FAIL, status(r, "NET-HYG-001"));
        assertEquals(Status.FAIL, status(r, "NET-HYG-002"));
        assertEquals(Status.FAIL, status(r, "NET-HYG-003"));
        assertTrue(r.boundaries.stream().anyMatch(b -> b.cleartext() && b.protocol().equals("Telnet")));
    }

    @Test
    void routerMacsAreNotTrustedForHostMatching() throws Exception {
        String router = "00:00:5e:00:01:01";
        Capture c = new Capture();
        c.add(Frames.udpFrame(router, "10.0.1.10", 50000, "01:00:5e:00:00:fc", "224.0.0.252", 5355, Payloads.dnsQuery(1, "a")));
        c.add(Frames.udpFrame(router, "10.0.1.11", 50000, "01:00:5e:00:00:fc", "224.0.0.252", 5355, Payloads.dnsQuery(1, "b")));
        c.add(Frames.udpFrame(C_MAC, "10.0.0.12", 50000, "01:00:5e:00:00:fc", "224.0.0.252", 5355, Payloads.dnsQuery(1, "c")));
        Report r = run(c);
        for (Observation o : r.observations) {
            if (o.ip().startsWith("10.0.1.")) {
                assertNull(o.mac(), "MAC seen with several IPs is a router");
            } else {
                assertEquals(C_MAC, o.mac());
            }
        }
    }

    @Test
    void checksWithoutTrafficAreNotApplicableNotPass() throws Exception {
        Report r = run(new Capture().add(Frames.arp(1, C_MAC, "10.0.0.9", "00:00:00:00:00:00", "10.0.0.1")));
        assertEquals(Status.NOT_APPLICABLE, status(r, "NET-TLS-001"));
        assertEquals(Status.PASS, status(r, "NET-HYG-001"));
    }

    @Test
    void hostileTrafficIsSurvivedAndMemoryBounded() throws Exception {
        java.util.Random rnd = new java.util.Random(1);
        Capture c = new Capture();
        for (int i = 0; i < 3000; i++) {
            byte[] junk = new byte[rnd.nextInt(400)];
            rnd.nextBytes(junk);
            int port = new int[]{80, 443, 445, 3389, 389, 21, 23, 53, 161}[rnd.nextInt(9)];
            c.tcp(C_MAC, "10.1." + (i % 250) + "." + (i / 250 + 1), 1024 + i, S_MAC, "10.0.0.5", port).handshake().client(junk).server(junk);
        }
        NetAnalysis.Options o = new NetAnalysis.Options(500, 4096, 512 * 1024, dev.gainsay.net.Segments.defaults(), Set.of());
        Report r = assertDoesNotThrow(() -> NetAnalysis.analyze(c.source(), o));
        assertTrue(r.captures.get(0).flowsEvicted() > 0);
        assertEquals(0, r.captures.get(0).malformed());
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }
}
