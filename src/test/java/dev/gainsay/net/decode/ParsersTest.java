package dev.gainsay.net.decode;

import dev.gainsay.net.synth.Payloads;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ParsersTest {

    @Test
    void tlsClientHelloWithSupportedVersionsAndSni() {
        byte[] ch = Payloads.tlsClientHello(0x0303, List.of(0x0A0A, 0x0304, 0x0303), List.of(0x1301, 0x000A), "example.test");
        TlsParser.ClientHello h = TlsParser.parse(ch, ch.length).clientHello();
        assertEquals("example.test", h.sni());
        assertEquals(List.of(0x0304, 0x0303), h.supportedVersions(), "GREASE ignored");
        assertTrue(h.modernOnly());
        assertFalse(h.offersLegacy());
        assertEquals(List.of(0x1301, 0x000A), h.cipherSuites());
    }

    @Test
    void tlsLegacyClientHelloWithoutExtensions() {
        byte[] ch = Payloads.tlsClientHello(0x0301, null, List.of(0x002F), null);
        TlsParser.ClientHello h = TlsParser.parse(ch, ch.length).clientHello();
        assertTrue(h.legacyOnly());
        assertTrue(h.offersLegacy());
        assertNull(h.sni());
    }

    @Test
    void tlsServerHelloVersionFromExtensionAndCertificate() {
        byte[] sh = Payloads.tlsServerHello(0x0304, 0x1301, true);
        assertEquals(0x0304, TlsParser.parse(sh, sh.length).serverHello().selectedVersion());
        byte[] legacy = concat(Payloads.tlsServerHello(0x0301, 0x000A, false), Payloads.tlsCertificate(0x0301, Payloads.EXPIRED_SELF_SIGNED_CERT));
        TlsParser.Handshake h = TlsParser.parse(legacy, legacy.length);
        assertEquals(0x0301, h.serverHello().selectedVersion());
        assertArrayEquals(Payloads.EXPIRED_SELF_SIGNED_CERT, h.firstCertificate());
        assertEquals("3DES (Sweet32)", CipherSuites.weakness(0x000A));
        assertNull(CipherSuites.weakness(0x1301));
    }

    @Test
    void tlsStopsAtEncryptedRecordsAndHandlesPartialRecords() {
        byte[] ch = Payloads.tlsClientHello(0x0303, null, List.of(0x002F), "a.test");
        byte[] half = java.util.Arrays.copyOf(ch, ch.length / 2);
        assertNull(TlsParser.parse(half, half.length).clientHello(), "incomplete hello waits for more bytes");
        assertFalse(TlsParser.parse(new byte[]{'G', 'E', 'T', ' ', '/'}, 5).tls());
    }

    @Test
    void smbNegotiateMessages() {
        byte[] req = Payloads.smb1NegotiateRequest(List.of("NT LM 0.12", "SMB 2.002", "SMB 2.???"));
        SmbParser.Message m = SmbParser.parse(req, req.length).get(0);
        assertEquals(SmbParser.Kind.SMB1_NEGOTIATE_REQUEST, m.kind());
        assertEquals(List.of("NT LM 0.12", "SMB 2.002", "SMB 2.???"), m.dialects());
        byte[] resp = Payloads.smb1NegotiateResponse(0, 0x0F);
        SmbParser.Message r = SmbParser.parse(resp, resp.length).get(0);
        assertEquals(0, r.dialectIndex());
        assertEquals(0x0F, r.securityMode());
        byte[] s2 = Payloads.smb2NegotiateResponse(0x01, 0x0311);
        SmbParser.Message r2 = SmbParser.parse(s2, s2.length).get(0);
        assertEquals(SmbParser.Kind.SMB2_NEGOTIATE_RESPONSE, r2.kind());
        assertEquals(0x0311, r2.dialect());
        assertEquals(0x01, r2.securityMode());
    }

    @Test
    void rdpNegotiation() {
        byte[] cr = Payloads.rdpConnectionRequest(RdpParser.PROTOCOL_SSL | RdpParser.PROTOCOL_HYBRID);
        RdpParser.X224 x = RdpParser.parse(cr, cr.length);
        assertTrue(x.request());
        assertTrue(x.nla(x.requestedProtocols()), "cookie line skipped, NEG_REQ found");
        byte[] cc = Payloads.rdpConnectionConfirm(RdpParser.PROTOCOL_SSL);
        RdpParser.X224 y = RdpParser.parse(cc, cc.length);
        assertEquals(RdpParser.PROTOCOL_SSL, y.selectedProtocol());
        assertFalse(y.nla(y.selectedProtocol()));
    }

    @Test
    void ntlmResponseLengthsOnly() {
        byte[] v1 = Payloads.ntlmAuthenticate(24);
        assertTrue(NtlmParser.find(v1, v1.length).get(0).ntlmV1());
        byte[] v2 = Payloads.ntlmAuthenticate(330);
        assertFalse(NtlmParser.find(v2, v2.length).get(0).ntlmV1());
        String http = "GET / HTTP/1.1\r\nAuthorization: NTLM " + java.util.Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOfRange(v1, 4 + 18, v1.length)) + "\r\n\r\n";
        byte[] h = http.getBytes();
        assertTrue(NtlmParser.find(h, h.length).get(0).ntlmV1(), "base64 NTLM in HTTP headers");
    }

    @Test
    void dnsAndNetbiosNames() {
        byte[] q = Payloads.dnsQuery(1, "fileserv.corp.test");
        DnsParser.Header h = DnsParser.parse(q, 0, q.length);
        assertEquals("fileserv.corp.test", h.firstName());
        assertFalse(h.response());
        byte[] nx = Payloads.dnsNxdomain(1, "x.test");
        assertEquals(3, DnsParser.parse(nx, 0, nx.length).rcode());
        byte[] nb = Payloads.nbnsQuery("FILESERV");
        assertEquals("FILESERV", DnsParser.netbiosName(DnsParser.parse(nb, 0, nb.length).firstName()));
    }

    @Test
    void httpHeadParsing() {
        byte[] b = "POST /a/b?x=1&password=z HTTP/1.1\r\nHost: h\r\nCookie: a=b\r\n\r\nbody".getBytes();
        HttpHead h = HttpHead.parse(b, b.length);
        assertTrue(h.complete);
        assertEquals("/a/b", h.path());
        assertEquals("x=1&password=z", h.query());
        assertEquals("h", h.header("host"));
        assertEquals("body", new String(b, h.bodyOffset, b.length - h.bodyOffset));
    }

    @Test
    void parsersSurviveRandomInput() {
        Random r = new Random(7);
        for (int i = 0; i < 20_000; i++) {
            byte[] b = new byte[r.nextInt(300)];
            r.nextBytes(b);
            if (b.length > 0 && r.nextBoolean()) {
                b[0] = (byte) (r.nextBoolean() ? 22 : 0); // steer towards TLS / NetBIOS framing
            }
            assertDoesNotThrow(() -> {
                TlsParser.parse(b, b.length);
                SmbParser.parse(b, b.length);
                RdpParser.parse(b, b.length);
                NtlmParser.find(b, b.length);
                DnsParser.parse(b, 0, b.length);
                HttpHead.parse(b, b.length);
            });
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }
}
