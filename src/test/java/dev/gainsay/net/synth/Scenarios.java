package dev.gainsay.net.synth;

import java.util.List;

import static dev.gainsay.net.synth.Payloads.ascii;

/**
 * The demo network used by the integration tests and by samples/: two audited Windows hosts
 * (WS-HARDENED 10.0.0.5 and WS-LEGACY 10.0.0.20, matching samples/fixtures) plus an old SMB1-only
 * scanner, a router and a web server on another segment.
 */
public final class Scenarios {

    public static final String HARDENED_IP = "10.0.0.5", HARDENED_MAC = "00:15:5d:01:02:05";
    public static final String LEGACY_IP = "10.0.0.20", LEGACY_MAC = "00:15:5d:01:02:14";
    public static final String SCANNER_IP = "10.0.0.42", SCANNER_MAC = "00:00:aa:00:00:42";
    public static final String ROUTER_IP = "10.0.0.7", ROUTER_MAC = "00:00:5e:00:01:07";
    public static final String WEB_IP = "10.0.1.80", GW_MAC = "00:00:5e:00:01:01";
    public static final String ADMIN_IP = "10.0.0.30", ADMIN_MAC = "00:00:aa:00:00:30";
    public static final String PASSWORD = "hunter2-SECRET";

    private Scenarios() {
    }

    /** Minimal capture required by the brief: cleartext HTTP, Telnet, SMB1 negotiate and a TLS 1.0 hello. */
    public static Capture brief() {
        Capture c = new Capture();
        http(c);
        telnet(c);
        smb1(c);
        tls10(c);
        return c;
    }

    /** The full demo: everything in {@link #brief()} plus evidence for most trial claims and hygiene signals. */
    public static Capture demo() {
        Capture c = brief();
        // LLMNR from the legacy host (its LLMNR is enabled by default)
        c.add(Frames.udpFrame(LEGACY_MAC, LEGACY_IP, 55355, "01:00:5e:00:00:fc", "224.0.0.252", 5355, Payloads.dnsQuery(7, "fileserv")));
        // NBT-NS broadcast from the legacy host
        c.add(Frames.udpFrame(LEGACY_MAC, LEGACY_IP, 137, "ff:ff:ff:ff:ff:ff", "10.0.0.255", 137, Payloads.nbnsQuery("FILESERV")));
        // NXDOMAIN to the hardened host, with no multicast fallback afterwards
        c.add(Frames.udpFrame(HARDENED_MAC, HARDENED_IP, 50001, ROUTER_MAC, ROUTER_IP, 53, Payloads.dnsQuery(9, "nosuchhost.corp.test")));
        c.add(Frames.udpFrame(ROUTER_MAC, ROUTER_IP, 53, HARDENED_MAC, HARDENED_IP, 50001, Payloads.dnsNxdomain(9, "nosuchhost.corp.test")));
        // Legacy host uses a public resolver
        c.add(Frames.udpFrame(LEGACY_MAC, LEGACY_IP, 50002, GW_MAC, "8.8.8.8", 53, Payloads.dnsQuery(11, "example.com")));
        // RDP to the hardened host is closed
        c.tcp(ADMIN_MAC, ADMIN_IP, 50100, HARDENED_MAC, HARDENED_IP, 3389).refused();
        // RDP to the legacy host: no NLA requested, none enforced
        c.tcp(ADMIN_MAC, ADMIN_IP, 50101, LEGACY_MAC, LEGACY_IP, 3389).handshake()
                .client(Payloads.rdpConnectionRequest(0)).server(Payloads.rdpConnectionConfirm(0));
        // SMB2 to the legacy host: signing not required; then an NTLMv1 authentication from the legacy host
        c.tcp(ADMIN_MAC, ADMIN_IP, 50102, LEGACY_MAC, LEGACY_IP, 445).handshake()
                .client(Payloads.smb2NegotiateRequest()).server(Payloads.smb2NegotiateResponse(0x01, 0x0302));
        c.tcp(LEGACY_MAC, LEGACY_IP, 50103, HARDENED_MAC, HARDENED_IP, 445).handshake()
                .client(Payloads.smb2NegotiateRequest()).server(Payloads.smb2NegotiateResponse(0x03, 0x0311))
                .client(Payloads.ntlmAuthenticate(24));
        // SNMP v2c with community "public"
        c.add(Frames.udpFrame(ADMIN_MAC, ADMIN_IP, 50200, ROUTER_MAC, ROUTER_IP, 161, Payloads.snmpGet(1, "public")));
        // ARP: 10.0.0.99 claimed by two MACs
        c.add(Frames.arp(2, "00:00:aa:00:00:99", "10.0.0.99", LEGACY_MAC, LEGACY_IP));
        c.add(Frames.arp(2, "00:00:bb:00:00:99", "10.0.0.99", LEGACY_MAC, LEGACY_IP));
        // Two DHCP servers
        c.add(Frames.udpFrame(ROUTER_MAC, "10.0.0.1", 67, "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68, Payloads.dhcpOffer("10.0.0.1")));
        c.add(Frames.udpFrame("00:00:cc:00:00:66", "10.0.0.66", 67, "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68, Payloads.dhcpOffer("10.0.0.66")));
        return c;
    }

    static void http(Capture c) {
        String body = "user=alice&password=" + PASSWORD;
        String req = "POST /login?next=/home HTTP/1.1\r\nHost: intranet.corp.test\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + body.length() + "\r\n\r\n" + body;
        String resp = "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: SESSIONID=0123456789abcdef; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n";
        c.tcp(LEGACY_MAC, LEGACY_IP, 50300, GW_MAC, WEB_IP, 80).handshake().clientSplit(ascii(req), 40).server(ascii(resp)).close();
    }

    static void telnet(Capture c) {
        c.tcp(LEGACY_MAC, LEGACY_IP, 50301, ROUTER_MAC, ROUTER_IP, 23).handshake()
                .server(new byte[]{(byte) 0xFF, (byte) 0xFD, 0x18, (byte) 0xFF, (byte) 0xFD, 0x20, (byte) 0xFF, (byte) 0xFB, 0x01})
                .client(ascii("admin\r\n")).client(ascii("letmein\r\n"));
    }

    static void smb1(Capture c) {
        c.tcp(SCANNER_MAC, SCANNER_IP, 50302, HARDENED_MAC, HARDENED_IP, 445).handshake()
                .client(Payloads.smb1NegotiateRequest(List.of("PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12")))
                .server(Payloads.smb1NegotiateResponse(2, 0x0F));
    }

    static void tls10(Capture c) {
        c.tcp(LEGACY_MAC, LEGACY_IP, 50303, HARDENED_MAC, HARDENED_IP, 443).handshake()
                .client(Payloads.tlsClientHello(0x0301, null, List.of(0x002F, 0x0035, 0x000A), "ws-hardened.corp.test"))
                .server(concat(Payloads.tlsServerHello(0x0301, 0x000A, false),
                        Payloads.tlsCertificate(0x0301, Payloads.EXPIRED_SELF_SIGNED_CERT)));
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }
}
