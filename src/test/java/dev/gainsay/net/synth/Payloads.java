package dev.gainsay.net.synth;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/** Builders for protocol payloads used in synthetic captures. */
public final class Payloads {

    /** Self-signed certificate for CN=legacy.lab.test, valid 2020-01-01..2020-01-31 (generated with keytool for tests). */
    public static final byte[] EXPIRED_SELF_SIGNED_CERT = Base64.getDecoder().decode(
            "MIIBSjCB8qADAgECAgkAolZRiJ4ZNvswCgYIKoZIzj0EAwMwGjEYMBYGA1UEAxMPbGVnYWN5LmxhYi50ZXN0MB4XDTIwMDEwMTIyNDU0MFoXDTIwMDEzMTIyNDU0MFow"
                    + "GjEYMBYGA1UEAxMPbGVnYWN5LmxhYi50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqWxl8qMhi4J3/mWgoUalEW0BQIdi7AUTcV5ltobOHyhuxr9wtb4tU52y"
                    + "l2zAk09sWxhTfJuiJLrzmQ0lJCpzbqMhMB8wHQYDVR0OBBYEFJGTTaMozorHBsCZXmPH9tYFTK2kMAoGCCqGSM49BAMDA0cAMEQCIHTaNinpz+8m1MKDTjl7CKUQw8TA"
                    + "Vm0AP2DrKla794k+AiAjwfB8axHjutqlhgYdsj1FsqQQ/BnCFgRZrkxg+OIzrA==");

    private Payloads() {
    }

    public static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    // ---------------- TLS ----------------

    public static byte[] tlsClientHello(int legacyVersion, List<Integer> supportedVersions, List<Integer> ciphers, String sni) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        u16(body, legacyVersion);
        body.writeBytes(new byte[32]);
        body.write(0); // session id
        u16(body, ciphers.size() * 2);
        ciphers.forEach(c -> u16(body, c));
        body.write(1);
        body.write(0); // null compression
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        if (sni != null) {
            byte[] n = ascii(sni);
            u16(ext, 0);
            u16(ext, n.length + 5);
            u16(ext, n.length + 3);
            ext.write(0);
            u16(ext, n.length);
            ext.writeBytes(n);
        }
        if (supportedVersions != null) {
            u16(ext, 43);
            u16(ext, 1 + supportedVersions.size() * 2);
            ext.write(supportedVersions.size() * 2);
            supportedVersions.forEach(v -> u16(ext, v));
        }
        if (ext.size() > 0) {
            u16(body, ext.size());
            body.writeBytes(ext.toByteArray());
        }
        return record(22, 0x0301, handshake(1, body.toByteArray()));
    }

    public static byte[] tlsServerHello(int version, int cipher, boolean viaExtension) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        u16(body, viaExtension ? 0x0303 : version);
        body.writeBytes(new byte[32]);
        body.write(0);
        u16(body, cipher);
        body.write(0);
        if (viaExtension) {
            u16(body, 6);
            u16(body, 43);
            u16(body, 2);
            u16(body, version);
        }
        return record(22, version >= 0x0303 ? 0x0303 : version, handshake(2, body.toByteArray()));
    }

    public static byte[] tlsCertificate(int version, byte[] der) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        u24(body, der.length + 3);
        u24(body, der.length);
        body.writeBytes(der);
        return record(22, version, handshake(11, body.toByteArray()));
    }

    public static byte[] tlsAlert() {
        return record(21, 0x0303, new byte[]{2, 70}); // fatal protocol_version
    }

    static byte[] handshake(int type, byte[] body) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(type);
        u24(o, body.length);
        o.writeBytes(body);
        return o.toByteArray();
    }

    static byte[] record(int type, int version, byte[] body) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(type);
        u16(o, version);
        u16(o, body.length);
        o.writeBytes(body);
        return o.toByteArray();
    }

    // ---------------- SMB ----------------

    public static byte[] smb1NegotiateRequest(List<String> dialects) {
        ByteArrayOutputStream d = new ByteArrayOutputStream();
        for (String s : dialects) {
            d.write(0x02);
            d.writeBytes(ascii(s));
            d.write(0);
        }
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.writeBytes(new byte[]{(byte) 0xFF, 'S', 'M', 'B', 0x72});
        m.writeBytes(new byte[4]);      // status
        m.write(0x18);                  // flags (request)
        m.writeBytes(new byte[22]);     // flags2 .. mid (header is 32 bytes)
        m.write(0);                     // WordCount
        u16le(m, d.size());
        m.writeBytes(d.toByteArray());
        return netbios(m.toByteArray());
    }

    public static byte[] smb1NegotiateResponse(int dialectIndex, int securityMode) {
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.writeBytes(new byte[]{(byte) 0xFF, 'S', 'M', 'B', 0x72});
        m.writeBytes(new byte[4]);
        m.write(0x98);                  // flags: reply
        m.writeBytes(new byte[22]);
        m.write(17);                    // WordCount
        u16le(m, dialectIndex);
        m.write(securityMode);
        m.writeBytes(new byte[31]);     // rest of the 17 words
        u16le(m, 0);                    // ByteCount
        return netbios(m.toByteArray());
    }

    public static byte[] smb2NegotiateRequest() {
        ByteArrayOutputStream m = smb2Header(false);
        u16le(m, 36);
        u16le(m, 2);
        u16le(m, 1);
        m.writeBytes(new byte[30]);
        u16le(m, 0x0302);
        u16le(m, 0x0311);
        return netbios(m.toByteArray());
    }

    public static byte[] smb2NegotiateResponse(int securityMode, int dialect) {
        ByteArrayOutputStream m = smb2Header(true);
        u16le(m, 65);
        u16le(m, securityMode);
        u16le(m, dialect);
        m.writeBytes(new byte[58]);
        return netbios(m.toByteArray());
    }

    private static ByteArrayOutputStream smb2Header(boolean response) {
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.writeBytes(new byte[]{(byte) 0xFE, 'S', 'M', 'B'});
        u16le(m, 64);
        m.writeBytes(new byte[6]);      // credit charge, status
        u16le(m, 0);                    // command NEGOTIATE
        u16le(m, 1);                    // credits
        u32le(m, response ? 1 : 0);     // flags
        m.writeBytes(new byte[44]);
        return m;
    }

    static byte[] netbios(byte[] msg) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0);
        u24(o, msg.length);
        o.writeBytes(msg);
        return o.toByteArray();
    }

    /** NTLMSSP AUTHENTICATE with the given NT response length, wrapped as an opaque SMB2 SESSION_SETUP-like blob. */
    public static byte[] ntlmAuthenticate(int ntLen) {
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.writeBytes(ascii("junk-spnego-prefix"));
        m.writeBytes(ascii("NTLMSSP\0"));
        u32le(m, 3);
        u16le(m, 24);
        u16le(m, 24);
        u32le(m, 88);   // LM response
        u16le(m, ntLen);
        u16le(m, ntLen);
        u32le(m, 112);  // NT response
        m.writeBytes(new byte[48]);
        return netbios(m.toByteArray());
    }

    // ---------------- RDP ----------------

    public static byte[] rdpConnectionRequest(long requestedProtocols) {
        byte[] cookie = ascii("Cookie: mstshash=alice\r\n");
        ByteArrayOutputStream x = new ByteArrayOutputStream();
        x.write(0xE0);
        x.writeBytes(new byte[5]);
        x.writeBytes(cookie);
        if (requestedProtocols >= 0) {
            x.write(0x01);
            x.write(0);
            u16le(x, 8);
            u32le(x, requestedProtocols);
        }
        return tpkt(x.toByteArray());
    }

    public static byte[] rdpConnectionConfirm(long selected) {
        ByteArrayOutputStream x = new ByteArrayOutputStream();
        x.write(0xD0);
        x.writeBytes(new byte[5]);
        x.write(0x02);
        x.write(0);
        u16le(x, 8);
        u32le(x, selected);
        return tpkt(x.toByteArray());
    }

    static byte[] tpkt(byte[] x224) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(3);
        o.write(0);
        u16(o, 4 + 1 + x224.length);
        o.write(x224.length);
        o.writeBytes(x224);
        return o.toByteArray();
    }

    // ---------------- DNS family ----------------

    public static byte[] dnsQuery(int id, String name) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, id);
        u16(o, 0x0100);
        u16(o, 1);
        u16(o, 0);
        u16(o, 0);
        u16(o, 0);
        for (String label : name.split("\\.")) {
            o.write(label.length());
            o.writeBytes(ascii(label));
        }
        o.write(0);
        u16(o, 1);
        u16(o, 1);
        return o.toByteArray();
    }

    public static byte[] dnsNxdomain(int id, String name) {
        byte[] q = dnsQuery(id, name);
        q[2] = (byte) 0x81;
        q[3] = (byte) 0x83; // QR, RD, RA, rcode 3
        return q;
    }

    public static byte[] nbnsQuery(String name) {
        StringBuilder enc = new StringBuilder();
        String padded = String.format("%-15s", name.toUpperCase()) + "\u0000";
        for (char c : padded.toCharArray()) {
            enc.append((char) ('A' + (c >> 4))).append((char) ('A' + (c & 0xf)));
        }
        return dnsQuery(0x1234, enc.toString());
    }

    // ---------------- misc UDP / TCP ----------------

    public static byte[] snmpGet(int version, String community) {
        byte[] c = ascii(community);
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.writeBytes(new byte[]{0x02, 0x01, (byte) version});
        inner.write(0x04);
        inner.write(c.length);
        inner.writeBytes(c);
        inner.writeBytes(new byte[]{(byte) 0xA0, 0x02, 0x30, 0x00});
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x30);
        o.write(inner.size());
        o.writeBytes(inner.toByteArray());
        return o.toByteArray();
    }

    public static byte[] tftpRead(String file) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, 1);
        o.writeBytes(ascii(file));
        o.write(0);
        o.writeBytes(ascii("octet"));
        o.write(0);
        return o.toByteArray();
    }

    public static byte[] ldapSimpleBind(String dn, String password) {
        byte[] d = ascii(dn);
        byte[] p = ascii(password);
        ByteArrayOutputStream bind = new ByteArrayOutputStream();
        bind.writeBytes(new byte[]{0x02, 0x01, 0x03});
        bind.write(0x04);
        bind.write(d.length);
        bind.writeBytes(d);
        bind.write(0x80);
        bind.write(p.length);
        bind.writeBytes(p);
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.writeBytes(new byte[]{0x02, 0x01, 0x01});
        msg.write(0x60);
        msg.write(bind.size());
        msg.writeBytes(bind.toByteArray());
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x30);
        o.write(msg.size());
        o.writeBytes(msg.toByteArray());
        return o.toByteArray();
    }

    public static byte[] dhcpOffer(String serverId) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(2);
        o.write(1);
        o.write(6);
        o.write(0);
        o.writeBytes(new byte[232]);
        u32(o, 0x63825363);
        o.writeBytes(new byte[]{53, 1, 2, 54, 4});
        o.writeBytes(dev.gainsay.core.Addresses.parse(serverId));
        o.write(255);
        return o.toByteArray();
    }

    // ---------------- byte helpers ----------------

    static void u16(ByteArrayOutputStream o, int v) {
        o.write((v >> 8) & 0xff);
        o.write(v & 0xff);
    }

    static void u24(ByteArrayOutputStream o, int v) {
        o.write((v >> 16) & 0xff);
        o.write((v >> 8) & 0xff);
        o.write(v & 0xff);
    }

    static void u32(ByteArrayOutputStream o, long v) {
        o.write((int) (v >> 24) & 0xff);
        o.write((int) (v >> 16) & 0xff);
        o.write((int) (v >> 8) & 0xff);
        o.write((int) v & 0xff);
    }

    static void u16le(ByteArrayOutputStream o, int v) {
        o.write(v & 0xff);
        o.write((v >> 8) & 0xff);
    }

    static void u32le(ByteArrayOutputStream o, long v) {
        o.write((int) v & 0xff);
        o.write((int) (v >> 8) & 0xff);
        o.write((int) (v >> 16) & 0xff);
        o.write((int) (v >> 24) & 0xff);
    }
}
