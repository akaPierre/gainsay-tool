package dev.gainsay.net.synth;

import dev.gainsay.core.Addresses;

import java.io.ByteArrayOutputStream;

/** Builds raw Ethernet/IPv4/IPv6/TCP/UDP/ARP frames for tests. Checksums are left zero (Gainsay does not verify them). */
public final class Frames {

    private Frames() {
    }

    public static byte[] mac(String m) {
        String hex = m.replace(":", "").replace("-", "");
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) {
            b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    public static byte[] ethernet(String srcMac, String dstMac, int etherType, byte[] payload) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(mac(dstMac));
        o.writeBytes(mac(srcMac));
        o.write(etherType >> 8);
        o.write(etherType);
        o.writeBytes(payload);
        return o.toByteArray();
    }

    public static byte[] ip(String src, String dst, int proto, byte[] payload) {
        byte[] s = Addresses.parse(src);
        byte[] d = Addresses.parse(dst);
        if (s.length == 16) {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            o.write(0x60);
            o.write(0);
            o.write(0);
            o.write(0);
            o.write(payload.length >> 8);
            o.write(payload.length);
            o.write(proto);
            o.write(64);
            o.writeBytes(s);
            o.writeBytes(d);
            o.writeBytes(payload);
            return o.toByteArray();
        }
        int total = 20 + payload.length;
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x45);
        o.write(0);
        o.write(total >> 8);
        o.write(total);
        o.write(0);
        o.write(1);
        o.write(0x40); // DF
        o.write(0);
        o.write(64);
        o.write(proto);
        o.write(0);
        o.write(0);
        o.writeBytes(s);
        o.writeBytes(d);
        o.writeBytes(payload);
        return o.toByteArray();
    }

    public static byte[] tcp(int sp, int dp, long seq, long ack, int flags, byte[] payload) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, sp);
        u16(o, dp);
        u32(o, seq);
        u32(o, ack);
        o.write(5 << 4);
        o.write(flags);
        u16(o, 65535);
        u16(o, 0);
        u16(o, 0);
        o.writeBytes(payload);
        return o.toByteArray();
    }

    public static byte[] udp(int sp, int dp, byte[] payload) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, sp);
        u16(o, dp);
        u16(o, 8 + payload.length);
        u16(o, 0);
        o.writeBytes(payload);
        return o.toByteArray();
    }

    public static byte[] arp(int op, String senderMac, String senderIp, String targetMac, String targetIp) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u16(o, 1);
        u16(o, 0x0800);
        o.write(6);
        o.write(4);
        u16(o, op);
        o.writeBytes(mac(senderMac));
        o.writeBytes(Addresses.parse(senderIp));
        o.writeBytes(mac(targetMac));
        o.writeBytes(Addresses.parse(targetIp));
        return ethernet(senderMac, op == 1 ? "ff:ff:ff:ff:ff:ff" : targetMac, 0x0806, o.toByteArray());
    }

    public static byte[] udpFrame(String srcMac, String srcIp, int sp, String dstMac, String dstIp, int dp, byte[] payload) {
        boolean v6 = srcIp.contains(":");
        return ethernet(srcMac, dstMac, v6 ? 0x86DD : 0x0800, ip(srcIp, dstIp, 17, udp(sp, dp, payload)));
    }

    static void u16(ByteArrayOutputStream o, int v) {
        o.write((v >> 8) & 0xff);
        o.write(v & 0xff);
    }

    static void u32(ByteArrayOutputStream o, long v) {
        o.write((int) (v >> 24) & 0xff);
        o.write((int) (v >> 16) & 0xff);
        o.write((int) (v >> 8) & 0xff);
        o.write((int) v & 0xff);
    }
}
