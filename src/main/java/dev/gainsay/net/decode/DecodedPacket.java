package dev.gainsay.net.decode;

import java.time.Instant;

/**
 * The layers Gainsay understands, decoded from one frame. Fields not present in the frame are
 * null/-1. {@code payload} is a view into {@code data} ({@code payloadOffset}, {@code payloadLength});
 * it is never copied, logged or stored.
 */
public final class DecodedPacket {

    public static final int TCP = 6;
    public static final int UDP = 17;

    // TCP flag bits
    public static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

    public long frame;
    public Instant ts;
    public byte[] data;

    public String srcMac;
    public String dstMac;
    public int etherType = -1;

    // ARP
    public int arpOp = -1;
    public String arpSenderIp;
    public String arpSenderMac;
    public String arpTargetIp;

    // IP
    public int ipVersion;
    public String srcIp;
    public String dstIp;
    public byte[] srcIpBytes;
    public byte[] dstIpBytes;
    public int protocol = -1;
    /** A non-first fragment: no transport header available (no reassembly is attempted). */
    public boolean fragment;

    // Transport
    public int srcPort = -1;
    public int dstPort = -1;
    public int tcpFlags;
    public long seq;
    public long ack;

    public int payloadOffset;
    public int payloadLength;

    public boolean isTcp() {
        return protocol == TCP && srcPort >= 0;
    }

    public boolean isUdp() {
        return protocol == UDP && srcPort >= 0;
    }

    public boolean has(int flag) {
        return (tcpFlags & flag) != 0;
    }

    /** "10.0.0.5:445" style endpoint label. */
    public String src() {
        return endpoint(srcIp, srcPort);
    }

    public String dst() {
        return endpoint(dstIp, dstPort);
    }

    public static String endpoint(String ip, int port) {
        if (ip == null) {
            return "?";
        }
        String h = ip.contains(":") ? "[" + ip + "]" : ip;
        return port >= 0 ? h + ":" + port : h;
    }
}
