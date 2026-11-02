package dev.gainsay.net.decode;

import dev.gainsay.core.Addresses;
import dev.gainsay.net.capture.RawFrame;

import static dev.gainsay.net.decode.Bytes.u16;
import static dev.gainsay.net.decode.Bytes.u32;
import static dev.gainsay.net.decode.Bytes.u8;

/**
 * Link → network → transport decoding: Ethernet (with up to two 802.1Q/802.1ad tags), Linux cooked
 * capture, raw IP and BSD loopback; IPv4 and IPv6 (extension headers skipped); TCP, UDP and ARP.
 *
 * <p>Robustness contract: {@link #decode} never throws. Truncated or inconsistent frames return null
 * (counted as malformed by the caller). IP fragments other than the first are marked and carry no
 * transport header; Gainsay does not reassemble IP fragments.
 */
public final class Decoder {

    static final int ETH_IPV4 = 0x0800, ETH_ARP = 0x0806, ETH_IPV6 = 0x86DD, ETH_VLAN = 0x8100, ETH_QINQ = 0x88A8;
    static final int MAX_IPV6_EXT = 8;

    private Decoder() {
    }

    public static DecodedPacket decode(RawFrame f, long frameNo) {
        try {
            DecodedPacket p = new DecodedPacket();
            p.frame = frameNo;
            p.ts = f.timestamp();
            p.data = f.data();
            byte[] b = f.data();
            int lim = b.length;
            switch (f.linkType()) {
                case RawFrame.LINKTYPE_ETHERNET -> ethernet(p, b, lim);
                case RawFrame.LINKTYPE_LINUX_SLL -> {
                    int addrLen = u16(b, 4, lim);
                    if (addrLen == 6) {
                        p.srcMac = mac(b, 6, lim);
                    }
                    network(p, b, 16, lim, u16(b, 14, lim));
                }
                case RawFrame.LINKTYPE_RAW, RawFrame.LINKTYPE_IPV4, RawFrame.LINKTYPE_IPV6 -> {
                    int v = u8(b, 0, lim) >> 4;
                    network(p, b, 0, lim, v == 6 ? ETH_IPV6 : ETH_IPV4);
                }
                case RawFrame.LINKTYPE_NULL -> {
                    int family = (int) Bytes.u32le(b, 0, lim);
                    if (family > 0xffff) {
                        family = (int) u32(b, 0, lim);
                    }
                    network(p, b, 4, lim, family == 2 ? ETH_IPV4 : ETH_IPV6);
                }
                default -> {
                    return null;
                }
            }
            return p;
        } catch (Bytes.Malformed | ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    private static void ethernet(DecodedPacket p, byte[] b, int lim) {
        p.dstMac = mac(b, 0, lim);
        p.srcMac = mac(b, 6, lim);
        int off = 12;
        int type = u16(b, off, lim);
        for (int tags = 0; (type == ETH_VLAN || type == ETH_QINQ) && tags < 2; tags++) {
            off += 4;
            type = u16(b, off, lim);
        }
        network(p, b, off + 2, lim, type);
    }

    private static void network(DecodedPacket p, byte[] b, int off, int lim, int type) {
        p.etherType = type;
        switch (type) {
            case ETH_IPV4 -> ipv4(p, b, off, lim);
            case ETH_IPV6 -> ipv6(p, b, off, lim);
            case ETH_ARP -> arp(p, b, off, lim);
            default -> {
                // other link-layer protocols (LLDP, STP, ...) are not analysed
            }
        }
    }

    private static void arp(DecodedPacket p, byte[] b, int off, int lim) {
        // htype=1 (Ethernet), ptype=0x0800, hlen=6, plen=4
        if (u16(b, off, lim) != 1 || u16(b, off + 2, lim) != ETH_IPV4 || u8(b, off + 4, lim) != 6 || u8(b, off + 5, lim) != 4) {
            return;
        }
        p.arpOp = u16(b, off + 6, lim);
        p.arpSenderMac = mac(b, off + 8, lim);
        Bytes.need(b, off + 14, 4, lim);
        p.arpSenderIp = Addresses.format(b, off + 14, 4);
        Bytes.need(b, off + 24, 4, lim);
        p.arpTargetIp = Addresses.format(b, off + 24, 4);
    }

    private static void ipv4(DecodedPacket p, byte[] b, int off, int lim) {
        int vihl = u8(b, off, lim);
        if (vihl >> 4 != 4) {
            throw new Bytes.Malformed("not IPv4");
        }
        int ihl = (vihl & 0x0f) * 4;
        int total = u16(b, off + 2, lim);
        if (ihl < 20 || total < ihl) {
            throw new Bytes.Malformed("bad IPv4 lengths");
        }
        int fragField = u16(b, off + 6, lim);
        p.ipVersion = 4;
        p.protocol = u8(b, off + 9, lim);
        Bytes.need(b, off + 12, 8, lim);
        p.srcIpBytes = java.util.Arrays.copyOfRange(b, off + 12, off + 16);
        p.dstIpBytes = java.util.Arrays.copyOfRange(b, off + 16, off + 20);
        p.srcIp = Addresses.format(b, off + 12, 4);
        p.dstIp = Addresses.format(b, off + 16, 4);
        int end = Math.min(off + total, lim); // ignore Ethernet padding beyond the IP total length
        if ((fragField & 0x1FFF) != 0) {
            p.fragment = true;
            return;
        }
        transport(p, b, off + ihl, end);
    }

    private static void ipv6(DecodedPacket p, byte[] b, int off, int lim) {
        if (u8(b, off, lim) >> 4 != 6) {
            throw new Bytes.Malformed("not IPv6");
        }
        int payloadLen = u16(b, off + 4, lim);
        int next = u8(b, off + 6, lim);
        Bytes.need(b, off + 8, 32, lim);
        p.ipVersion = 6;
        p.srcIpBytes = java.util.Arrays.copyOfRange(b, off + 8, off + 24);
        p.dstIpBytes = java.util.Arrays.copyOfRange(b, off + 24, off + 40);
        p.srcIp = Addresses.format(b, off + 8, 16);
        p.dstIp = Addresses.format(b, off + 24, 16);
        int end = Math.min(off + 40 + payloadLen, lim);
        int cur = off + 40;
        for (int i = 0; i < MAX_IPV6_EXT; i++) {
            switch (next) {
                case 0, 43, 60 -> { // hop-by-hop, routing, destination options
                    int nh = u8(b, cur, end);
                    cur += (u8(b, cur + 1, end) + 1) * 8;
                    next = nh;
                }
                case 44 -> { // fragment
                    int nh = u8(b, cur, end);
                    int offField = u16(b, cur + 2, end);
                    if ((offField & 0xFFF8) != 0) {
                        p.protocol = nh;
                        p.fragment = true;
                        return;
                    }
                    next = nh;
                    cur += 8;
                }
                case 51 -> { // authentication header
                    int nh = u8(b, cur, end);
                    cur += (u8(b, cur + 1, end) + 2) * 4;
                    next = nh;
                }
                default -> {
                    p.protocol = next;
                    transport(p, b, cur, end);
                    return;
                }
            }
        }
        p.protocol = next; // too many extension headers: give up on transport
    }

    private static void transport(DecodedPacket p, byte[] b, int off, int end) {
        if (p.protocol == DecodedPacket.TCP) {
            p.srcPort = u16(b, off, end);
            p.dstPort = u16(b, off + 2, end);
            p.seq = u32(b, off + 4, end);
            p.ack = u32(b, off + 8, end);
            int dataOff = (u8(b, off + 12, end) >> 4) * 4;
            if (dataOff < 20) {
                throw new Bytes.Malformed("bad TCP header length");
            }
            p.tcpFlags = u8(b, off + 13, end);
            Bytes.need(b, off, dataOff, end);
            p.payloadOffset = off + dataOff;
            p.payloadLength = end - p.payloadOffset;
        } else if (p.protocol == DecodedPacket.UDP) {
            p.srcPort = u16(b, off, end);
            p.dstPort = u16(b, off + 2, end);
            int len = u16(b, off + 4, end);
            p.payloadOffset = off + 8;
            p.payloadLength = Math.max(0, Math.min(len - 8, end - p.payloadOffset));
        }
    }

    static String mac(byte[] b, int off, int lim) {
        Bytes.need(b, off, 6, lim);
        StringBuilder s = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                s.append(':');
            }
            s.append(Character.forDigit((b[off + i] >> 4) & 0xf, 16)).append(Character.forDigit(b[off + i] & 0xf, 16));
        }
        return s.toString();
    }
}
