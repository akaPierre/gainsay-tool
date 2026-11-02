package dev.gainsay.net.decode;

import dev.gainsay.net.capture.RawFrame;
import dev.gainsay.net.synth.Frames;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class DecoderTest {

    static DecodedPacket decode(byte[] frame) {
        return Decoder.decode(new RawFrame(Instant.EPOCH, RawFrame.LINKTYPE_ETHERNET, frame, frame.length), 1);
    }

    @Test
    void decodesEthernetIpv4Tcp() {
        byte[] f = Frames.ethernet("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800,
                Frames.ip("10.0.0.1", "10.0.0.2", 6, Frames.tcp(51000, 443, 7, 0, 0x02, new byte[0])));
        DecodedPacket p = decode(f);
        assertEquals("10.0.0.1", p.srcIp);
        assertEquals(443, p.dstPort);
        assertTrue(p.has(DecodedPacket.SYN));
        assertEquals("00:11:22:33:44:55", p.srcMac);
    }

    @Test
    void decodesVlanTaggedFrames() {
        byte[] inner = Frames.ip("10.0.0.1", "10.0.0.2", 17, Frames.udp(1, 53, new byte[]{9}));
        byte[] tagged = new byte[14 + 4 + inner.length];
        byte[] plain = Frames.ethernet("00:00:00:00:00:01", "00:00:00:00:00:02", 0x8100, new byte[0]);
        System.arraycopy(plain, 0, tagged, 0, 14);
        tagged[14] = 0;
        tagged[15] = 10;          // VLAN 10
        tagged[16] = 0x08;
        tagged[17] = 0x00;        // inner type IPv4
        System.arraycopy(inner, 0, tagged, 18, inner.length);
        DecodedPacket p = decode(tagged);
        assertEquals(53, p.dstPort);
        assertEquals(1, p.payloadLength);
    }

    @Test
    void decodesIpv6UdpWithCanonicalAddresses() {
        byte[] f = Frames.udpFrame("00:00:00:00:00:01", "fe80::215:5dff:fe01:205", 5355, "33:33:00:01:00:03", "ff02::1:3", 5355, new byte[12]);
        DecodedPacket p = decode(f);
        assertEquals(6, p.ipVersion);
        assertEquals("fe80::215:5dff:fe01:205", p.srcIp);
        assertEquals("ff02::1:3", p.dstIp);
    }

    @Test
    void decodesArp() {
        DecodedPacket p = decode(Frames.arp(2, "00:00:aa:00:00:99", "10.0.0.99", "00:00:aa:00:00:01", "10.0.0.1"));
        assertEquals(2, p.arpOp);
        assertEquals("10.0.0.99", p.arpSenderIp);
        assertEquals("00:00:aa:00:00:99", p.arpSenderMac);
    }

    @Test
    void marksNonFirstFragmentsWithoutTransport() {
        byte[] ip = Frames.ip("10.0.0.1", "10.0.0.2", 17, new byte[16]);
        ip[6] = 0x00;
        ip[7] = 0x10; // fragment offset 16*8
        DecodedPacket p = decode(Frames.ethernet("00:00:00:00:00:01", "00:00:00:00:00:02", 0x0800, ip));
        assertTrue(p.fragment);
        assertEquals(-1, p.srcPort);
    }

    @Test
    void truncatedFramesAreRejectedNotThrown() {
        byte[] f = Frames.ethernet("00:11:22:33:44:55", "66:77:88:99:aa:bb", 0x0800,
                Frames.ip("10.0.0.1", "10.0.0.2", 6, Frames.tcp(1, 2, 3, 4, 0x18, new byte[10])));
        for (int len = 0; len < 54; len++) {
            byte[] cut = java.util.Arrays.copyOf(f, len);
            assertDoesNotThrow(() -> decode(cut));
        }
        assertNull(decode(java.util.Arrays.copyOf(f, 30)));
    }

    @Test
    void randomBytesNeverEscapeTheDecoder() {
        Random r = new Random(42);
        for (int i = 0; i < 20_000; i++) {
            byte[] b = new byte[r.nextInt(200)];
            r.nextBytes(b);
            int link = new int[]{0, 1, 101, 113, 228, 229}[r.nextInt(6)];
            assertDoesNotThrow(() -> Decoder.decode(new RawFrame(Instant.EPOCH, link, b, b.length), 1));
        }
    }
}
