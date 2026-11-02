package dev.gainsay.net.capture;

import dev.gainsay.net.synth.Capture;
import dev.gainsay.net.synth.Frames;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PcapFileSourceTest {

    static byte[] frame() {
        return Frames.udpFrame("00:00:00:00:00:01", "10.0.0.1", 1000, "00:00:00:00:00:02", "10.0.0.2", 53, new byte[]{1, 2, 3});
    }

    @Test
    void readsClassicPcap() throws IOException {
        Capture c = new Capture().add(frame()).add(frame());
        try (PcapFileSource s = c.source()) {
            RawFrame f = s.next();
            assertEquals(RawFrame.LINKTYPE_ETHERNET, f.linkType());
            assertArrayEquals(frame(), f.data());
            assertNotNull(s.next());
            assertNull(s.next());
        }
    }

    @Test
    void readsBigEndianNanosecondPcap() throws IOException {
        ByteBuffer b = ByteBuffer.allocate(24 + 16 + 4).order(ByteOrder.BIG_ENDIAN);
        b.putInt(0xA1B23C4D).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0).putInt(65535).putInt(101);
        b.putInt(1_700_000_000).putInt(123_456_789).putInt(4).putInt(4).put(new byte[]{0x45, 0, 0, 4});
        try (PcapFileSource s = new PcapFileSource(new ByteArrayInputStream(b.array()), "t")) {
            RawFrame f = s.next();
            assertEquals(RawFrame.LINKTYPE_RAW, f.linkType());
            assertEquals(123_456_789, f.timestamp().getNano());
        }
    }

    @Test
    void readsPcapng() throws IOException {
        byte[] data = frame();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        // SHB
        o.writeBytes(le(0x0A0D0D0A, 28, 0x1A2B3C4D));
        o.writeBytes(new byte[]{1, 0, 0, 0});              // version 1.0
        o.writeBytes(new byte[]{-1, -1, -1, -1, -1, -1, -1, -1}); // section length -1
        o.writeBytes(le(28));
        // IDB: linktype 1, if_tsresol = 9 (nanoseconds)
        o.writeBytes(le(1, 32));
        o.writeBytes(new byte[]{1, 0, 0, 0});
        o.writeBytes(le(65535));
        o.writeBytes(new byte[]{9, 0, 1, 0, 9, 0, 0, 0});
        o.writeBytes(new byte[]{0, 0, 0, 0});              // opt_endofopt
        o.writeBytes(le(32));
        // EPB
        int padded = (data.length + 3) & ~3;
        int total = 32 + padded;
        long ts = 1_700_000_000_123_456_789L;
        o.writeBytes(le(6, total, 0, (int) (ts >>> 32), (int) ts, data.length, data.length));
        o.writeBytes(Arrays.copyOf(data, padded));
        o.writeBytes(le(total));
        try (PcapFileSource s = new PcapFileSource(new ByteArrayInputStream(o.toByteArray()), "ng")) {
            RawFrame f = s.next();
            assertArrayEquals(data, f.data());
            assertEquals(1_700_000_000L, f.timestamp().getEpochSecond());
            assertEquals(123_456_789, f.timestamp().getNano());
            assertNull(s.next());
        }
    }

    @Test
    void rejectsGarbageAndCorruptLengths() {
        assertThrows(IOException.class, () -> new PcapFileSource(new ByteArrayInputStream("hello world, not a pcap".getBytes()), "x"));
        byte[] good = new Capture().add(frame()).toPcap();
        ByteBuffer.wrap(good).order(ByteOrder.LITTLE_ENDIAN).putInt(24 + 8, 0x7fffffff); // absurd captured length
        assertThrows(IOException.class, () -> {
            try (PcapFileSource s = new PcapFileSource(new ByteArrayInputStream(good), "x")) {
                s.next();
            }
        });
    }

    @Test
    void truncatedTrailingRecordEndsCaptureQuietly() throws IOException {
        byte[] good = new Capture().add(frame()).add(frame()).toPcap();
        byte[] cut = Arrays.copyOf(good, good.length - 30);
        try (PcapFileSource s = new PcapFileSource(new ByteArrayInputStream(cut), "x")) {
            assertNotNull(s.next());
            assertThrows(IOException.class, s::next, "a record header claiming more bytes than remain is an error");
        }
    }

    static byte[] le(int... v) {
        ByteBuffer b = ByteBuffer.allocate(v.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int x : v) {
            b.putInt(x);
        }
        return b.array();
    }
}
