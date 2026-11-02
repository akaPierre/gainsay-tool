package dev.gainsay.net.capture;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure-Java reader for classic pcap (micro- and nanosecond, both byte orders) and pcapng
 * (SHB/IDB/EPB/SPB/OPB blocks, per-interface link type and timestamp resolution).
 *
 * <p>Written by hand rather than via pcap4j because pcap4j's offline mode still loads native libpcap,
 * and the test suite must run without it. All lengths read from the file are untrusted and bounded:
 * frames above {@link #MAX_FRAME} or blocks above {@link #MAX_BLOCK} end the read with an error.
 */
public final class PcapFileSource implements PacketSource {

    public static final int MAX_FRAME = 262_144;
    static final int MAX_BLOCK = 16 * 1024 * 1024;
    static final int MAX_INTERFACES = 1024;

    private final InputStream in;
    private final String name;
    private final boolean pcapng;
    private ByteOrder order;
    private boolean nanos;
    private int linkType;
    private final List<long[]> interfaces = new ArrayList<>(); // [linkType, ticksPerSecond]

    public PcapFileSource(Path file) throws IOException {
        this(new BufferedInputStream(Files.newInputStream(file), 1 << 16), "file " + file.getFileName());
    }

    public PcapFileSource(InputStream in, String name) throws IOException {
        this.in = in;
        this.name = name;
        byte[] magic = readFully(4);
        int be = ByteBuffer.wrap(magic).order(ByteOrder.BIG_ENDIAN).getInt();
        if (be == 0x0A0D0D0A) {
            pcapng = true;
            readSectionHeaderRest();
        } else {
            pcapng = false;
            switch (be) {
                case 0xA1B2C3D4 -> { order = ByteOrder.BIG_ENDIAN; nanos = false; }
                case 0xD4C3B2A1 -> { order = ByteOrder.LITTLE_ENDIAN; nanos = false; }
                case 0xA1B23C4D -> { order = ByteOrder.BIG_ENDIAN; nanos = true; }
                case 0x4D3CB2A1 -> { order = ByteOrder.LITTLE_ENDIAN; nanos = true; }
                default -> throw new IOException("not a pcap or pcapng file (magic " + String.format("%08x", be) + ")");
            }
            ByteBuffer h = ByteBuffer.wrap(readFully(20)).order(order);
            h.getShort(); // version major
            h.getShort(); // version minor
            h.getInt();   // thiszone
            h.getInt();   // sigfigs
            h.getInt();   // snaplen
            linkType = h.getInt() & 0x0FFFFFFF; // upper bits may carry FCS info
        }
    }

    @Override
    public RawFrame next() throws IOException {
        return pcapng ? nextNg() : nextClassic();
    }

    private RawFrame nextClassic() throws IOException {
        byte[] hdr = readOrEof(16);
        if (hdr == null) {
            return null;
        }
        ByteBuffer h = ByteBuffer.wrap(hdr).order(order);
        long sec = h.getInt() & 0xFFFFFFFFL;
        long frac = h.getInt() & 0xFFFFFFFFL;
        int incl = h.getInt();
        int orig = h.getInt();
        if (incl < 0 || incl > MAX_FRAME) {
            throw new IOException("corrupt pcap record (captured length " + incl + ")");
        }
        byte[] data = readFully(incl);
        Instant ts = Instant.ofEpochSecond(sec, nanos ? Math.min(frac, 999_999_999L) : Math.min(frac, 999_999L) * 1000);
        return new RawFrame(ts, linkType, data, orig);
    }

    private void readSectionHeaderRest() throws IOException {
        byte[] lenAndMagic = readFully(8);
        int bom = ByteBuffer.wrap(lenAndMagic, 4, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        if (bom == 0x1A2B3C4D) {
            order = ByteOrder.BIG_ENDIAN;
        } else if (bom == 0x4D3C2B1A) {
            order = ByteOrder.LITTLE_ENDIAN;
        } else {
            throw new IOException("corrupt pcapng section header");
        }
        int total = ByteBuffer.wrap(lenAndMagic, 0, 4).order(order).getInt();
        checkBlockLength(total);
        skip(total - 12); // version, section length, options, trailing length
        interfaces.clear();
    }

    private RawFrame nextNg() throws IOException {
        while (true) {
            byte[] th = readOrEof(4);
            if (th == null) {
                return null;
            }
            int type = ByteBuffer.wrap(th).order(order).getInt();
            if (type == 0x0A0D0D0A) {
                readSectionHeaderRest();
                continue;
            }
            int total = ByteBuffer.wrap(readFully(4)).order(order).getInt();
            checkBlockLength(total);
            ByteBuffer body = ByteBuffer.wrap(readFully(total - 8)).order(order); // includes trailing length
            switch (type) {
                case 1 -> readInterface(body, total);
                case 6 -> {
                    return enhancedPacket(body, total);
                }
                case 3 -> {
                    return simplePacket(body, total);
                }
                case 2 -> {
                    return obsoletePacket(body, total);
                }
                default -> {
                    // name resolution, statistics, custom blocks: not needed
                }
            }
        }
    }

    private void readInterface(ByteBuffer b, int total) {
        int lt = b.getShort() & 0xffff;
        b.getShort();
        b.getInt(); // snaplen
        long ticks = 1_000_000L;
        int optEnd = total - 12;
        while (b.position() + 4 <= optEnd) {
            int code = b.getShort() & 0xffff;
            int len = b.getShort() & 0xffff;
            if (code == 0 || b.position() + len > optEnd) {
                break;
            }
            if (code == 9 && len >= 1) { // if_tsresol
                int v = b.get(b.position()) & 0xff;
                int exp = v & 0x7f;
                if (exp <= 18) {
                    ticks = (v & 0x80) == 0 ? (long) Math.pow(10, exp) : 1L << Math.min(exp, 62);
                }
            }
            b.position(b.position() + ((len + 3) & ~3));
        }
        if (interfaces.size() < MAX_INTERFACES) {
            interfaces.add(new long[]{lt, ticks});
        }
    }

    private RawFrame enhancedPacket(ByteBuffer b, int total) throws IOException {
        int iface = b.getInt();
        long ts = ((b.getInt() & 0xFFFFFFFFL) << 32) | (b.getInt() & 0xFFFFFFFFL);
        int cap = b.getInt();
        int orig = b.getInt();
        return frame(b, iface, ts, cap, orig, total - 32);
    }

    private RawFrame simplePacket(ByteBuffer b, int total) throws IOException {
        int orig = b.getInt();
        int cap = Math.min(orig, total - 16);
        return frame(b, 0, -1, cap, orig, total - 16);
    }

    private RawFrame obsoletePacket(ByteBuffer b, int total) throws IOException {
        int iface = b.getShort() & 0xffff;
        b.getShort();
        long ts = ((b.getInt() & 0xFFFFFFFFL) << 32) | (b.getInt() & 0xFFFFFFFFL);
        int cap = b.getInt();
        int orig = b.getInt();
        return frame(b, iface, ts, cap, orig, total - 32);
    }

    private RawFrame frame(ByteBuffer b, int iface, long ts, int cap, int orig, int room) throws IOException {
        if (cap < 0 || cap > MAX_FRAME || cap > room) {
            throw new IOException("corrupt pcapng packet block (captured length " + cap + ")");
        }
        byte[] data = new byte[cap];
        b.get(data);
        long[] ifc = iface >= 0 && iface < interfaces.size() ? interfaces.get(iface) : new long[]{RawFrame.LINKTYPE_ETHERNET, 1_000_000L};
        Instant t;
        if (ts < 0) {
            t = Instant.EPOCH;
        } else {
            long perSec = ifc[1];
            long sec = Long.divideUnsigned(ts, perSec);
            long rem = Long.remainderUnsigned(ts, perSec);
            t = Instant.ofEpochSecond(sec, perSec >= 1_000_000_000L ? rem / (perSec / 1_000_000_000L) : rem * (1_000_000_000L / perSec));
        }
        return new RawFrame(t, (int) ifc[0], data, orig);
    }

    private static void checkBlockLength(int total) throws IOException {
        if (total < 12 || total > MAX_BLOCK || (total & 3) != 0) {
            throw new IOException("corrupt pcapng block length " + total);
        }
    }

    private byte[] readOrEof(int n) throws IOException {
        byte[] b = new byte[n];
        int r = in.readNBytes(b, 0, n);
        if (r == 0) {
            return null;
        }
        if (r < n) {
            return null; // truncated trailing record: treat as end of capture
        }
        return b;
    }

    private byte[] readFully(int n) throws IOException {
        byte[] b = new byte[n];
        if (in.readNBytes(b, 0, n) < n) {
            throw new EOFException("truncated capture file");
        }
        return b;
    }

    private void skip(long n) throws IOException {
        in.skipNBytes(n);
    }

    @Override
    public String describe() {
        return name;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
