package dev.gainsay.net.synth;

import dev.gainsay.net.capture.PcapFileSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * An in-memory synthetic capture: frames with timestamps, written as a classic little-endian
 * microsecond pcap. Tests build captures programmatically; nothing is downloaded.
 */
public final class Capture {

    record Frame(Instant ts, byte[] data) {
    }

    private final List<Frame> frames = new ArrayList<>();
    private Instant clock;

    public Capture(Instant start) {
        this.clock = start;
    }

    public Capture() {
        this(Instant.parse("2026-10-30T11:00:00Z"));
    }

    public Capture add(byte[] frame) {
        clock = clock.plusMillis(5);
        frames.add(new Frame(clock, frame));
        return this;
    }

    public TcpSession tcp(String clientMac, String clientIp, int clientPort, String serverMac, String serverIp, int serverPort) {
        return new TcpSession(this, clientMac, clientIp, clientPort, serverMac, serverIp, serverPort);
    }

    public byte[] toPcap() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(0xA1B2C3D4).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0).putInt(262144).putInt(1);
        o.writeBytes(h.array());
        for (Frame f : frames) {
            ByteBuffer r = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            r.putInt((int) f.ts().getEpochSecond()).putInt(f.ts().getNano() / 1000).putInt(f.data().length).putInt(f.data().length);
            o.writeBytes(r.array());
            o.writeBytes(f.data());
        }
        return o.toByteArray();
    }

    public Path write(Path file) throws IOException {
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, toPcap());
        return file;
    }

    public PcapFileSource source() throws IOException {
        return new PcapFileSource(new ByteArrayInputStream(toPcap()), "file synthetic.pcap");
    }

    public int size() {
        return frames.size();
    }
}
