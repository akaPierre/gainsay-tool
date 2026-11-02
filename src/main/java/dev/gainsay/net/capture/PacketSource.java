package dev.gainsay.net.capture;

import java.io.IOException;

/**
 * Where frames come from. The rest of the network module only sees this interface, so live capture
 * ({@link LiveCaptureSource}, the only class touching native libpcap/Npcap) and offline files
 * ({@link PcapFileSource}, pure Java) are interchangeable.
 */
public interface PacketSource extends AutoCloseable {

    /** Next frame, or null at end of capture (file end, duration elapsed). */
    RawFrame next() throws IOException;

    /** Human-readable origin for the report, e.g. "file capture.pcap" or "live eth1 (60 s)". */
    String describe();

    @Override
    void close() throws IOException;
}
