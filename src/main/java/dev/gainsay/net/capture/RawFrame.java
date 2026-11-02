package dev.gainsay.net.capture;

import java.time.Instant;

/**
 * One captured frame as delivered by a {@link PacketSource}: link-layer type, timestamp and the
 * captured bytes (possibly truncated by the snap length; {@code originalLength} is the wire length).
 */
public record RawFrame(Instant timestamp, int linkType, byte[] data, int originalLength) {

    /** DLT/LINKTYPE values handled by the decoder. */
    public static final int LINKTYPE_NULL = 0;
    public static final int LINKTYPE_ETHERNET = 1;
    public static final int LINKTYPE_RAW = 101;
    public static final int LINKTYPE_LINUX_SLL = 113;
    public static final int LINKTYPE_IPV4 = 228;
    public static final int LINKTYPE_IPV6 = 229;
}
