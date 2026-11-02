package dev.gainsay.net.analyze;

import java.util.Arrays;

/**
 * The first bytes of one direction of a TCP connection, reassembled in order. Protocol handshakes
 * (TLS hellos, SMB negotiate, HTTP heads) live here; the rest of the stream is never kept.
 *
 * <p>In-order segments are appended; retransmissions are trimmed; a gap (missing segment) or the
 * per-head cap ends collection. Memory is charged to a shared {@link Budget}.
 */
public final class StreamHead {

    /** Shared byte budget across all heads, so a capture with many flows cannot exhaust memory. */
    public static final class Budget {
        private final long max;
        private long used;

        public Budget(long max) {
            this.max = max;
        }

        boolean take(int n) {
            if (used + n > max) {
                return false;
            }
            used += n;
            return true;
        }

        void give(int n) {
            used = Math.max(0, used - n);
        }

        public long used() {
            return used;
        }
    }

    private final int cap;
    private final Budget budget;
    private byte[] buf = new byte[0];
    private int len;
    private long nextSeq = -1;
    private boolean closed;

    public StreamHead(int cap, Budget budget) {
        this.cap = cap;
        this.budget = budget;
    }

    /** Sets the expected first sequence number (ISN + 1) when the SYN was seen. */
    void expect(long seq) {
        if (nextSeq < 0 && len == 0) {
            nextSeq = seq & 0xFFFFFFFFL;
        }
    }

    /** Appends a segment; returns true if new bytes were added. */
    boolean append(long seq, byte[] data, int off, int n) {
        if (closed || n <= 0) {
            return false;
        }
        seq &= 0xFFFFFFFFL;
        if (nextSeq < 0) {
            nextSeq = seq; // joined mid-stream (no SYN seen): start here
        }
        long delta = (seq - nextSeq) & 0xFFFFFFFFL;
        if (delta != 0) {
            if (delta > 0x7FFFFFFFL) { // segment starts before nextSeq: retransmission / overlap
                long overlap = (nextSeq - seq) & 0xFFFFFFFFL;
                if (overlap >= n) {
                    return false;
                }
                off += (int) overlap;
                n -= (int) overlap;
            } else {
                closed = true; // gap: later bytes would be misplaced
                return false;
            }
        }
        int take = Math.min(n, cap - len);
        if (take <= 0) {
            closed = true;
            return false;
        }
        if (len + take > buf.length) {
            int newSize = Math.min(cap, Math.max(len + take, buf.length * 2 + 256));
            if (!budget.take(newSize - buf.length)) {
                closed = true;
                return false;
            }
            buf = Arrays.copyOf(buf, newSize);
        }
        System.arraycopy(data, off, buf, len, take);
        len += take;
        nextSeq = (nextSeq + take) & 0xFFFFFFFFL;
        return true;
    }

    /** Frees the buffer (e.g. when the flow is evicted). */
    void release() {
        budget.give(buf.length);
        buf = new byte[0];
        len = 0;
        closed = true;
    }

    public byte[] bytes() {
        return buf;
    }

    public int length() {
        return len;
    }
}
