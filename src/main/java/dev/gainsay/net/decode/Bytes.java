package dev.gainsay.net.decode;

/**
 * Bounds-checked reads over untrusted packet bytes. Every read either returns a value inside
 * {@code [off, limit)} or throws {@link Malformed}, which decoders and parsers catch at their boundary.
 */
public final class Bytes {

    /** Thrown for truncated or inconsistent input; never escapes the capture loop. */
    public static final class Malformed extends RuntimeException {
        public Malformed(String msg) {
            super(msg, null, false, false);
        }
    }

    private Bytes() {
    }

    public static void need(byte[] b, int off, int n, int limit) {
        if (off < 0 || n < 0 || off + n > Math.min(limit, b.length)) {
            throw new Malformed("need " + n + " bytes at " + off);
        }
    }

    public static int u8(byte[] b, int off, int limit) {
        need(b, off, 1, limit);
        return b[off] & 0xff;
    }

    public static int u16(byte[] b, int off, int limit) {
        need(b, off, 2, limit);
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    public static int u16le(byte[] b, int off, int limit) {
        need(b, off, 2, limit);
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    public static int u24(byte[] b, int off, int limit) {
        need(b, off, 3, limit);
        return ((b[off] & 0xff) << 16) | ((b[off + 1] & 0xff) << 8) | (b[off + 2] & 0xff);
    }

    public static long u32(byte[] b, int off, int limit) {
        need(b, off, 4, limit);
        return ((long) (b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    public static long u32le(byte[] b, int off, int limit) {
        need(b, off, 4, limit);
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8) | ((b[off + 2] & 0xff) << 16) | ((long) (b[off + 3] & 0xff) << 24);
    }

    /** True if {@code pattern} occurs at {@code off}. */
    public static boolean startsWith(byte[] b, int off, int limit, byte[] pattern) {
        if (off < 0 || off + pattern.length > Math.min(limit, b.length)) {
            return false;
        }
        for (int i = 0; i < pattern.length; i++) {
            if (b[off + i] != pattern[i]) {
                return false;
            }
        }
        return true;
    }

    /** Index of {@code pattern} in {@code [from, limit)}, or -1. Naive search over bounded input. */
    public static int indexOf(byte[] b, int from, int limit, byte[] pattern) {
        int end = Math.min(limit, b.length) - pattern.length;
        for (int i = Math.max(0, from); i <= end; i++) {
            if (startsWith(b, i, limit, pattern)) {
                return i;
            }
        }
        return -1;
    }

    /** ASCII view of a bounded range (non-printables become '.'), for text protocols. */
    public static String ascii(byte[] b, int off, int len) {
        int n = Math.max(0, Math.min(len, b.length - off));
        char[] c = new char[n];
        for (int i = 0; i < n; i++) {
            int v = b[off + i] & 0xff;
            c[i] = (v >= 0x20 && v < 0x7f) || v == '\r' || v == '\n' || v == '\t' ? (char) v : '.';
        }
        return new String(c);
    }
}
