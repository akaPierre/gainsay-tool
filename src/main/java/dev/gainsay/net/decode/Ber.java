package dev.gainsay.net.decode;

import static dev.gainsay.net.decode.Bytes.u8;

/**
 * Minimal BER TLV reader for SNMP and LDAP. Supports definite lengths up to 4 bytes; indefinite
 * lengths are rejected (they never appear in SNMP/LDAP PDUs).
 */
public final class Ber {

    /** One TLV: tag byte, value offset and length, and the offset just past it. */
    public record Tlv(int tag, int valueOffset, int valueLength, int next) {
    }

    private Ber() {
    }

    public static Tlv read(byte[] b, int off, int end) {
        int tag = u8(b, off, end);
        int l0 = u8(b, off + 1, end);
        int p = off + 2;
        int len;
        if (l0 < 0x80) {
            len = l0;
        } else {
            int n = l0 & 0x7f;
            if (n == 0 || n > 4) {
                throw new Bytes.Malformed("unsupported BER length");
            }
            len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | u8(b, p + i, end);
            }
            p += n;
            if (len < 0) {
                throw new Bytes.Malformed("BER length overflow");
            }
        }
        return new Tlv(tag, p, len, p + len);
    }

    /** Value of a small INTEGER. */
    public static long integer(byte[] b, Tlv t, int end) {
        if (t.valueLength() < 1 || t.valueLength() > 8) {
            throw new Bytes.Malformed("bad INTEGER");
        }
        Bytes.need(b, t.valueOffset(), t.valueLength(), end);
        long v = b[t.valueOffset()];
        for (int i = 1; i < t.valueLength(); i++) {
            v = (v << 8) | (b[t.valueOffset() + i] & 0xff);
        }
        return v;
    }
}
