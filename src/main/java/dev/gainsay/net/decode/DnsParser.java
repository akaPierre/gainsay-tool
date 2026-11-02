package dev.gainsay.net.decode;

import static dev.gainsay.net.decode.Bytes.u16;
import static dev.gainsay.net.decode.Bytes.u8;

/**
 * DNS-format header and first question name, shared by DNS (53), LLMNR (5355), mDNS (5353) and
 * NetBIOS Name Service (137, which uses DNS framing with "first-level encoded" names).
 */
public final class DnsParser {

    public record Header(int id, boolean response, int opcode, int rcode, int questions, String firstName) {
    }

    static final int MAX_NAME = 255;

    private DnsParser() {
    }

    public static Header parse(byte[] b, int off, int len) {
        int end = Math.min(off + len, b.length);
        try {
            int id = u16(b, off, end);
            int flags = u16(b, off + 2, end);
            int qd = u16(b, off + 4, end);
            String name = qd > 0 ? name(b, off + 12, end) : null;
            return new Header(id, (flags & 0x8000) != 0, (flags >> 11) & 0xF, flags & 0xF, qd, name);
        } catch (Bytes.Malformed e) {
            return null;
        }
    }

    /** Reads an uncompressed name (questions never need compression); stops at a pointer. */
    static String name(byte[] b, int p, int end) {
        StringBuilder s = new StringBuilder();
        for (int labels = 0; labels < 128; labels++) {
            int l = u8(b, p, end);
            if (l == 0 || (l & 0xC0) != 0) {
                break;
            }
            Bytes.need(b, p + 1, l, end);
            if (s.length() > 0) {
                s.append('.');
            }
            s.append(Bytes.ascii(b, p + 1, l));
            if (s.length() > MAX_NAME) {
                break;
            }
            p += 1 + l;
        }
        return s.toString();
    }

    /** NetBIOS first-level decoding: 32 chars 'A'..'P' → 16 bytes; trailing spaces and the suffix byte removed. */
    public static String netbiosName(String encoded) {
        if (encoded == null || encoded.length() < 32) {
            return encoded;
        }
        StringBuilder s = new StringBuilder(16);
        for (int i = 0; i + 1 < 30; i += 2) { // first 15 characters; the 16th is the service suffix
            int hi = encoded.charAt(i) - 'A';
            int lo = encoded.charAt(i + 1) - 'A';
            if (hi < 0 || hi > 15 || lo < 0 || lo > 15) {
                return encoded;
            }
            s.append((char) ((hi << 4) | lo));
        }
        return s.toString().trim();
    }
}
