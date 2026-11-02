package dev.gainsay.net.decode;

import java.util.ArrayList;
import java.util.List;

import static dev.gainsay.net.decode.Bytes.u16le;
import static dev.gainsay.net.decode.Bytes.u24;
import static dev.gainsay.net.decode.Bytes.u8;

/**
 * Parses SMB NEGOTIATE exchanges from a TCP stream head (port 445 direct, or 139 via NetBIOS session
 * service; both frame messages with a 4-byte header: type 0x00 + 24-bit length).
 *
 * <ul>
 *   <li>SMB1 header: {@code FF 'S' 'M' 'B'}, command at +4 (0x72 = NEGOTIATE), flags at +9 (0x80 = reply).
 *       Request: WordCount (0), ByteCount, then dialects as {@code 0x02 "name" 0x00}. Response: WordCount,
 *       DialectIndex (0xFFFF = none acceptable), SecurityMode (0x08 = signatures required).</li>
 *   <li>SMB2 header: {@code FE 'S' 'M' 'B'}, command at +12 (0 = NEGOTIATE), flags at +16
 *       (0x1 = response). Response body at +64: StructureSize, SecurityMode (0x02 = signing required),
 *       DialectRevision.</li>
 * </ul>
 */
public final class SmbParser {

    public enum Kind { SMB1_NEGOTIATE_REQUEST, SMB1_NEGOTIATE_RESPONSE, SMB2_NEGOTIATE_REQUEST, SMB2_NEGOTIATE_RESPONSE, OTHER }

    /**
     * @param dialects     SMB1 request: offered dialect strings
     * @param dialectIndex SMB1 response: chosen index (0xFFFF = refused)
     * @param securityMode response security mode, -1 if absent
     * @param dialect      SMB2 response: DialectRevision (0x02FF = wildcard, more negotiation follows)
     */
    public record Message(Kind kind, List<String> dialects, int dialectIndex, int securityMode, int dialect) {
    }

    static final int MAX_MESSAGES = 8;
    static final int MAX_DIALECTS = 32;

    private SmbParser() {
    }

    public static List<Message> parse(byte[] b, int len) {
        List<Message> out = new ArrayList<>();
        int lim = Math.min(len, b.length);
        int off = 0;
        try {
            while (off + 4 <= lim && out.size() < MAX_MESSAGES) {
                int type = u8(b, off, lim);
                int mlen = u24(b, off + 1, lim);
                if (type == 0x00) {
                    if (off + 4 + mlen > lim) {
                        if (off + 4 + 68 <= lim) {
                            out.add(message(b, off + 4, lim)); // enough of a long message to read its header
                        }
                        break;
                    }
                    out.add(message(b, off + 4, off + 4 + mlen));
                } else if (type < 0x81 || type > 0x85) {
                    break; // not NetBIOS session framing: not SMB
                }
                off += 4 + mlen;
            }
        } catch (Bytes.Malformed e) {
            // truncated: return what parsed
        }
        return out;
    }

    static Message message(byte[] b, int off, int end) {
        int magic0 = u8(b, off, end);
        if (magic0 == 0xFF && u8(b, off + 1, end) == 'S' && u8(b, off + 2, end) == 'M' && u8(b, off + 3, end) == 'B') {
            int cmd = u8(b, off + 4, end);
            boolean reply = (u8(b, off + 9, end) & 0x80) != 0;
            if (cmd != 0x72) {
                return other();
            }
            int p = off + 32;
            int wc = u8(b, p, end);
            if (!reply) {
                int bc = u16le(b, p + 1 + 2 * wc, end);
                int q = p + 3 + 2 * wc;
                int qend = Math.min(end, q + bc);
                List<String> dialects = new ArrayList<>();
                while (q < qend && dialects.size() < MAX_DIALECTS) {
                    if (b[q] != 0x02) {
                        break;
                    }
                    int s = q + 1;
                    int z = s;
                    while (z < qend && b[z] != 0 && z - s < 64) {
                        z++;
                    }
                    dialects.add(Bytes.ascii(b, s, z - s));
                    q = z + 1;
                }
                return new Message(Kind.SMB1_NEGOTIATE_REQUEST, dialects, -1, -1, -1);
            }
            int idx = wc >= 1 ? u16le(b, p + 1, end) : 0xFFFF;
            int sec = wc >= 17 ? u8(b, p + 3, end) : -1;
            return new Message(Kind.SMB1_NEGOTIATE_RESPONSE, List.of(), idx, sec, -1);
        }
        if (magic0 == 0xFE && u8(b, off + 1, end) == 'S' && u8(b, off + 2, end) == 'M' && u8(b, off + 3, end) == 'B') {
            int cmd = u16le(b, off + 12, end);
            boolean response = (u8(b, off + 16, end) & 0x01) != 0;
            if (cmd != 0) {
                return other();
            }
            if (!response) {
                return new Message(Kind.SMB2_NEGOTIATE_REQUEST, List.of(), -1, -1, -1);
            }
            int body = off + 64;
            int sec = u16le(b, body + 2, end);
            int dialect = u16le(b, body + 4, end);
            return new Message(Kind.SMB2_NEGOTIATE_RESPONSE, List.of(), -1, sec, dialect);
        }
        return other();
    }

    private static Message other() {
        return new Message(Kind.OTHER, List.of(), -1, -1, -1);
    }

    /** Dialect strings that mean SMB1 (CIFS) and its LAN Manager ancestors. */
    public static boolean isSmb1Dialect(String d) {
        return !d.startsWith("SMB 2.");
    }

    public static String smb2DialectName(int d) {
        return switch (d) {
            case 0x0202 -> "SMB 2.0.2";
            case 0x0210 -> "SMB 2.1";
            case 0x0300 -> "SMB 3.0";
            case 0x0302 -> "SMB 3.0.2";
            case 0x0311 -> "SMB 3.1.1";
            case 0x02FF -> "SMB 2.???";
            default -> String.format("0x%04x", d);
        };
    }
}
