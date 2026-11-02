package dev.gainsay.net.decode;

import static dev.gainsay.net.decode.Bytes.u16;
import static dev.gainsay.net.decode.Bytes.u8;

/**
 * Parses the first RDP exchange (MS-RDPBCGR 2.2.1.1 / 2.2.1.2): TPKT (version 3) + X.224 Connection
 * Request (0xE0) / Confirm (0xD0) carrying RDP_NEG_REQ / RDP_NEG_RSP / RDP_NEG_FAILURE.
 *
 * <p>Protocol bits: 0 = standard RDP security, 0x1 = TLS, 0x2 = CredSSP (NLA), 0x8 = CredSSP with
 * early user authorization (HYBRID_EX). The optional "Cookie: mstshash=&lt;user&gt;" line in the request
 * contains a user name and is skipped, never stored.
 */
public final class RdpParser {

    public static final int PROTOCOL_RDP = 0, PROTOCOL_SSL = 0x1, PROTOCOL_HYBRID = 0x2, PROTOCOL_HYBRID_EX = 0x8;
    public static final int HYBRID_REQUIRED_BY_SERVER = 0x05;

    /** requested/selected/failure are -1 when absent. */
    public record X224(boolean request, boolean confirm, long requestedProtocols, long selectedProtocol, long failureCode) {
        public boolean nla(long protocols) {
            return (protocols & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)) != 0;
        }
    }

    private RdpParser() {
    }

    public static X224 parse(byte[] b, int len) {
        int lim = Math.min(len, b.length);
        try {
            if (u8(b, 0, lim) != 3 || u8(b, 1, lim) != 0) {
                return null;
            }
            int tpktLen = u16(b, 2, lim);
            int end = Math.min(lim, tpktLen);
            int li = u8(b, 4, end);
            int code = u8(b, 5, end) & 0xF0;
            int p = 4 + 1 + 6;          // LI byte + fixed part (code, dst-ref, src-ref, class)
            int x224End = Math.min(end, 5 + li);
            if (code == 0xE0) {
                p = skipCookie(b, p, x224End);
                if (p + 8 <= x224End && u8(b, p, x224End) == 0x01) {
                    return new X224(true, false, Bytes.u32le(b, p + 4, x224End), -1, -1);
                }
                return new X224(true, false, PROTOCOL_RDP, -1, -1); // no negotiation = standard RDP security
            }
            if (code == 0xD0) {
                if (p + 8 <= x224End) {
                    int type = u8(b, p, x224End);
                    if (type == 0x02) {
                        return new X224(false, true, -1, Bytes.u32le(b, p + 4, x224End), -1);
                    }
                    if (type == 0x03) {
                        return new X224(false, true, -1, -1, Bytes.u32le(b, p + 4, x224End));
                    }
                }
                return new X224(false, true, -1, PROTOCOL_RDP, -1);
            }
            return null;
        } catch (Bytes.Malformed e) {
            return null;
        }
    }

    /** Skips "Cookie: ...\r\n" or a routing token terminated by CRLF. */
    private static int skipCookie(byte[] b, int p, int end) {
        if (p < end && (b[p] == 'C' || b[p] == 'c')) {
            for (int i = p; i + 1 < end; i++) {
                if (b[i] == '\r' && b[i + 1] == '\n') {
                    return i + 2;
                }
            }
            return end;
        }
        return p;
    }
}
