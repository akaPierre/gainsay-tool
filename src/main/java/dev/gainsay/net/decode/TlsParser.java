package dev.gainsay.net.decode;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import static dev.gainsay.net.decode.Bytes.u16;
import static dev.gainsay.net.decode.Bytes.u24;
import static dev.gainsay.net.decode.Bytes.u8;

/**
 * Reads TLS handshake <em>metadata</em> from the start of one direction of a TCP stream: ClientHello
 * (offered versions, cipher suites, SNI), ServerHello (selected version and suite) and, for TLS ≤ 1.2,
 * the first certificate (still in clear before ChangeCipherSpec). Nothing is ever decrypted; parsing
 * stops at the first ChangeCipherSpec or application-data record.
 */
public final class TlsParser {

    public static final int SSL3 = 0x0300, TLS10 = 0x0301, TLS11 = 0x0302, TLS12 = 0x0303, TLS13 = 0x0304;
    static final int MAX_HANDSHAKE_BYTES = 64 * 1024;
    static final int MAX_RECORD = 18_432;

    private TlsParser() {
    }

    public record ClientHello(int legacyVersion, List<Integer> supportedVersions, List<Integer> cipherSuites, String sni, boolean sslv2) {

        /** Highest version offered (supported_versions if present, else legacy_version). */
        public int maxOffered() {
            return supportedVersions.isEmpty() ? legacyVersion : supportedVersions.stream().mapToInt(Integer::intValue).max().orElse(legacyVersion);
        }

        /** True if SSL 3.0 / TLS 1.0 / TLS 1.1 is among the offered versions. */
        public boolean offersLegacy() {
            if (sslv2) {
                return true;
            }
            if (supportedVersions.isEmpty()) {
                return legacyVersion <= TLS11; // without the extension, only legacy_version (and below) is known
            }
            return supportedVersions.stream().anyMatch(v -> v <= TLS11);
        }

        /** The client cannot do better than TLS 1.1. */
        public boolean legacyOnly() {
            return maxOffered() <= TLS11;
        }

        /** supported_versions present and every offered version is TLS 1.2 or newer. */
        public boolean modernOnly() {
            return !supportedVersions.isEmpty() && supportedVersions.stream().allMatch(v -> v >= TLS12);
        }
    }

    public record ServerHello(int legacyVersion, int selectedVersion, int cipherSuite) {
    }

    /** Everything found in the stream head. Fields are null when not (yet) present. */
    public record Handshake(boolean tls, ClientHello clientHello, ServerHello serverHello, byte[] firstCertificate, boolean alert) {
    }

    public static Handshake parse(byte[] b, int len) {
        int lim = Math.min(len, b.length);
        if (lim < 5) {
            return new Handshake(false, null, null, null, false);
        }
        int first = b[0] & 0xff;
        if ((first & 0x80) != 0 && lim >= 5 && (b[2] & 0xff) == 1) {
            // SSLv2-format ClientHello (2-byte length with high bit set, msg type 1, then version)
            int v = u16(b, 3, lim);
            return new Handshake(true, new ClientHello(v, List.of(), List.of(), null, true), null, null, false);
        }
        if (first != 22 && first != 21) {
            return new Handshake(false, null, null, null, false);
        }
        ByteArrayOutputStream hs = new ByteArrayOutputStream();
        boolean alert = false;
        int off = 0;
        try {
            while (off + 5 <= lim) {
                int type = u8(b, off, lim);
                int major = u8(b, off + 1, lim);
                int rlen = u16(b, off + 3, lim);
                if (type < 20 || type > 24 || major != 3 || rlen > MAX_RECORD) {
                    break;
                }
                int bodyEnd = Math.min(off + 5 + rlen, lim);
                if (type == 21) {
                    alert = true;
                } else if (type == 22 && hs.size() < MAX_HANDSHAKE_BYTES) {
                    hs.write(b, off + 5, Math.min(bodyEnd - off - 5, MAX_HANDSHAKE_BYTES - hs.size()));
                } else if (type == 20 || type == 23) {
                    break; // everything after this is encrypted
                }
                off += 5 + rlen;
            }
        } catch (Bytes.Malformed e) {
            // partial record at the end of the head: keep what we have
        }
        byte[] h = hs.toByteArray();
        ClientHello ch = null;
        ServerHello sh = null;
        byte[] cert = null;
        int hoff = 0;
        try {
            while (hoff + 4 <= h.length) {
                int type = h[hoff] & 0xff;
                int mlen = u24(h, hoff + 1, h.length);
                int body = hoff + 4;
                if (body + mlen > h.length) {
                    break; // incomplete message; more segments may complete it
                }
                switch (type) {
                    case 1 -> ch = clientHello(h, body, body + mlen);
                    case 2 -> sh = serverHello(h, body, body + mlen);
                    case 11 -> {
                        if (cert == null && (sh == null || sh.selectedVersion() <= TLS12)) {
                            cert = firstCert(h, body, body + mlen);
                        }
                    }
                    default -> {
                    }
                }
                hoff = body + mlen;
            }
        } catch (Bytes.Malformed e) {
            // malformed message: report what parsed cleanly
        }
        return new Handshake(true, ch, sh, cert, alert);
    }

    static ClientHello clientHello(byte[] h, int off, int end) {
        int legacy = u16(h, off, end);
        int p = off + 2 + 32;
        p += 1 + u8(h, p, end);                    // session id
        int csLen = u16(h, p, end);
        List<Integer> suites = new ArrayList<>();
        for (int i = 0; i + 1 < csLen && suites.size() < 256; i += 2) {
            int s = u16(h, p + 2 + i, end);
            if (!isGrease(s)) {
                suites.add(s);
            }
        }
        p += 2 + csLen;
        p += 1 + u8(h, p, end);                    // compression methods
        List<Integer> versions = new ArrayList<>();
        String sni = null;
        if (p + 2 <= end) {
            int extEnd = Math.min(end, p + 2 + u16(h, p, end));
            p += 2;
            while (p + 4 <= extEnd) {
                int et = u16(h, p, extEnd);
                int el = u16(h, p + 2, extEnd);
                int ed = p + 4;
                if (ed + el > extEnd) {
                    break;
                }
                if (et == 0 && el >= 5) {          // server_name
                    int nameLen = u16(h, ed + 3, ed + el);
                    if (u8(h, ed + 2, ed + el) == 0 && nameLen <= 255) {
                        Bytes.need(h, ed + 5, nameLen, ed + el);
                        sni = Bytes.ascii(h, ed + 5, nameLen);
                    }
                } else if (et == 43 && el >= 1) {  // supported_versions
                    int vl = u8(h, ed, ed + el);
                    for (int i = 0; i + 1 < vl && 1 + i + 2 <= el; i += 2) {
                        int v = u16(h, ed + 1 + i, ed + el);
                        if (!isGrease(v)) {
                            versions.add(v);
                        }
                    }
                }
                p = ed + el;
            }
        }
        return new ClientHello(legacy, versions, suites, sni, false);
    }

    static ServerHello serverHello(byte[] h, int off, int end) {
        int legacy = u16(h, off, end);
        int p = off + 2 + 32;
        p += 1 + u8(h, p, end);
        int suite = u16(h, p, end);
        p += 3;                                    // suite + compression method
        int selected = legacy;
        if (p + 2 <= end) {
            int extEnd = Math.min(end, p + 2 + u16(h, p, end));
            p += 2;
            while (p + 4 <= extEnd) {
                int et = u16(h, p, extEnd);
                int el = u16(h, p + 2, extEnd);
                if (et == 43 && el == 2) {
                    selected = u16(h, p + 4, extEnd);
                }
                p += 4 + el;
            }
        }
        return new ServerHello(legacy, selected, suite);
    }

    static byte[] firstCert(byte[] h, int off, int end) {
        int listLen = u24(h, off, end);
        if (listLen < 3) {
            return null;
        }
        int certLen = u24(h, off + 3, end);
        if (certLen <= 0 || certLen > 16_384) {
            return null;
        }
        Bytes.need(h, off + 6, certLen, end);
        return java.util.Arrays.copyOfRange(h, off + 6, off + 6 + certLen);
    }

    /** GREASE values (RFC 8701) like 0x0A0A are noise inserted by clients; ignore them. */
    static boolean isGrease(int v) {
        return (v & 0x0f0f) == 0x0a0a && ((v >> 8) == (v & 0xff));
    }

    public static String versionName(int v) {
        return switch (v) {
            case 0x0002 -> "SSL 2.0";
            case SSL3 -> "SSL 3.0";
            case TLS10 -> "TLS 1.0";
            case TLS11 -> "TLS 1.1";
            case TLS12 -> "TLS 1.2";
            case TLS13 -> "TLS 1.3";
            default -> String.format("0x%04x", v);
        };
    }
}
