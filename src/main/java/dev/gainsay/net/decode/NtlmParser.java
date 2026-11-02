package dev.gainsay.net.decode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static dev.gainsay.net.decode.Bytes.u16le;

/**
 * Finds NTLMSSP AUTHENTICATE (type 3) messages (MS-NLMP 2.2.1.3) in a stream head, either raw (inside
 * SMB/SPNEGO blobs) or base64-encoded in HTTP {@code Authorization: NTLM|Negotiate} headers, and
 * reports only the <em>lengths</em> of the LM and NT challenge responses. A 24-byte NT response means
 * NTLMv1; NTLMv2 responses are longer. User, domain and the responses themselves are never extracted.
 */
public final class NtlmParser {

    static final byte[] SIGNATURE = "NTLMSSP\0".getBytes(StandardCharsets.US_ASCII);
    static final byte[] B64_SIGNATURE = "TlRMTVNTUA".getBytes(StandardCharsets.US_ASCII);
    static final int MAX_MESSAGES = 4;

    public record Authenticate(int lmResponseLength, int ntResponseLength) {
        public boolean ntlmV1() {
            return ntResponseLength == 24;
        }
    }

    private NtlmParser() {
    }

    public static List<Authenticate> find(byte[] b, int len) {
        List<Authenticate> out = new ArrayList<>();
        int lim = Math.min(len, b.length);
        int i = 0;
        while (out.size() < MAX_MESSAGES && (i = Bytes.indexOf(b, i, lim, SIGNATURE)) >= 0) {
            Authenticate a = authenticate(b, i, lim);
            if (a != null) {
                out.add(a);
            }
            i += SIGNATURE.length;
        }
        i = 0;
        while (out.size() < MAX_MESSAGES && (i = Bytes.indexOf(b, i, lim, B64_SIGNATURE)) >= 0) {
            int j = i;
            while (j < lim && j - i < 4096 && isB64(b[j])) {
                j++;
            }
            try {
                byte[] raw = Base64.getDecoder().decode(new String(b, i, j - i, StandardCharsets.US_ASCII));
                Authenticate a = authenticate(raw, 0, raw.length);
                if (a != null) {
                    out.add(a);
                }
            } catch (IllegalArgumentException e) {
                // not valid base64 after all
            }
            i = j;
        }
        return out;
    }

    static Authenticate authenticate(byte[] b, int off, int lim) {
        try {
            if (Bytes.u32le(b, off + 8, lim) != 3) {
                return null;
            }
            int lm = u16le(b, off + 12, lim);
            int nt = u16le(b, off + 20, lim);
            return new Authenticate(lm, nt);
        } catch (Bytes.Malformed e) {
            return null;
        }
    }

    private static boolean isB64(byte c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    }
}
