package dev.gainsay.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Last line of defence against secrets leaking into reports or logs.
 *
 * <p>Analyzers are expected to build evidence from metadata only, but every {@link Evidence} string
 * is still passed through {@link #sanitize(String)}: credentials in HTTP headers, cookie values,
 * password-like parameters and protocol login commands are replaced by {@code ****}, control bytes
 * are escaped and the result is truncated. All patterns are linear (no nested quantifiers) and the
 * input is bounded before matching, so hostile packet content cannot cause catastrophic backtracking.
 */
public final class Redactor {

    public static final String MASK = "****";
    public static final int MAX_EVIDENCE_CHARS = 400;
    private static final int MAX_INPUT_CHARS = 4096;

    private static final Pattern AUTH_HEADER =
            Pattern.compile("(?i)\\b((?:proxy-)?authorization)\\s*:\\s*([A-Za-z0-9_-]{1,20})\\s+[^\\r\\n;]{0,4096}");
    private static final Pattern COOKIE_HEADER =
            Pattern.compile("(?i)\\b(set-cookie|cookie)\\s*:\\s*([^\\r\\n]{0,4096})");
    private static final Pattern COOKIE_PAIR = Pattern.compile("([^=;\\s]{1,128})=([^;]{0,4096})");
    private static final Pattern SECRET_PARAM = Pattern.compile(
            "(?i)\\b(pass(?:word|wd)?|pwd|passphrase|token|secret|api[_-]?key|access[_-]?token|auth|session|session[_-]?id|phpsessid|jsessionid|community|creds?)=([^&\\s;\"']{0,4096})");
    private static final Pattern LOGIN_COMMAND =
            Pattern.compile("(?im)^(\\s{0,8}(?:PASS|AUTH\\s+(?:PLAIN|LOGIN)|LOGIN|\\S{1,16}\\s+LOGIN))\\s+[^\\r\\n]{0,4096}");

    private Redactor() {
    }

    /** Masks secrets, escapes control characters and truncates. Null-safe. */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        String s = input.length() > MAX_INPUT_CHARS ? input.substring(0, MAX_INPUT_CHARS) : input;
        s = AUTH_HEADER.matcher(s).replaceAll("$1: $2 " + MASK);
        s = redactCookies(s);
        s = SECRET_PARAM.matcher(s).replaceAll("$1=" + MASK);
        s = LOGIN_COMMAND.matcher(s).replaceAll("$1 " + MASK);
        s = escapeControls(s);
        if (s.length() > MAX_EVIDENCE_CHARS) {
            s = s.substring(0, MAX_EVIDENCE_CHARS) + "…[truncated]";
        }
        return s;
    }

    private static String redactCookies(String s) {
        Matcher m = COOKIE_HEADER.matcher(s);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String pairs = COOKIE_PAIR.matcher(m.group(2)).replaceAll(r -> {
                String name = r.group(1);
                // Cookie attributes are not secret; keep them so "missing Secure" stays visible.
                if (isCookieAttribute(name)) {
                    return Matcher.quoteReplacement(r.group());
                }
                return Matcher.quoteReplacement(name + "=" + MASK);
            });
            m.appendReplacement(out, Matcher.quoteReplacement(m.group(1) + ": " + pairs));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static boolean isCookieAttribute(String name) {
        String n = name.trim().toLowerCase();
        return n.equals("path") || n.equals("domain") || n.equals("expires") || n.equals("max-age")
                || n.equals("samesite");
    }

    private static String escapeControls(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n') {
                b.append("\\n");
            } else if (c == '\r') {
                b.append("\\r");
            } else if (c == '\t') {
                b.append(' ');
            } else if (c < 0x20 || c == 0x7f) {
                b.append(String.format("\\x%02x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** Renders bytes as printable ASCII with non-printables as '.', bounded. Used for packet proofs. */
    public static String printable(byte[] data, int off, int len, int max) {
        int n = Math.max(0, Math.min(len, Math.min(max, data.length - off)));
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            int c = data[off + i] & 0xff;
            b.append(c >= 0x20 && c < 0x7f ? (char) c : '.');
        }
        return b.toString();
    }

    /** Hex dump of a bounded byte range, e.g. {@code "ff fd 18"}. Only use for non-secret protocol fields. */
    public static String hex(byte[] data, int off, int len, int max) {
        int n = Math.max(0, Math.min(len, Math.min(max, data.length - off)));
        StringBuilder b = new StringBuilder(n * 3);
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                b.append(' ');
            }
            b.append(String.format("%02x", data[off + i] & 0xff));
        }
        return b.toString();
    }
}
