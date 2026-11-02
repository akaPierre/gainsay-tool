package dev.gainsay.core;

import java.util.Locale;

/**
 * Pure, allocation-light IP address helpers. Never performs DNS: only numeric literals are parsed.
 * IPv6 is rendered in RFC 5952 canonical form so that addresses from packets and from Windows
 * ({@code Get-NetIPAddress}) compare equal.
 */
public final class Addresses {

    private Addresses() {
    }

    public static String format(byte[] b, int off, int len) {
        if (len == 4) {
            return (b[off] & 0xff) + "." + (b[off + 1] & 0xff) + "." + (b[off + 2] & 0xff) + "." + (b[off + 3] & 0xff);
        }
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) {
            g[i] = ((b[off + 2 * i] & 0xff) << 8) | (b[off + 2 * i + 1] & 0xff);
        }
        return formatV6(g);
    }

    static String formatV6(int[] g) {
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (g[i] == 0) {
                int j = i;
                while (j < 8 && g[j] == 0) {
                    j++;
                }
                if (j - i > bestLen && j - i >= 2) {
                    bestStart = i;
                    bestLen = j - i;
                }
                i = j;
            } else {
                i++;
            }
        }
        StringBuilder s = new StringBuilder(39);
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                s.append("::");
                i += bestLen - 1;
                continue;
            }
            if (s.length() > 0 && s.charAt(s.length() - 1) != ':') {
                s.append(':');
            }
            s.append(Integer.toHexString(g[i]));
        }
        return s.toString();
    }

    /** Parses an IPv4 or IPv6 literal (zone index stripped) into bytes, or returns null. */
    public static byte[] parse(String text) {
        if (text == null) {
            return null;
        }
        String s = text.trim();
        int pct = s.indexOf('%');
        if (pct >= 0) {
            s = s.substring(0, pct);
        }
        if (s.contains(":")) {
            return parseV6(s);
        }
        return parseV4(s);
    }

    static byte[] parseV4(String s) {
        String[] p = s.split("\\.", -1);
        if (p.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (p[i].isEmpty() || p[i].length() > 3 || !p[i].chars().allMatch(Character::isDigit)) {
                return null;
            }
            int v = Integer.parseInt(p[i]);
            if (v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    static byte[] parseV6(String s) {
        if (s.length() > 45) {
            return null;
        }
        String lower = s.toLowerCase(Locale.ROOT);
        byte[] tail4 = null;
        int lastColon = lower.lastIndexOf(':');
        if (lower.indexOf('.', lastColon) > 0) { // embedded IPv4 (::ffff:1.2.3.4)
            tail4 = parseV4(lower.substring(lastColon + 1));
            if (tail4 == null) {
                return null;
            }
            lower = lower.substring(0, lastColon + 1) + "0:0";
        }
        int dbl = lower.indexOf("::");
        if (dbl != lower.lastIndexOf("::")) {
            return null;
        }
        String[] head, tail;
        if (dbl >= 0) {
            String h = lower.substring(0, dbl);
            String t = lower.substring(dbl + 2);
            head = h.isEmpty() ? new String[0] : h.split(":", -1);
            tail = t.isEmpty() ? new String[0] : t.split(":", -1);
        } else {
            head = lower.split(":", -1);
            tail = new String[0];
            if (head.length != 8) {
                return null;
            }
        }
        if (head.length + tail.length > (dbl >= 0 ? 7 : 8)) {
            return null;
        }
        int[] g = new int[8];
        for (int i = 0; i < head.length; i++) {
            Integer v = hexGroup(head[i]);
            if (v == null) return null;
            g[i] = v;
        }
        for (int i = 0; i < tail.length; i++) {
            Integer v = hexGroup(tail[i]);
            if (v == null) return null;
            g[8 - tail.length + i] = v;
        }
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[2 * i] = (byte) (g[i] >> 8);
            out[2 * i + 1] = (byte) g[i];
        }
        if (tail4 != null) {
            System.arraycopy(tail4, 0, out, 12, 4);
        }
        return out;
    }

    private static Integer hexGroup(String s) {
        if (s.isEmpty() || s.length() > 4) {
            return null;
        }
        int v = 0;
        for (char c : s.toCharArray()) {
            int d = Character.digit(c, 16);
            if (d < 0) {
                return null;
            }
            v = (v << 4) | d;
        }
        return v;
    }

    /** Canonical text form, or the trimmed lower-case input if it is not a literal. */
    public static String canonical(String text) {
        byte[] b = parse(text);
        return b == null ? (text == null ? "" : text.trim().toLowerCase(Locale.ROOT)) : format(b, 0, b.length);
    }

    /** RFC 1918, loopback, link-local, CGNAT (100.64/10), IPv6 ULA (fc00::/7), link-local (fe80::/10), loopback. */
    public static boolean isPrivate(byte[] a) {
        if (a == null) {
            return false;
        }
        if (a.length == 4) {
            int b0 = a[0] & 0xff, b1 = a[1] & 0xff;
            return b0 == 10 || b0 == 127 || (b0 == 172 && b1 >= 16 && b1 <= 31) || (b0 == 192 && b1 == 168)
                    || (b0 == 169 && b1 == 254) || (b0 == 100 && b1 >= 64 && b1 <= 127);
        }
        boolean loopback = true;
        for (int i = 0; i < 15; i++) {
            if (a[i] != 0) {
                loopback = false;
                break;
            }
        }
        if (loopback && a[15] == 1) {
            return true;
        }
        int b0 = a[0] & 0xff, b1 = a[1] & 0xff;
        return (b0 & 0xfe) == 0xfc || (b0 == 0xfe && (b1 & 0xc0) == 0x80);
    }

    public static boolean isPrivate(String ip) {
        return isPrivate(parse(ip));
    }

    /** Multicast or broadcast (not a unicast host). */
    public static boolean isGroup(byte[] a) {
        if (a == null) {
            return false;
        }
        if (a.length == 4) {
            int b0 = a[0] & 0xff;
            return (b0 >= 224 && b0 <= 239) || ((a[0] & a[1] & a[2] & a[3]) == (byte) 0xff);
        }
        return (a[0] & 0xff) == 0xff;
    }
}
