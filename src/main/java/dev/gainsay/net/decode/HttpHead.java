package dev.gainsay.net.decode;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The first HTTP/1.x request or response head in a stream: start line plus headers (names
 * lower-cased), and the offset of the body. Bounded to {@link #MAX_HEAD} bytes and
 * {@link #MAX_HEADERS} headers; anything beyond is ignored.
 */
public final class HttpHead {

    static final int MAX_HEAD = 16 * 1024;
    static final int MAX_HEADERS = 100;
    static final List<String> METHODS = List.of("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "PROPFIND", "TRACE");

    public final String startLine;
    public final List<String[]> headers;
    public final int bodyOffset;
    public final boolean complete;

    private HttpHead(String startLine, List<String[]> headers, int bodyOffset, boolean complete) {
        this.startLine = startLine;
        this.headers = headers;
        this.bodyOffset = bodyOffset;
        this.complete = complete;
    }

    /** True if the bytes start like an HTTP request ("GET /", "POST /", …). CONNECT tunnels are excluded. */
    public static boolean looksLikeRequest(byte[] b, int len) {
        String start = Bytes.ascii(b, 0, Math.min(len, 10));
        for (String m : METHODS) {
            if (start.startsWith(m + " ")) {
                return true;
            }
        }
        return false;
    }

    public static boolean looksLikeResponse(byte[] b, int len) {
        return Bytes.ascii(b, 0, Math.min(len, 8)).startsWith("HTTP/1.");
    }

    public static HttpHead parse(byte[] b, int len) {
        int lim = Math.min(Math.min(len, b.length), MAX_HEAD);
        String text = Bytes.ascii(b, 0, lim);
        int end = text.indexOf("\r\n\r\n");
        boolean complete = end >= 0;
        String head = complete ? text.substring(0, end) : text;
        String[] lines = head.split("\r\n", MAX_HEADERS + 1);
        List<String[]> hs = new ArrayList<>();
        for (int i = 1; i < lines.length && hs.size() < MAX_HEADERS; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) {
                hs.add(new String[]{lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT), lines[i].substring(c + 1).trim()});
            }
        }
        return new HttpHead(lines.length > 0 ? lines[0] : "", hs, complete ? end + 4 : lim, complete);
    }

    public String header(String name) {
        for (String[] h : headers) {
            if (h[0].equals(name)) {
                return h[1];
            }
        }
        return null;
    }

    public List<String> all(String name) {
        List<String> out = new ArrayList<>();
        for (String[] h : headers) {
            if (h[0].equals(name)) {
                out.add(h[1]);
            }
        }
        return out;
    }

    public String method() {
        int sp = startLine.indexOf(' ');
        return sp > 0 ? startLine.substring(0, sp) : "";
    }

    /** Request target without the query string. */
    public String path() {
        String target = target();
        int q = target.indexOf('?');
        return q >= 0 ? target.substring(0, q) : target;
    }

    public String query() {
        String target = target();
        int q = target.indexOf('?');
        return q >= 0 ? target.substring(q + 1) : "";
    }

    private String target() {
        String[] parts = startLine.split(" ", 3);
        return parts.length >= 2 ? parts[1] : "";
    }
}
