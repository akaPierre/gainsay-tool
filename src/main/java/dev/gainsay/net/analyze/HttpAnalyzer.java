package dev.gainsay.net.analyze;

import dev.gainsay.core.Redactor;
import dev.gainsay.core.Status;
import dev.gainsay.net.decode.Bytes;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.HttpHead;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * NET-HTTP-001..003: cleartext HTTP, credentials in cleartext HTTP, cookies set over cleartext HTTP.
 * Only the first request and response of each connection are examined. Header values, parameter
 * values and cookie values are never recorded: evidence shows names and masked values only.
 */
public final class HttpAnalyzer implements Analyzer {

    /** WinRM over HTTP encrypts its SOAP body with SPNEGO; treating it as cleartext HTTP would be wrong. */
    static final int WINRM_HTTP = 5985;
    private static final Pattern SECRET_NAME = Pattern.compile(
            "(?i)^(pass|passwd|password|pwd|passphrase|secret|token|api[_-]?key|access[_-]?token|auth)$");

    @Override
    public List<String> checkIds() {
        return List.of("NET-HTTP-001", "NET-HTTP-002", "NET-HTTP-003");
    }

    @Override
    public void onStream(Flow f, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
        if (f.serverPort == WINRM_HTTP) {
            return;
        }
        if (toServer && !f.marked("http.req") && HttpHead.looksLikeRequest(head.bytes(), head.length())) {
            HttpHead h = HttpHead.parse(head.bytes(), head.length());
            if (!h.complete && head.length() < 4096) {
                return; // wait for the rest of the head
            }
            f.mark("http.req");
            f.mark("cleartext");
            f.classify("HTTP", true);
            String host = h.header("host");
            String filter = Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && http.request";
            ctx.finding("NET-HTTP-001", f.server(), Status.FAIL,
                    "Cleartext HTTP to " + (host == null ? f.server() : host + " (" + f.server() + ")") + ".",
                    ctx.packetEvidence(p, h.method() + " " + h.path() + (h.query().isEmpty() ? "" : "?…") + (host == null ? "" : "  Host: " + host),
                            filter), p.ts);
            credentials(f, h, head, p, ctx, filter);
        } else if (!toServer && !f.marked("http.resp") && HttpHead.looksLikeResponse(head.bytes(), head.length())) {
            HttpHead h = HttpHead.parse(head.bytes(), head.length());
            if (!h.complete && head.length() < 4096) {
                return;
            }
            f.mark("http.resp");
            ctx.relevant("NET-HTTP-003");
            List<String> cookies = new ArrayList<>();
            for (String c : h.all("set-cookie")) {
                int eq = c.indexOf('=');
                if (eq > 0) {
                    cookies.add(c.substring(0, eq).trim());
                }
            }
            if (!cookies.isEmpty()) {
                ctx.finding("NET-HTTP-003", f.server(), Status.FAIL,
                        "Cookie(s) " + String.join(", ", cookies) + " set over cleartext HTTP.",
                        ctx.packetEvidence(p, "Set-Cookie: " + h.all("set-cookie").get(0),
                                Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && http.set_cookie"), p.ts);
            }
        }
    }

    private void credentials(Flow f, HttpHead h, StreamHead head, DecodedPacket p, AnalysisContext ctx, String filter) {
        ctx.relevant("NET-HTTP-002");
        List<String> what = new ArrayList<>();
        String auth = h.header("authorization");
        if (auth != null) {
            String scheme = auth.split("\\s+", 2)[0];
            String s = scheme.toLowerCase(Locale.ROOT);
            if (s.equals("basic") || s.equals("bearer")) {
                what.add("Authorization: " + scheme + " " + Redactor.MASK);
            }
        }
        for (String name : paramNames(h.query())) {
            if (SECRET_NAME.matcher(name).matches()) {
                what.add("query parameter " + name + "=" + Redactor.MASK);
            }
        }
        String ctype = h.header("content-type");
        if (h.complete && ctype != null && ctype.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            String body = Bytes.ascii(head.bytes(), h.bodyOffset, Math.min(4096, head.length() - h.bodyOffset));
            for (String name : paramNames(body)) {
                if (SECRET_NAME.matcher(name).matches()) {
                    what.add("form field " + name + "=" + Redactor.MASK);
                }
            }
        }
        if (!what.isEmpty()) {
            ctx.finding("NET-HTTP-002", f.server(), Status.FAIL,
                    "Credentials sent in cleartext to " + f.server() + " by " + f.clientIp + ".",
                    ctx.packetEvidence(p, h.method() + " " + h.path() + " — " + String.join("; ", what), filter), p.ts);
        }
    }

    /** Parameter names of an application/x-www-form-urlencoded string (values discarded). */
    static List<String> paramNames(String qs) {
        List<String> names = new ArrayList<>();
        if (qs == null || qs.isEmpty()) {
            return names;
        }
        for (String pair : qs.split("&", 64)) {
            int eq = pair.indexOf('=');
            String n = (eq >= 0 ? pair.substring(0, eq) : pair).trim();
            if (!n.isEmpty() && n.length() <= 64) {
                names.add(n);
            }
        }
        return names;
    }
}
