package dev.gainsay.scan;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Cidr;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Decides which targets the active check may touch. Rules (all enforced before any connection):
 * <ul>
 *   <li>Targets are IP literals or CIDRs only; host names are refused (no DNS, no ambiguity about what is hit).</li>
 *   <li>Every address must be private (RFC 1918, CGNAT), loopback or link-local, or be covered by an entry
 *       in the user-maintained allowlist file.</li>
 *   <li>At most {@link #MAX_HOSTS} addresses per run; larger ranges are refused, not truncated.</li>
 * </ul>
 */
public final class TargetPolicy {

    public static final int MAX_HOSTS = 1024;
    public static final String DEFAULT_ALLOWLIST = "allowed_targets.txt";

    /** Thrown when a run must not start; the message lists the reasons. */
    public static final class Refused extends Exception {
        public Refused(String msg) {
            super(msg);
        }
    }

    private final List<Cidr> allowlist;

    public TargetPolicy(List<Cidr> allowlist) {
        this.allowlist = List.copyOf(allowlist);
    }

    /** Loads the allowlist ("one IP or CIDR per line, # comments"); a missing file means an empty allowlist. */
    public static TargetPolicy load(Path allowlistFile) throws IOException {
        List<Cidr> out = new ArrayList<>();
        if (allowlistFile != null && Files.exists(allowlistFile)) {
            for (String line : Files.readAllLines(allowlistFile, StandardCharsets.UTF_8)) {
                String t = line.strip();
                if (!t.isEmpty() && !t.startsWith("#")) {
                    out.add(Cidr.parse(t));
                }
            }
        }
        return new TargetPolicy(out);
    }

    /** Parses a comma-separated target list, or a file of targets if {@code spec} names an existing file. */
    public static List<String> targetSpecs(String spec) throws IOException {
        Path p = Path.of(spec);
        List<String> raw = new ArrayList<>();
        if (!spec.contains(",") && Addresses.parse(spec) == null && Files.isRegularFile(p)) {
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                String t = line.strip();
                if (!t.isEmpty() && !t.startsWith("#")) {
                    raw.add(t);
                }
            }
        } else {
            for (String s : spec.split(",")) {
                if (!s.isBlank()) {
                    raw.add(s.strip());
                }
            }
        }
        return raw;
    }

    /** Expands and authorises targets, or refuses the whole run. */
    public List<byte[]> authorise(List<String> specs) throws Refused {
        List<String> problems = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        List<byte[]> out = new ArrayList<>();
        for (String s : specs) {
            Cidr c;
            try {
                c = Cidr.parse(s);
            } catch (IllegalArgumentException e) {
                problems.add("'" + s + "' is not an IP address or CIDR (host names are not accepted)");
                continue;
            }
            if (c.size() > MAX_HOSTS || out.size() + c.size() > MAX_HOSTS) {
                problems.add("'" + s + "' would exceed the limit of " + MAX_HOSTS + " addresses per run");
                continue;
            }
            for (byte[] a : expand(c)) {
                String text = Addresses.format(a, 0, a.length);
                if (!seen.add(text)) {
                    continue;
                }
                if (!allowed(a)) {
                    if (problems.size() < 20) {
                        problems.add(text + " is not a private/link-local address and is not in " + DEFAULT_ALLOWLIST);
                    }
                    continue;
                }
                out.add(a);
            }
        }
        if (!problems.isEmpty()) {
            throw new Refused("Refusing to scan:\n  - " + String.join("\n  - ", problems));
        }
        if (out.isEmpty()) {
            throw new Refused("Refusing to scan: no targets given");
        }
        return out;
    }

    boolean allowed(byte[] a) {
        if (Addresses.isPrivate(a)) {
            return true;
        }
        for (Cidr c : allowlist) {
            if (c.contains(a)) {
                return true;
            }
        }
        return false;
    }

    /** All addresses of a small prefix. For IPv4 /31 and wider, network and broadcast addresses are skipped. */
    static List<byte[]> expand(Cidr c) {
        List<byte[]> out = new ArrayList<>();
        long n = c.size();
        boolean skipEdges = c.network().length == 4 && n > 2;
        for (long i = 0; i < n; i++) {
            if (skipEdges && (i == 0 || i == n - 1)) {
                continue;
            }
            byte[] a = c.network().clone();
            long carry = i;
            for (int k = a.length - 1; k >= 0 && carry > 0; k--) {
                long v = (a[k] & 0xff) + (carry & 0xff);
                a[k] = (byte) v;
                carry = (carry >>> 8) + (v >> 8);
            }
            out.add(a);
        }
        return out;
    }
}
