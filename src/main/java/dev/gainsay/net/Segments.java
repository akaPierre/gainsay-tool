package dev.gainsay.net;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Cidr;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Maps addresses to named network segments so findings can say which boundary a flow crosses.
 * A segments file has one line per segment: {@code name CIDR [CIDR ...]} ('#' for comments).
 * Without a file, private IPv4 addresses are grouped by /24 and IPv6 by /64; everything else is "public".
 */
public final class Segments {

    record Named(String name, Cidr cidr) {
    }

    private final List<Named> named;
    private final String source;

    private Segments(List<Named> named, String source) {
        this.named = named;
        this.source = source;
    }

    public static Segments defaults() {
        return new Segments(List.of(), "default (/24 per private IPv4 network, /64 per IPv6 network)");
    }

    public static Segments load(Path file) throws IOException {
        List<Named> out = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String t = line.strip();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            String[] parts = t.split("\\s+");
            if (parts.length < 2) {
                throw new IOException("segments file: expected 'name CIDR...' but got: " + t);
            }
            for (int i = 1; i < parts.length; i++) {
                out.add(new Named(parts[0], Cidr.parse(parts[i])));
            }
            if (out.size() > 10_000) {
                throw new IOException("segments file too large");
            }
        }
        return new Segments(out, "file " + file.getFileName());
    }

    /** Segments from a name → CIDR list map (as in gainsay.json). */
    public static Segments of(java.util.Map<String, List<String>> map, String source) {
        List<Named> out = new ArrayList<>();
        map.forEach((name, cidrs) -> cidrs.forEach(c -> out.add(new Named(name, Cidr.parse(c)))));
        return out.isEmpty() ? defaults() : new Segments(out, source);
    }

    public String of(String ip) {
        byte[] a = Addresses.parse(ip);
        if (a == null) {
            return "unknown";
        }
        Named best = null;
        for (Named n : named) {
            if (n.cidr().contains(a) && (best == null || n.cidr().prefix() > best.cidr().prefix())) {
                best = n;
            }
        }
        if (best != null) {
            return best.name();
        }
        if (Addresses.isGroup(a)) {
            return "multicast/broadcast";
        }
        if (!Addresses.isPrivate(a)) {
            return "public";
        }
        if (a.length == 4) {
            return (a[0] & 0xff) + "." + (a[1] & 0xff) + "." + (a[2] & 0xff) + ".0/24";
        }
        byte[] p = new byte[16];
        System.arraycopy(a, 0, p, 0, 8);
        return Addresses.format(p, 0, 16) + "/64";
    }

    public String source() {
        return source;
    }
}
