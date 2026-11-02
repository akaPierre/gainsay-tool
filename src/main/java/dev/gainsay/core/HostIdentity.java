package dev.gainsay.core;

import java.util.List;
import java.util.Locale;

/**
 * The addresses under which an audited host may appear on the wire. This is what lets the tribunal
 * tie a host's testimony (its settings) to network evidence (packets with these IPs or MACs).
 */
public record HostIdentity(String hostname, List<String> ips, List<String> macs) {

    public HostIdentity {
        hostname = hostname == null ? "" : hostname;
        ips = ips == null ? List.of() : ips.stream().map(HostIdentity::normalizeIp).filter(s -> !s.isEmpty()).distinct().toList();
        macs = macs == null ? List.of() : macs.stream().map(HostIdentity::normalizeMac).filter(s -> !s.isEmpty()).distinct().toList();
    }

    /** Label used in reports: hostname if known, else first IP. */
    public String label() {
        if (!hostname.isEmpty()) {
            return hostname;
        }
        return ips.isEmpty() ? "(unknown host)" : ips.get(0);
    }

    /** Returns "ip", "mac" or null depending on how (or whether) the address belongs to this host. */
    public String matchMethod(String ip, String mac) {
        if (ip != null && ips.contains(normalizeIp(ip))) {
            return "ip";
        }
        if (mac != null && macs.contains(normalizeMac(mac))) {
            return "mac";
        }
        return null;
    }

    public boolean hasIp(String ip) {
        return ip != null && ips.contains(normalizeIp(ip));
    }

    static String normalizeIp(String ip) {
        if (ip == null) {
            return "";
        }
        // canonical form (zone index stripped, RFC 5952 IPv6) so Windows and packet addresses compare equal
        return Addresses.canonical(ip);
    }

    public static String normalizeMac(String mac) {
        if (mac == null) {
            return "";
        }
        String hex = mac.replaceAll("[^0-9A-Fa-f]", "").toLowerCase(Locale.ROOT);
        if (hex.length() != 12) {
            return "";
        }
        StringBuilder b = new StringBuilder(17);
        for (int i = 0; i < 12; i += 2) {
            if (i > 0) {
                b.append(':');
            }
            b.append(hex, i, i + 2);
        }
        return b.toString();
    }
}
