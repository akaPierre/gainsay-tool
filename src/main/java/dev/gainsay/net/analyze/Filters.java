package dev.gainsay.net.analyze;

/** Builds Wireshark/tshark display filters for "reproduce by hand" snippets. */
public final class Filters {

    private Filters() {
    }

    public static String host(String ip) {
        return (ip != null && ip.contains(":") ? "ipv6.addr==" : "ip.addr==") + ip;
    }

    public static String hostPort(String ip, String transport, int port) {
        return host(ip) + " && " + transport + ".port==" + port;
    }
}
