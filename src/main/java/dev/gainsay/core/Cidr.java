package dev.gainsay.core;

/** An IPv4 or IPv6 prefix such as {@code 10.0.0.0/24} or {@code fd00::/8}. A bare address is a /32 or /128. */
public record Cidr(byte[] network, int prefix) {

    public static Cidr parse(String text) {
        String t = text.trim();
        int slash = t.indexOf('/');
        byte[] addr = Addresses.parse(slash < 0 ? t : t.substring(0, slash));
        if (addr == null) {
            throw new IllegalArgumentException("not an IP address or CIDR: " + text);
        }
        int bits = addr.length * 8;
        int prefix = bits;
        if (slash >= 0) {
            try {
                prefix = Integer.parseInt(t.substring(slash + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("bad prefix length in " + text);
            }
            if (prefix < 0 || prefix > bits) {
                throw new IllegalArgumentException("bad prefix length in " + text);
            }
        }
        return new Cidr(mask(addr, prefix), prefix);
    }

    public boolean contains(byte[] addr) {
        if (addr == null || addr.length != network.length) {
            return false;
        }
        byte[] m = mask(addr, prefix);
        for (int i = 0; i < m.length; i++) {
            if (m[i] != network[i]) {
                return false;
            }
        }
        return true;
    }

    public boolean contains(String ip) {
        return contains(Addresses.parse(ip));
    }

    /** Number of addresses, saturating at Long.MAX_VALUE. */
    public long size() {
        int hostBits = network.length * 8 - prefix;
        return hostBits >= 63 ? Long.MAX_VALUE : 1L << hostBits;
    }

    static byte[] mask(byte[] addr, int prefix) {
        byte[] out = addr.clone();
        for (int i = 0; i < out.length; i++) {
            int bitsHere = Math.max(0, Math.min(8, prefix - i * 8));
            out[i] = (byte) (out[i] & (0xff << (8 - bitsHere)));
        }
        return out;
    }

    @Override
    public String toString() {
        return Addresses.format(network, 0, network.length) + "/" + prefix;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Cidr c && c.prefix == prefix && java.util.Arrays.equals(c.network, network);
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(network) * 31 + prefix;
    }
}
