package dev.gainsay.net.analyze;

import dev.gainsay.net.decode.DecodedPacket;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * One TCP or UDP conversation, oriented client → server. The client is whoever sent the first SYN;
 * for flows joined mid-stream, the side using the higher (ephemeral) port is assumed to be the client.
 */
public final class Flow {

    public final String key;
    public final int protocol;
    public final String clientIp;
    public final int clientPort;
    public final String serverIp;
    public final int serverPort;
    public String clientMac;
    public String serverMac;
    public final Instant start;
    public Instant last;
    public long packets;
    public boolean synSeen;
    public boolean synAckSeen;
    public boolean resetByServer;
    final StreamHead toServer;
    final StreamHead toClient;
    /** Per-analyzer state markers ("tls.ch", "smb.smb1only", ...); small and bounded by analyzer design. */
    private final Set<String> marks = new HashSet<>();
    /** Protocol label for the segment-boundary view, and whether any analyzer saw it in cleartext. */
    String label;
    boolean cleartext;

    /** Analyzers name the protocol they recognised; a cleartext classification wins over a neutral one. */
    public void classify(String protocol, boolean clear) {
        if (label == null || (clear && !cleartext)) {
            label = protocol;
        }
        cleartext |= clear;
    }

    Flow(String key, DecodedPacket p, boolean srcIsClient, int headCap, StreamHead.Budget budget) {
        this.key = key;
        this.protocol = p.protocol;
        this.clientIp = srcIsClient ? p.srcIp : p.dstIp;
        this.clientPort = srcIsClient ? p.srcPort : p.dstPort;
        this.serverIp = srcIsClient ? p.dstIp : p.srcIp;
        this.serverPort = srcIsClient ? p.dstPort : p.srcPort;
        this.clientMac = srcIsClient ? p.srcMac : p.dstMac;
        this.serverMac = srcIsClient ? p.dstMac : p.srcMac;
        this.start = p.ts;
        this.last = p.ts;
        this.toServer = new StreamHead(headCap, budget);
        this.toClient = new StreamHead(headCap, budget);
    }

    public String protocolLabel() {
        return label;
    }

    public boolean cleartext() {
        return cleartext;
    }

    public boolean fromClient(DecodedPacket p) {
        return p.srcPort == clientPort && p.srcIp.equals(clientIp);
    }

    /** Sets a marker; returns true if it was not already set (handy for "report once"). */
    public boolean mark(String m) {
        return marks.add(m);
    }

    public boolean marked(String m) {
        return marks.contains(m);
    }

    public StreamHead head(boolean towardServer) {
        return towardServer ? toServer : toClient;
    }

    /** "client:port → server:port" for evidence. */
    public String label() {
        return DecodedPacket.endpoint(clientIp, clientPort) + " → " + DecodedPacket.endpoint(serverIp, serverPort);
    }

    public String server() {
        return DecodedPacket.endpoint(serverIp, serverPort);
    }

    void release() {
        toServer.release();
        toClient.release();
    }
}
