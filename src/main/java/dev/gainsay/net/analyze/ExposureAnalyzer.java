package dev.gainsay.net.analyze;

import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.decode.DecodedPacket;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Map.entry;

/**
 * NET-EXPOSE-001 and service evidence for the trial. Listening services are inferred passively from
 * SYN-ACKs (TCP) and from replies sent from well-known UDP ports; closed ports from RST answers to a
 * SYN. Nothing is probed. Risky services are WARN, or FAIL when they are inherently dangerous to expose
 * or are reached from another segment.
 */
public final class ExposureAnalyzer implements Analyzer {

    static final int MAX_SERVICES = 50_000;

    /** port → service name for TCP services worth reporting. */
    static final Map<Integer, String> RISKY_TCP = Map.ofEntries(
            entry(21, "FTP"), entry(23, "Telnet"), entry(111, "rpcbind"), entry(135, "MS-RPC"), entry(139, "NetBIOS session"),
            entry(445, "SMB"), entry(512, "rexec"), entry(513, "rlogin"), entry(514, "rsh"), entry(1433, "MS SQL"), entry(1521, "Oracle"),
            entry(2375, "Docker API (no TLS)"), entry(2376, "Docker API"), entry(2379, "etcd"), entry(3306, "MySQL"), entry(3389, "RDP"),
            entry(5432, "PostgreSQL"), entry(5900, "VNC"), entry(5901, "VNC"), entry(5985, "WinRM HTTP"), entry(5986, "WinRM HTTPS"),
            entry(6379, "Redis"), entry(6443, "Kubernetes API"), entry(9200, "Elasticsearch"), entry(10250, "kubelet"),
            entry(11211, "memcached"), entry(27017, "MongoDB"));

    /** Exposed at all = FAIL: unauthenticated by default, or cleartext remote shells. */
    static final Set<Integer> ALWAYS_FAIL = Set.of(23, 512, 513, 514, 2375, 2379, 5900, 5901, 6379, 9200, 10250, 11211, 27017);

    static final Map<Integer, String> RISKY_UDP = Map.of(161, "SNMP", 623, "IPMI", 1900, "SSDP", 11211, "memcached", 69, "TFTP");

    /** Ports whose closed state is trial evidence (RDP, WinRM, NetBIOS). */
    static final Set<Integer> CLAIM_PORTS = Set.of(139, 3389, 5985, 5986);

    private final Set<String> seen = new HashSet<>();

    @Override
    public List<String> checkIds() {
        return List.of("NET-EXPOSE-001");
    }

    @Override
    public void onPacket(DecodedPacket p, Flow f, AnalysisContext ctx) {
        if (p.isTcp() && f != null) {
            tcp(p, f, ctx);
        } else if (p.isUdp() && RISKY_UDP.containsKey(p.srcPort) && p.payloadLength > 0 && p.srcPort != p.dstPort) {
            service(p.srcIp, p.srcMac, p.dstIp, p.srcPort, "udp", RISKY_UDP.get(p.srcPort), p, ctx);
        }
    }

    private void tcp(DecodedPacket p, Flow f, AnalysisContext ctx) {
        boolean fromServer = !f.fromClient(p);
        if (p.has(DecodedPacket.SYN) && !p.has(DecodedPacket.ACK)) {
            f.synSeen = true;
            return;
        }
        if (fromServer && p.has(DecodedPacket.SYN) && p.has(DecodedPacket.ACK) && !f.synAckSeen) {
            f.synAckSeen = true;
            ctx.relevant("NET-EXPOSE-001");
            if (f.serverMac == null) {
                f.serverMac = p.srcMac;
            }
            String name = RISKY_TCP.get(f.serverPort);
            f.classify(name == null ? "tcp/" + f.serverPort : name, false);
            ctx.observe(ObservationType.SERVICE_LISTENING, f.serverIp, p.srcMac, f.clientIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, "SYN-ACK from TCP/" + f.serverPort + (name == null ? "" : " (" + name + ")"),
                            Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && tcp.flags.syn==1 && tcp.flags.ack==1"));
            if (name != null) {
                service(f.serverIp, p.srcMac, f.clientIp, f.serverPort, "tcp", name, p, ctx);
            }
            return;
        }
        if (fromServer && p.has(DecodedPacket.RST) && f.synSeen && !f.synAckSeen && CLAIM_PORTS.contains(f.serverPort) && f.mark("expose.closed")) {
            ctx.observe(ObservationType.PORT_CLOSED, f.serverIp, p.srcMac, f.clientIp, f.serverPort, p.ts,
                    ctx.packetEvidence(p, "RST in answer to SYN on TCP/" + f.serverPort + " (port closed)",
                            Filters.hostPort(f.serverIp, "tcp", f.serverPort) + " && tcp.flags.reset==1"));
        }
    }

    private void service(String server, String mac, String client, int port, String transport, String name, DecodedPacket p, AnalysisContext ctx) {
        String from = ctx.segments.of(client);
        String to = ctx.segments.of(server);
        boolean crossing = !from.equals(to);
        String key = server + "|" + transport + "|" + port + "|" + crossing;
        if (seen.size() >= MAX_SERVICES || !seen.add(key)) {
            return;
        }
        if (transport.equals("udp")) {
            ctx.relevant("NET-EXPOSE-001");
            ctx.observe(ObservationType.SERVICE_LISTENING, server, mac, client, port, p.ts,
                    ctx.packetEvidence(p, "UDP reply from port " + port + " (" + name + ")", Filters.hostPort(server, "udp", port)));
        }
        boolean fail = ALWAYS_FAIL.contains(port) || crossing || from.equals("public");
        String where = crossing ? " and is reached from segment " + from : "";
        ctx.finding("NET-EXPOSE-001", DecodedPacket.endpoint(server, port) + "/" + transport, fail ? Status.FAIL : Status.WARN,
                name + " on " + DecodedPacket.endpoint(server, port) + " is reachable" + where + ".",
                ctx.packetEvidence(p, name + " answered " + client, Filters.hostPort(server, transport, port)), p.ts);
    }
}
