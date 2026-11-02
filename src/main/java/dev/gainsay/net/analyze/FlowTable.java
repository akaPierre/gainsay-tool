package dev.gainsay.net.analyze;

import dev.gainsay.net.decode.DecodedPacket;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Flows keyed by the canonical 5-tuple, in an access-ordered LRU map with a hard cap. When the cap
 * is reached the least recently used flow is evicted (its stream buffers released and analyzers told
 * via the eviction callback), so memory stays bounded however many connections the capture contains.
 */
public final class FlowTable {

    private final int maxFlows;
    private final int headCap;
    private final StreamHead.Budget budget;
    private final Consumer<Flow> onEvict;
    private long evicted;
    private final LinkedHashMap<String, Flow> flows;

    public FlowTable(int maxFlows, int headCap, long headBudgetBytes, Consumer<Flow> onEvict) {
        this.maxFlows = maxFlows;
        this.headCap = headCap;
        this.budget = new StreamHead.Budget(headBudgetBytes);
        this.onEvict = onEvict;
        this.flows = new LinkedHashMap<>(1024, 0.75f, true);
    }

    /** Finds or creates the flow for a TCP/UDP packet. */
    public Flow get(DecodedPacket p) {
        String a = p.srcIp + "|" + p.srcPort;
        String b = p.dstIp + "|" + p.dstPort;
        String key = p.protocol + "|" + (a.compareTo(b) <= 0 ? a + "|" + b : b + "|" + a);
        Flow f = flows.get(key);
        if (f == null) {
            boolean srcIsClient;
            if (p.protocol == DecodedPacket.TCP && p.has(DecodedPacket.SYN)) {
                srcIsClient = !p.has(DecodedPacket.ACK);
            } else {
                srcIsClient = p.srcPort > p.dstPort || (p.srcPort == p.dstPort && a.compareTo(b) <= 0);
            }
            f = new Flow(key, p, srcIsClient, headCap, budget);
            flows.put(key, f);
            if (flows.size() > maxFlows) {
                Iterator<Map.Entry<String, Flow>> it = flows.entrySet().iterator();
                Flow old = it.next().getValue();
                it.remove();
                evicted++;
                onEvict.accept(old);
                old.release();
            }
        }
        f.last = p.ts;
        f.packets++;
        return f;
    }

    /** Feeds TCP payload into the right stream head; returns the head if it grew, else null. */
    public StreamHead feed(Flow f, DecodedPacket p) {
        boolean toServer = f.fromClient(p);
        StreamHead h = f.head(toServer);
        if (p.has(DecodedPacket.SYN)) {
            h.expect(p.seq + 1);
        }
        if (p.payloadLength > 0 && h.append(p.seq, p.data, p.payloadOffset, p.payloadLength)) {
            return h;
        }
        return null;
    }

    /** Remaining flows at the end of the capture. */
    public List<Flow> drain() {
        List<Flow> all = new ArrayList<>(flows.values());
        flows.clear();
        return all;
    }

    public long evicted() {
        return evicted;
    }

    public int size() {
        return flows.size();
    }

    public long bufferedBytes() {
        return budget.used();
    }
}
