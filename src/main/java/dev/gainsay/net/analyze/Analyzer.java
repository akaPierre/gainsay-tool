package dev.gainsay.net.analyze;

import dev.gainsay.net.decode.DecodedPacket;

import java.util.List;

/**
 * A stateful, passive analyzer. Analyzers never send packets and never store payloads: they read
 * protocol fields, record redacted evidence through the {@link AnalysisContext}, and keep only small
 * per-flow markers. Exceptions thrown by an analyzer are caught by the engine and counted.
 */
public interface Analyzer {

    /** The NET check ids this analyzer is responsible for (used for PASS / NOT_APPLICABLE summaries). */
    List<String> checkIds();

    /** Every decoded packet. {@code flow} is null for non-TCP/UDP packets (ARP, ICMP, fragments). */
    default void onPacket(DecodedPacket p, Flow flow, AnalysisContext ctx) {
    }

    /** New in-order bytes were appended to one direction's stream head. */
    default void onStream(Flow flow, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
    }

    /** The flow was evicted or the capture ended. */
    default void onFlowEnd(Flow flow, AnalysisContext ctx) {
    }

    /** End of capture. */
    default void finish(AnalysisContext ctx) {
    }
}
