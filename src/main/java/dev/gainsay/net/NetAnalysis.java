package dev.gainsay.net;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.net.analyze.AnalysisContext;
import dev.gainsay.net.analyze.Analyzer;
import dev.gainsay.net.analyze.ExposureAnalyzer;
import dev.gainsay.net.analyze.Flow;
import dev.gainsay.net.analyze.FlowTable;
import dev.gainsay.net.analyze.HttpAnalyzer;
import dev.gainsay.net.analyze.HygieneAnalyzer;
import dev.gainsay.net.analyze.LegacyProtocolAnalyzer;
import dev.gainsay.net.analyze.NameResolutionAnalyzer;
import dev.gainsay.net.analyze.NtlmAnalyzer;
import dev.gainsay.net.analyze.RdpAnalyzer;
import dev.gainsay.net.analyze.SmbAnalyzer;
import dev.gainsay.net.analyze.StreamHead;
import dev.gainsay.net.analyze.TlsAnalyzer;
import dev.gainsay.net.capture.PacketSource;
import dev.gainsay.net.capture.RawFrame;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.Decoder;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * The capture loop: frames → {@link Decoder} → {@link FlowTable} → analyzers → partial report with
 * findings, observations (evidence for the trial) and segment-boundary crossings.
 *
 * <p>Nothing thrown by a decoder or analyzer escapes the loop: malformed frames are counted, analyzer
 * errors are counted and reported as a note. Memory is bounded by the flow cap, the stream-head
 * budget and the caps inside {@link AnalysisContext}.
 */
public final class NetAnalysis {

    /** Tunables; defaults suit a laptop analysing a few GB of capture. */
    public record Options(int maxFlows, int headBytes, long headBudget, Segments segments, Set<String> expectedResolvers) {
        public static Options defaults() {
            return new Options(20_000, 16 * 1024, 64L * 1024 * 1024, Segments.defaults(), Set.of());
        }

        public Options with(Segments s, Set<String> resolvers, Integer flows) {
            return new Options(flows == null ? maxFlows : flows, headBytes, headBudget, s == null ? segments : s,
                    resolvers == null ? expectedResolvers : resolvers);
        }
    }

    private NetAnalysis() {
    }

    public static List<Analyzer> analyzers(Options o) {
        return List.of(new HttpAnalyzer(), new LegacyProtocolAnalyzer(), new SmbAnalyzer(), new NtlmAnalyzer(), new TlsAnalyzer(),
                new RdpAnalyzer(), new NameResolutionAnalyzer(o.expectedResolvers()), new ExposureAnalyzer(), new HygieneAnalyzer());
    }

    public static Report analyze(PacketSource source, Options o) throws IOException {
        List<Analyzer> analyzers = analyzers(o);
        AnalysisContext ctx = new AnalysisContext(o.segments(), source.describe());
        long[] errors = {0};
        FlowTable flows = new FlowTable(o.maxFlows(), o.headBytes(), o.headBudget(), f -> endFlow(f, analyzers, ctx, errors));
        long packets = 0, bytes = 0, malformed = 0;
        Instant first = null, last = null;
        RawFrame raw;
        while ((raw = source.next()) != null) {
            packets++;
            bytes += raw.originalLength();
            if (first == null) {
                first = raw.timestamp();
            }
            last = raw.timestamp();
            DecodedPacket p = Decoder.decode(raw, packets);
            if (p == null) {
                malformed++;
                continue;
            }
            ctx.learn(p);
            Flow f = null;
            StreamHead grown = null;
            boolean toServer = false;
            if ((p.isTcp() || p.isUdp()) && !p.fragment) {
                f = flows.get(p);
                if (p.isTcp()) {
                    toServer = f.fromClient(p);
                    grown = flows.feed(f, p);
                }
            }
            for (Analyzer a : analyzers) {
                try {
                    a.onPacket(p, f, ctx);
                    if (grown != null) {
                        a.onStream(f, toServer, grown, p, ctx);
                    }
                } catch (RuntimeException e) {
                    errors[0]++;
                }
            }
        }
        for (Flow f : flows.drain()) {
            endFlow(f, analyzers, ctx, errors);
        }
        for (Analyzer a : analyzers) {
            try {
                a.finish(ctx);
            } catch (RuntimeException e) {
                errors[0]++;
            }
        }

        Report r = new Report();
        r.kinds.add("net");
        r.captures.add(new Report.CaptureInfo(source.describe(), packets, bytes, malformed, flows.evicted(), first, last, o.segments().source()));
        List<Finding> findings = ctx.findings();
        r.findings.addAll(findings);
        r.findings.addAll(summaries(analyzers, ctx, first, last));
        r.observations.addAll(ctx.observations());
        r.boundaries.addAll(ctx.crossings());
        if (malformed > 0) {
            r.notes.add(malformed + " frame(s) could not be decoded (truncated, unsupported link type or malformed) and were skipped.");
        }
        if (flows.evicted() > 0) {
            r.notes.add(flows.evicted() + " flow(s) were evicted from the flow table (cap " + o.maxFlows() + "); analysis of very long captures is best effort.");
        }
        if (errors[0] > 0) {
            r.notes.add(errors[0] + " analyzer error(s) were caught on malformed input; affected packets were skipped.");
        }
        if (ctx.dropped() > 0) {
            r.notes.add(ctx.dropped() + " finding/observation record(s) were dropped after reaching the memory caps.");
        }
        r.notes.add("Network analysis is passive: no packet was sent, and payloads, passwords, cookies and tokens were not stored.");
        return r;
    }

    private static void endFlow(Flow f, List<Analyzer> analyzers, AnalysisContext ctx, long[] errors) {
        for (Analyzer a : analyzers) {
            try {
                a.onFlowEnd(f, ctx);
            } catch (RuntimeException e) {
                errors[0]++;
            }
        }
        if (f.synAckSeen || f.protocolLabel() != null) {
            ctx.flowSeen(f, f.protocolLabel() != null ? f.protocolLabel() : (f.protocol == DecodedPacket.TCP ? "tcp/" : "udp/") + f.serverPort,
                    f.cleartext());
        }
    }

    /** For each check id with no finding: PASS if relevant traffic was seen, else NOT_APPLICABLE. */
    private static List<Finding> summaries(List<Analyzer> analyzers, AnalysisContext ctx, Instant first, Instant last) {
        java.util.ArrayList<Finding> out = new java.util.ArrayList<>();
        for (Analyzer a : analyzers) {
            for (String id : a.checkIds()) {
                if (ctx.hasFinding(id)) {
                    continue;
                }
                NetChecks.Info info = NetChecks.get(id);
                long n = ctx.relevantCount(id);
                Status st = n > 0 ? Status.PASS : Status.NOT_APPLICABLE;
                String summary = n > 0 ? "No problem found in " + n + " relevant observation(s)."
                        : "No relevant traffic in this capture, so this could not be judged.";
                out.add(Finding.builder(id, Plane.NET).category(info.category()).title(info.title()).severity(info.severity()).status(st)
                        .summary(summary).rationale(info.rationale()).howVerified(info.howVerified()).remediation(info.remediation())
                        .references(info.references()).seen(first, last).occurrences(Math.max(1, n)).build());
            }
        }
        return out;
    }
}
