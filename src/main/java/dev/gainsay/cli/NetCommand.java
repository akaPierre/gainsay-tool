package dev.gainsay.cli;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Report;
import dev.gainsay.net.NetAnalysis;
import dev.gainsay.net.Segments;
import dev.gainsay.net.capture.LiveCaptureSource;
import dev.gainsay.net.capture.PacketSource;
import dev.gainsay.net.capture.PcapFileSource;
import dev.gainsay.report.ReportWriter;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Command(name = "net", description = "Analyse network traffic (evidence), live or from a pcap/pcapng file. Passive: nothing is sent.")
public final class NetCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Mixin
    OutputOptions output;

    static final class SourceOptions {
        @Option(names = "--iface", paramLabel = "NAME", description = "Capture live on this interface (needs libpcap/Npcap and admin/root).")
        String iface;

        @Option(names = "--pcap", paramLabel = "FILE", description = "Analyse a .pcap or .pcapng file.")
        Path pcap;
    }

    @ArgGroup(exclusive = true, multiplicity = "1")
    SourceOptions source;

    @Option(names = "--duration", paramLabel = "SEC", description = "Live capture duration (default ${DEFAULT-VALUE}).", defaultValue = "60")
    int durationSec;

    @Option(names = "--claims-from", paramLabel = "host.json", split = ",", description = "Host report(s) whose claims to put on trial against this traffic.")
    List<Path> claimsFrom = new ArrayList<>();

    @Option(names = "--segments", paramLabel = "FILE", description = "Segment definitions: one 'name CIDR...' per line.")
    Path segments;

    @Option(names = "--expected-resolvers", paramLabel = "IP", split = ",", description = "Internal DNS resolvers; DNS to anything else is flagged.")
    List<String> expectedResolvers = new ArrayList<>();

    @Option(names = "--max-flows", paramLabel = "N", description = "Flow table cap (default 20000).")
    Integer maxFlows;

    @Override
    public Integer call() throws Exception {
        var err = spec.commandLine().getErr();
        if (durationSec < 1 || durationSec > 86_400) {
            throw new picocli.CommandLine.ParameterException(spec.commandLine(), "--duration must be between 1 and 86400 seconds");
        }
        Set<String> resolvers = expectedResolvers.stream().map(Addresses::canonical).collect(Collectors.toSet());
        NetAnalysis.Options opts = NetAnalysis.Options.defaults().with(segments == null ? null : Segments.load(segments), resolvers, maxFlows);
        List<Report> inputs = new ArrayList<>();
        for (Path p : claimsFrom) {
            inputs.add(ReportWriter.read(p));
        }
        Report net;
        try (PacketSource src = open(err)) {
            net = NetAnalysis.analyze(src, opts);
        }
        inputs.add(net);
        return output.finish(inputs, spec.commandLine().getOut());
    }

    private PacketSource open(java.io.PrintWriter err) throws java.io.IOException {
        if (source.pcap != null) {
            return new PcapFileSource(source.pcap);
        }
        err.println("Passive capture on " + source.iface + " for " + durationSec + " s (read-only; no packets are sent)...");
        return LiveCaptureSource.open(source.iface, Duration.ofSeconds(durationSec));
    }
}
