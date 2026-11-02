package dev.gainsay.cli;

import dev.gainsay.core.Report;
import dev.gainsay.report.ReportWriter;
import dev.gainsay.scan.ConnectScanner;
import dev.gainsay.scan.RateLimiter;
import dev.gainsay.scan.TargetPolicy;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "scan", description = {"OPTIONAL ACTIVE CHECK: low-rate TCP connect to a short port list on explicitly authorised targets.",
        "Refuses to run without --i-am-authorized, refuses public addresses unless listed in allowed_targets.txt."})
public final class ScanCommand implements Callable<Integer> {

    static final String BANNER = """
            ============================================================================
             gainsay scan — ACTIVE network check
             You are responsible for having permission to test every target below.
             Connect-only, rate-limited, no payloads, no banner grabbing, no exploitation.
            ============================================================================""";

    @Spec
    CommandSpec spec;

    @Mixin
    OutputOptions output;

    @Option(names = "--targets", required = true, paramLabel = "CIDR_OR_FILE",
            description = "Comma-separated IPs/CIDRs, or a file with one per line. Host names are not accepted.")
    String targets;

    @Option(names = "--i-am-authorized", description = "Confirms you are authorised to test these targets. Required.")
    boolean authorized;

    @Option(names = "--rate", paramLabel = "N", description = "Connections per second (1-" + RateLimiter.MAX_RATE + ", default ${DEFAULT-VALUE}).",
            defaultValue = "" + RateLimiter.DEFAULT_RATE)
    int rate;

    @Option(names = "--ports", paramLabel = "P", split = ",", description = "Ports to try (max " + ConnectScanner.MAX_PORTS + "; default: a short list of risky services).")
    List<Integer> ports;

    @Option(names = "--allowlist", paramLabel = "FILE", description = "Allowlist for non-private targets (default ./" + TargetPolicy.DEFAULT_ALLOWLIST + ").")
    Path allowlist;

    @Option(names = "--timeout-ms", paramLabel = "MS", description = "Connect timeout (default ${DEFAULT-VALUE}).", defaultValue = "1000")
    int timeoutMs;

    @Option(names = "--claims-from", paramLabel = "host.json", split = ",", description = "Host report(s) to put on trial against the scan results.")
    List<Path> claimsFrom = new ArrayList<>();

    /** Test hook: the connector used for connections. */
    ConnectScanner.Connector connector = ConnectScanner.Connector.TCP;
    RateLimiter.Clock clock = RateLimiter.Clock.SYSTEM;

    @Override
    public Integer call() throws Exception {
        var err = spec.commandLine().getErr();
        if (!authorized) {
            throw new ParameterException(spec.commandLine(),
                    "scan is an active check and refuses to run without --i-am-authorized (you must have permission to test the targets)");
        }
        if (rate < 1 || rate > RateLimiter.MAX_RATE) {
            throw new ParameterException(spec.commandLine(), "--rate must be between 1 and " + RateLimiter.MAX_RATE);
        }
        if (timeoutMs < 100 || timeoutMs > 10_000) {
            throw new ParameterException(spec.commandLine(), "--timeout-ms must be between 100 and 10000");
        }
        List<Integer> portList = ports == null ? ConnectScanner.DEFAULT_PORTS : ports;
        if (portList.size() > ConnectScanner.MAX_PORTS || portList.stream().anyMatch(p -> p < 1 || p > 65535)) {
            throw new ParameterException(spec.commandLine(), "--ports: at most " + ConnectScanner.MAX_PORTS + " ports in 1-65535");
        }
        TargetPolicy policy = TargetPolicy.load(allowlist != null ? allowlist : Path.of(TargetPolicy.DEFAULT_ALLOWLIST));
        List<byte[]> addrs;
        try {
            addrs = policy.authorise(TargetPolicy.targetSpecs(targets));
        } catch (TargetPolicy.Refused e) {
            throw new ParameterException(spec.commandLine(), e.getMessage());
        }
        err.println(BANNER);
        err.printf("Targets: %d address(es) × %d port(s) at %d connection(s)/s%n", addrs.size(), portList.size(), rate);
        err.flush();
        Report scan = new ConnectScanner(connector, new RateLimiter(rate, clock), timeoutMs).scan(addrs, portList);
        List<Report> inputs = new ArrayList<>();
        for (Path p : claimsFrom) {
            inputs.add(ReportWriter.read(p));
        }
        inputs.add(scan);
        return output.finish(inputs, spec.commandLine().getOut());
    }
}
