package dev.gainsay.cli;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;
import dev.gainsay.host.Check;
import dev.gainsay.host.HostAuditor;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.LocalLists;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.host.source.FixtureHostDataSource;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.WindowsHostDataSource;
import dev.gainsay.net.NetAnalysis;
import dev.gainsay.net.Segments;
import dev.gainsay.net.capture.CommandRunner;
import dev.gainsay.net.capture.LiveCaptureSource;
import dev.gainsay.net.capture.PcapFileSource;
import dev.gainsay.net.capture.PktmonCapture;
import dev.gainsay.report.ReportComposer;
import dev.gainsay.report.ReportWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The one-command experience: check privileges, start a passive capture, audit this host (read-only),
 * finish the capture, put the host's settings on trial, compare with the previous run, write the
 * reports and open the HTML. Every step degrades gracefully: no admin → fewer reads; no capture
 * backend → host audit only, with a clear explanation.
 */
@Command(name = "audit", description = {"One command: audit this machine, capture traffic, put its settings on trial and open the report.",
        "Read-only on the host and passive on the network. Run from an elevated prompt for full coverage."})
public final class AuditCommand implements java.util.concurrent.Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = "--config", paramLabel = "FILE", description = "Settings file (default ./gainsay.json if present; create one with 'gainsay init').")
    Path config;

    @Option(names = "--capture", paramLabel = "MODE", description = "auto (default), pktmon, npcap or none.")
    String capture;

    @Option(names = "--seconds", paramLabel = "N", description = "Capture duration (default 60, or captureSeconds in the config).")
    Integer seconds;

    @Option(names = "--iface", paramLabel = "NAME", description = "Npcap/libpcap interface (default: the one carrying this host's address).")
    String iface;

    @Option(names = "--pcap", paramLabel = "FILE", description = "Use an existing capture instead of capturing live.")
    Path pcap;

    @Option(names = "--fixture", paramLabel = "FILE", description = "Use a recorded host snapshot instead of this machine.")
    Path fixture;

    @Option(names = "--exercise", description = "During capture, look up a random non-existent name so LLMNR/NetBIOS fallback can be tested.")
    Boolean exercise;

    @Option(names = "--out", paramLabel = "DIR", description = "Run folder (default: <runsDir>/<timestamp>).")
    Path out;

    @Option(names = "--no-open", description = "Do not open the HTML report.")
    boolean noOpen;

    @Option(names = "--no-baseline", description = "Do not compare with the previous run.")
    boolean noBaseline;

    @Option(names = "--keep-capture", description = "Keep the raw capture files (they contain full packets; deleted by default).")
    boolean keepCapture;

    @Option(names = "--fail-on", paramLabel = "SEVERITY", description = "Exit with code 1 if a FAIL finding of at least this severity exists.")
    Severity failOn;

    @Option(names = "--keep-runs", paramLabel = "N", description = "After this run, delete all but the newest N runs in the runs folder (default: keepRuns in the config, 0 = keep all).")
    Integer keepRuns;

    /** Test hooks. */
    CommandRunner runner = CommandRunner.SYSTEM;
    boolean windows = WindowsHostDataSource.isWindows();

    static final int STEPS = 5;

    @Override
    public Integer call() throws Exception {
        PrintWriter o = spec.commandLine().getOut();
        GainsayConfig cfg = GainsayConfig.load(config);
        int captureSecs = seconds != null ? seconds : cfg.captureSeconds;
        if (captureSecs < 5 || captureSecs > 3600) {
            throw new picocli.CommandLine.ParameterException(spec.commandLine(), "--seconds must be between 5 and 3600");
        }
        String mode = (capture != null ? capture : cfg.capture).toLowerCase(Locale.ROOT);
        if (!Set.of("auto", "pktmon", "npcap", "none").contains(mode)) {
            throw new picocli.CommandLine.ParameterException(spec.commandLine(), "--capture must be auto, pktmon, npcap or none");
        }
        boolean doExercise = exercise != null ? exercise : cfg.exercise;
        int keep = keepRuns != null ? keepRuns : cfg.keepRuns;
        if (keep < 0) {
            throw new picocli.CommandLine.ParameterException(spec.commandLine(), "--keep-runs must be 0 or more");
        }
        Path runsDir = Path.of(cfg.runsDir);
        Path runDir = out != null ? out : runsDir.resolve(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss")));
        Files.createDirectories(runDir);

        HostPolicy policy = HostPolicy.defaults()
                .withLists(cfg.eolList == null ? null : LocalLists.loadEol(Path.of(cfg.eolList)),
                        cfg.buildsList == null ? null : LocalLists.loadBuilds(Path.of(cfg.buildsList)))
                .withAges(cfg.maxSignatureAgeDays, cfg.maxHotfixAgeDays);
        NetAnalysis.Options netOpts = NetAnalysis.Options.defaults().with(Segments.of(cfg.segments, "gainsay.json"),
                cfg.expectedResolvers.stream().map(Addresses::canonical).collect(Collectors.toSet()), null);

        o.println(Terminal.style("bold", "Gainsay audit") + Terminal.style("faint", "  read-only · passive · results in " + runDir));

        // 1. privileges
        boolean liveHost = fixture == null && windows;
        boolean elevated = liveHost && WindowsHostDataSource.isElevated();
        Terminal.step(o, 1, STEPS, "Checking privileges");
        if (liveHost && !elevated) {
            o.println(Terminal.style("yellow", "      Not elevated: BitLocker, TPM, audit policy and pktmon capture need an administrator prompt."));
            o.println(Terminal.style("faint", "      For full coverage: right-click your terminal → Run as administrator, then run 'gainsay audit' again."));
        } else if (liveHost) {
            o.println("      Elevated: every read is available.");
        } else if (fixture == null) {
            o.println(Terminal.style("yellow", "      Live host checks need Windows; this run covers the network only (use --fixture to audit a recorded snapshot)."));
        }

        // 2. capture
        Terminal.step(o, 2, STEPS, "Starting passive capture");
        Capture cap = startCapture(mode, elevated, captureSecs, runDir, netOpts, o);
        long captureStart = System.nanoTime();
        if (cap != null && doExercise) {
            exercise(o);
        }

        // 3. host
        Terminal.step(o, 3, STEPS, "Auditing host settings (read-only)");
        List<Report> inputs = new ArrayList<>();
        List<Check> checks = CheckCatalog.all(policy);
        HostDataSource ds = null;
        if (fixture != null) {
            ds = FixtureHostDataSource.load(fixture);
        } else if (windows) {
            ds = WindowsHostDataSource.collect(rec -> HostAuditor.dryRun(rec, checks), Duration.ofSeconds(60));
        }
        if (ds != null) {
            inputs.add(HostAuditor.audit(ds, checks));
            o.println("      " + checks.size() + " checks on " + ds.identity().label() + ".");
        }

        // 4. finish capture
        Terminal.step(o, 4, STEPS, cap == null ? "No capture this run" : "Finishing capture");
        if (cap != null) {
            Report net = cap.finish(captureStart, captureSecs, o);
            if (net != null) {
                inputs.add(net);
            }
        } else {
            o.println(Terminal.style("faint", "      Without traffic the host's claims stay untested; the report says so."));
        }
        if (inputs.isEmpty()) {
            o.println(Terminal.style("red", "Nothing to report: no host data and no capture."));
            return 2;
        }

        // 5. trial, compare, write
        Terminal.step(o, 5, STEPS, "Putting the settings on trial and writing the report");
        Report baseline = noBaseline ? null : previousRun(runsDir, runDir);
        Report r = ReportComposer.compose(inputs, baseline);
        List<Path> written = ReportWriter.write(r, runDir, List.of("json", "md", "html"));
        o.println();
        Terminal.summary(r, o);
        if (r.baseline != null) {
            o.println();
            o.println(String.format("Since the last run: %d improved, %d regressed, %d new problem(s), %d gone.",
                    r.baseline.improved().size(), r.baseline.regressed().size(), r.baseline.appeared().size(), r.baseline.disappeared().size()));
        }
        Path html = written.stream().filter(p -> p.toString().endsWith(".html")).findFirst().orElseThrow();
        if (keep > 0) {
            int removed = pruneRuns(runsDir, keep);
            if (removed > 0) {
                o.println();
                o.println(Terminal.style("faint", "Removed " + removed + " old run(s); keeping the newest " + keep + "."));
            }
        }
        o.println();
        o.println("Report: " + Terminal.style("bold", html.toAbsolutePath().toString()));
        o.flush();
        if (!noOpen && cfg.openReport) {
            Browser.open(html, o);
        }
        if (failOn != null) {
            for (Finding f : r.findings) {
                if (f.status() == Status.FAIL && f.severity().atLeast(failOn) && f.severity() != Severity.INFO) {
                    return 1;
                }
            }
        }
        return 0;
    }

    /** A running capture of some kind. */
    interface Capture {
        Report finish(long startNanos, int seconds, PrintWriter o) throws Exception;
    }

    private Capture startCapture(String mode, boolean elevated, int secs, Path runDir, NetAnalysis.Options opts, PrintWriter o) throws Exception {
        if (pcap != null) {
            o.println("      Using the capture file " + pcap + ".");
            return (start, s, out) -> analyzeFile(pcap, opts);
        }
        if (mode.equals("none")) {
            o.println("      Capture disabled.");
            return null;
        }
        String pktmon = windows ? PktmonCapture.locate() : null;
        boolean npcap = LiveCaptureSource.nativeLikelyAvailable() && (!windows || hasNpcap());
        String chosen = mode;
        if (mode.equals("auto")) {
            if (npcap) {
                chosen = "npcap";
            } else if (pktmon != null && elevated) {
                chosen = "pktmon";
            } else {
                o.println(Terminal.style("yellow", "      No capture: " + (pktmon != null
                        ? "Windows Packet Monitor (pktmon) needs an elevated prompt"
                        : "install Npcap (https://npcap.com) or libpcap for live capture") + "."));
                return null;
            }
        }
        try {
            if (chosen.equals("pktmon")) {
                if (pktmon == null) {
                    throw new IOException("pktmon.exe was not found (it ships with Windows 10 21H1 and later)");
                }
                PktmonCapture p = new PktmonCapture(runner, pktmon, runDir);
                p.start();
                o.println("      Windows Packet Monitor is capturing on all network adapters for " + secs + " s.");
                return (start, s, out) -> {
                    waitRemaining(start, s, out);
                    try (p) {
                        Path file = p.stopAndConvert();
                        try {
                            return analyzeFile(file, opts);
                        } finally {
                            if (!keepCapture) {
                                Files.deleteIfExists(file);
                                Files.deleteIfExists(file.resolveSibling("capture.etl"));
                            }
                        }
                    }
                };
            }
            String name = iface != null ? iface : interfaceForThisHost();
            if (name == null) {
                throw new IOException("could not tell which interface carries this host's address; pass --iface (see 'gainsay list-ifaces')");
            }
            LiveCaptureSource src = LiveCaptureSource.open(name, Duration.ofSeconds(secs));
            o.println("      Capturing on " + name + " for " + secs + " s.");
            ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "gainsay-capture");
                t.setDaemon(true);
                return t;
            });
            Future<Report> f = pool.submit(() -> {
                try (src) {
                    return NetAnalysis.analyze(src, opts);
                }
            });
            pool.shutdown();
            return (start, s, out) -> {
                waitRemaining(start, s, out);
                return f.get();
            };
        } catch (IOException e) {
            o.println(Terminal.style("yellow", "      Capture unavailable: " + e.getMessage()));
            return null;
        }
    }

    private static Report analyzeFile(Path file, NetAnalysis.Options opts) throws IOException {
        try (PcapFileSource src = new PcapFileSource(file)) {
            return NetAnalysis.analyze(src, opts);
        }
    }

    private static void waitRemaining(long startNanos, int secs, PrintWriter o) throws InterruptedException {
        long end = startNanos + secs * 1_000_000_000L;
        long left;
        while ((left = end - System.nanoTime()) > 0) {
            o.println(Terminal.style("faint", "      capturing… " + (left / 1_000_000_000L + 1) + " s left"));
            o.flush();
            Thread.sleep(Math.min(left / 1_000_000L + 1, 10_000));
        }
    }

    private static boolean hasNpcap() {
        String root = System.getenv("SystemRoot");
        return root != null && (Files.exists(Path.of(root, "System32", "Npcap", "wpcap.dll")) || Files.exists(Path.of(root, "System32", "wpcap.dll")));
    }

    /** The pcap interface that carries one of this machine's own addresses (read from the OS, no traffic). */
    private static String interfaceForThisHost() throws IOException {
        List<String> ips = new ArrayList<>();
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (ni.isUp() && !ni.isLoopback()) {
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    ips.add(Addresses.canonical(a.getHostAddress()));
                }
            }
        }
        return LiveCaptureSource.interfaceFor(ips);
    }

    /**
     * Optional, minimal self-generated traffic: one lookup of a random single-label name that cannot exist.
     * On Windows, a failed lookup makes the DNS client fall back to LLMNR/NetBIOS if they are enabled, which
     * is exactly the evidence the LLMNR/NetBIOS claims need. Nothing is sent to any other host directly.
     */
    private static void exercise(PrintWriter o) {
        String name = "gainsay-probe-" + UUID.randomUUID().toString().substring(0, 8);
        o.println("      Exercise: looking up '" + name + "' (does not exist) to test LLMNR/NetBIOS fallback.");
        try {
            InetAddress.getAllByName(name);
        } catch (IOException expected) {
            // NXDOMAIN is the point
        }
    }

    /** Folder names that {@code audit} creates; only these are ever pruned. */
    private static final java.util.regex.Pattern RUN_NAME = java.util.regex.Pattern.compile("\\d{4}-\\d{2}-\\d{2}_\\d{6}");

    /**
     * Deletes all but the newest {@code keep} run folders. Only folders that look like runs Gainsay made
     * (timestamp name, a report.json inside, no subfolders) are touched, so nothing else in the runs folder can be lost.
     */
    static int pruneRuns(Path runsDir, int keep) throws IOException {
        if (!Files.isDirectory(runsDir)) {
            return 0;
        }
        List<Path> runs;
        try (Stream<Path> s = Files.list(runsDir)) {
            runs = s.filter(Files::isDirectory)
                    .filter(p -> RUN_NAME.matcher(p.getFileName().toString()).matches())
                    .filter(p -> Files.exists(p.resolve("report.json")))
                    .sorted().toList();
        }
        int removed = 0;
        for (Path run : runs.subList(0, Math.max(0, runs.size() - keep))) {
            List<Path> files;
            try (Stream<Path> s = Files.list(run)) {
                files = s.toList();
            }
            if (files.stream().anyMatch(Files::isDirectory)) {
                continue;
            }
            for (Path f : files) {
                Files.delete(f);
            }
            Files.delete(run);
            removed++;
        }
        return removed;
    }

    /** The most recent earlier run in the runs folder, if any. */
    static Report previousRun(Path runsDir, Path current) {
        if (!Files.isDirectory(runsDir)) {
            return null;
        }
        try (Stream<Path> s = Files.list(runsDir)) {
            List<Path> runs = s.filter(p -> Files.exists(p.resolve("report.json")))
                    .filter(p -> !p.toAbsolutePath().normalize().equals(current.toAbsolutePath().normalize()))
                    .sorted().toList();
            return runs.isEmpty() ? null : ReportWriter.read(runs.get(runs.size() - 1).resolve("report.json"));
        } catch (IOException e) {
            return null;
        }
    }
}
