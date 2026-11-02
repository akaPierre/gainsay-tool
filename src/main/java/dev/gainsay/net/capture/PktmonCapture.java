package dev.gainsay.net.capture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Live capture without Npcap, using Windows' built-in Packet Monitor ({@code pktmon.exe}, Windows 10
 * 21H1+ / Windows 11 / Server 2022+). Needs an elevated prompt.
 *
 * <p>Sequence: {@code pktmon start --capture --comp nics --pkt-size 0 --file-name run.etl} (capture full
 * packets at the network adapters only, so each packet is recorded once), then {@code pktmon stop} and
 * {@code pktmon etl2pcap run.etl --out run.pcapng}; the pcapng is read by {@link PcapFileSource}.
 *
 * <p>Gainsay adds no packet filters and changes no settings. If a Packet Monitor session is already
 * running (someone else's capture), start fails and Gainsay does not touch it. Gainsay always stops the
 * session it started, including on Ctrl+C (shutdown hook). The .etl and .pcapng files stay in the run
 * folder; delete them if you do not need them, as they contain full packets.
 */
public final class PktmonCapture implements AutoCloseable {

    static final Duration CMD_TIMEOUT = Duration.ofSeconds(120);

    private final CommandRunner runner;
    private final String exe;
    private final Path etl;
    private final Path pcapng;
    private boolean running;
    private Thread hook;

    public PktmonCapture(CommandRunner runner, String exe, Path workDir) {
        this.runner = runner;
        this.exe = exe;
        this.etl = workDir.resolve("capture.etl").toAbsolutePath();
        this.pcapng = workDir.resolve("capture.pcapng").toAbsolutePath();
    }

    /** Path of pktmon.exe if this Windows has it, else null. */
    public static String locate() {
        String root = System.getenv("SystemRoot");
        if (root == null) {
            return null;
        }
        Path p = Path.of(root, "System32", "PktMon.exe");
        return Files.exists(p) ? p.toString() : null;
    }

    public void start() throws IOException {
        Files.createDirectories(etl.getParent());
        List<String> cmd = new ArrayList<>(List.of(exe, "start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", etl.toString()));
        CommandRunner.Result r = runner.run(cmd, CMD_TIMEOUT);
        if (r.exitCode() != 0) {
            throw new IOException("pktmon could not start (" + firstLine(r.output()) + "). It needs an elevated prompt, "
                    + "and a capture that is already running is left alone.");
        }
        running = true;
        hook = new Thread(this::stopQuietly, "gainsay-pktmon-stop");
        Runtime.getRuntime().addShutdownHook(hook);
    }

    /** Stops the capture and converts it; returns the pcapng to analyse. */
    public Path stopAndConvert() throws IOException {
        stop();
        CommandRunner.Result r = runner.run(List.of(exe, "etl2pcap", etl.toString(), "--out", pcapng.toString()), CMD_TIMEOUT);
        if (r.exitCode() != 0 || !Files.exists(pcapng)) {
            throw new IOException("pktmon could not convert the capture (" + firstLine(r.output()) + ")");
        }
        return pcapng;
    }

    private void stop() throws IOException {
        if (!running) {
            return;
        }
        CommandRunner.Result r = runner.run(List.of(exe, "stop"), CMD_TIMEOUT);
        running = false;
        removeHook();
        if (r.exitCode() != 0) {
            throw new IOException("pktmon stop failed (" + firstLine(r.output()) + "); run 'pktmon stop' yourself from an elevated prompt");
        }
    }

    private void stopQuietly() {
        try {
            if (running) {
                runner.run(List.of(exe, "stop"), CMD_TIMEOUT);
                running = false;
            }
        } catch (IOException ignored) {
            // best effort during shutdown
        }
    }

    private void removeHook() {
        if (hook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (IllegalStateException ignored) {
                // already shutting down
            }
            hook = null;
        }
    }

    public boolean running() {
        return running;
    }

    @Override
    public void close() {
        stopQuietly();
        removeHook();
    }

    static String firstLine(String s) {
        if (s == null || s.isBlank()) {
            return "no output";
        }
        String t = s.strip();
        int nl = t.indexOf('\n');
        t = (nl >= 0 ? t.substring(0, nl) : t).strip();
        return t.length() > 160 ? t.substring(0, 160) : t;
    }
}
