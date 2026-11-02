package dev.gainsay.cli;

import dev.gainsay.core.Json;
import dev.gainsay.core.Report;
import dev.gainsay.net.synth.Scenarios;
import dev.gainsay.report.ReportWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuditCommandTest {

    record Run(int code, String out) {
    }

    static Run run(String... args) {
        CommandLine cl = Main.commandLine();
        StringWriter sw = new StringWriter();
        cl.setOut(new PrintWriter(sw));
        cl.setErr(new PrintWriter(sw));
        int code = cl.execute(args);
        return new Run(code, sw.toString());
    }

    @Test
    void oneCommandRunsHostNetAndTrialAndComparesWithThePreviousRun(@TempDir Path dir) throws Exception {
        Path pcap = Scenarios.demo().write(dir.resolve("demo.pcap"));
        Path cfg = dir.resolve("gainsay.json");
        Json.MAPPER.writeValue(cfg.toFile(), Map.of("runsDir", dir.resolve("runs").toString(), "openReport", false,
                "segments", Map.of("office", List.of("10.0.0.0/24"), "web", List.of("10.0.1.0/24"))));

        Run first = run("audit", "--config", cfg.toString(), "--fixture", "samples/fixtures/host-unhardened.json",
                "--pcap", pcap.toString(), "--out", dir.resolve("runs/2026-01-01_000000").toString());
        assertEquals(0, first.code(), first.out());
        assertTrue(first.out().contains("Fix these first"), first.out());
        assertTrue(first.out().contains("Trial coverage"));
        Report r1 = ReportWriter.read(dir.resolve("runs/2026-01-01_000000/report.json"));
        assertTrue(r1.kinds.containsAll(List.of("host", "net", "trial")));
        assertFalse(r1.fixPlan.isEmpty());
        assertTrue(r1.boundaries.stream().anyMatch(b -> b.toSegment().equals("web")), "segments come from the config file");
        assertNull(r1.baseline, "first run has nothing to compare with");

        Run second = run("audit", "--config", cfg.toString(), "--fixture", "samples/fixtures/host-unhardened.json",
                "--pcap", pcap.toString(), "--out", dir.resolve("runs/2026-01-02_000000").toString());
        assertEquals(0, second.code(), second.out());
        assertTrue(second.out().contains("Since the last run"));
        assertNotNull(ReportWriter.read(dir.resolve("runs/2026-01-02_000000/report.json")).baseline);
        assertTrue(Files.readString(dir.resolve("runs/2026-01-02_000000/report.html")).contains("Fix these first"));
    }

    @Test
    void captureNoneStillAuditsTheHost(@TempDir Path dir) throws Exception {
        Run r = run("audit", "--fixture", "samples/fixtures/host-hardened.json", "--capture", "none", "--no-open", "--no-baseline",
                "--out", dir.toString());
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains("Capture disabled"));
        assertTrue(r.out().contains("untested"));
    }

    @Test
    void keepRunsDeletesOnlyOldRunsGainsayMade(@TempDir Path dir) throws Exception {
        Path runs = dir.resolve("runs");
        for (String name : List.of("2026-01-01_000000", "2026-01-02_000000", "2026-01-03_000000")) {
            Files.createDirectories(runs.resolve(name));
            Files.writeString(runs.resolve(name).resolve("report.json"), "{}");
        }
        Files.createDirectories(runs.resolve("my-notes"));
        Files.writeString(runs.resolve("my-notes/report.json"), "{}");
        Files.createDirectories(runs.resolve("2025-12-31_000000"));                       // no report.json: not a finished run
        Files.createDirectories(runs.resolve("2025-12-30_000000/sub"));
        Files.writeString(runs.resolve("2025-12-30_000000/report.json"), "{}");          // has a subfolder: left alone

        assertEquals(1, AuditCommand.pruneRuns(runs, 2));
        assertFalse(Files.exists(runs.resolve("2026-01-01_000000")));
        assertTrue(Files.exists(runs.resolve("2026-01-02_000000")));
        assertTrue(Files.exists(runs.resolve("2026-01-03_000000")));
        assertTrue(Files.exists(runs.resolve("my-notes")));
        assertTrue(Files.exists(runs.resolve("2025-12-31_000000")));
        assertTrue(Files.exists(runs.resolve("2025-12-30_000000/sub")));
        assertEquals(0, AuditCommand.pruneRuns(dir.resolve("missing"), 1));
    }

    @Test
    void badOptionsAreUsageErrors() {
        assertEquals(2, run("audit", "--capture", "carrier-pigeon", "--no-open").code());
        assertEquals(2, run("audit", "--seconds", "1", "--no-open").code());
    }

    @Test
    void explainTeachesOneCheck() {
        Run r = run("explain", "host-cred-004");
        assertEquals(0, r.code());
        assertTrue(r.out().contains("LmCompatibilityLevel"));
        assertTrue(r.out().contains("Fix command"));
        assertEquals(0, run("explain", "NET-SMB-001").code());
        Run trial = run("explain", "TRIAL-TLS-SRV");
        assertTrue(trial.out().contains("own TLS library"));
        Run unknown = run("explain", "HOST-CRED");
        assertEquals(2, unknown.code());
        assertTrue(unknown.out().contains("Did you mean"));
    }

    @Test
    void initWritesAnEditableConfigOnce(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("gainsay.json");
        assertEquals(0, run("init", "--file", f.toString()).code());
        GainsayConfig c = GainsayConfig.load(f);
        assertFalse(c.segments.isEmpty());
        assertEquals(2, run("init", "--file", f.toString()).code(), "does not overwrite without --force");
    }
}
