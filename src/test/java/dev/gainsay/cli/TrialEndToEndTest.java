package dev.gainsay.cli;

import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.core.verdict.Verdict;
import dev.gainsay.core.verdict.VerdictKind;
import dev.gainsay.net.synth.Scenarios;
import dev.gainsay.report.ReportWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The signature concept end to end: two host snapshots testify, a capture provides evidence, and the
 * trial finds that WS-HARDENED's SMB1 and legacy-TLS claims are contradicted on the wire, names the
 * peers that depend on the weak behaviour, corroborates what it can and reports coverage honestly.
 */
class TrialEndToEndTest {

    @TempDir
    static Path dir;
    static Path hardened, legacy, pcap;

    @BeforeAll
    static void testify() throws Exception {
        assertEquals(0, Main.commandLine().execute("host", "--fixture", "samples/fixtures/host-hardened.json", "--format", "json",
                "--out", dir.resolve("h1").toString()));
        assertEquals(0, Main.commandLine().execute("host", "--fixture", "samples/fixtures/host-unhardened.json", "--format", "json",
                "--out", dir.resolve("h2").toString()));
        hardened = dir.resolve("h1/report.json");
        legacy = dir.resolve("h2/report.json");
        pcap = Scenarios.demo().write(dir.resolve("demo.pcap"));
    }

    static Optional<Verdict> verdict(Report r, ClaimType t, String host) {
        return r.verdicts.stream().filter(v -> v.claimType() == t && v.hostLabel().equals(host)).findFirst();
    }

    @Test
    void netWithClaimsPutsTestimonyOnTrial() throws Exception {
        Path out = dir.resolve("trial1");
        assertEquals(0, Main.commandLine().execute("net", "--pcap", pcap.toString(), "--claims-from", hardened + "," + legacy,
                "--out", out.toString()));
        Report r = ReportWriter.read(out.resolve("report.json"));
        assertTrue(r.kinds.contains("trial"));

        Verdict smb1 = verdict(r, ClaimType.SMB1_SERVER_DISABLED, "WS-HARDENED").orElseThrow();
        assertEquals(VerdictKind.CONTRADICTED, smb1.kind());
        assertTrue(smb1.dependants().contains(Scenarios.SCANNER_IP), "the SMB1-only scanner is the blast radius");
        assertEquals("ip", smb1.matchedBy());

        Verdict tls = verdict(r, ClaimType.TLS_LEGACY_SERVER_DISABLED, "WS-HARDENED").orElseThrow();
        assertEquals(VerdictKind.CONTRADICTED, tls.kind());
        assertTrue(tls.dependants().contains(Scenarios.LEGACY_IP));
        assertTrue(tls.explanation().contains("own TLS library"), "explains SCHANNEL vs application TLS stacks");

        assertEquals(VerdictKind.CORROBORATED, verdict(r, ClaimType.LLMNR_DISABLED, "WS-HARDENED").orElseThrow().kind());
        assertEquals(VerdictKind.CORROBORATED, verdict(r, ClaimType.RDP_DISABLED, "WS-HARDENED").orElseThrow().kind());
        assertEquals(VerdictKind.UNTESTED, verdict(r, ClaimType.WINRM_NOT_EXPOSED, "WS-HARDENED").orElseThrow().kind());

        // the legacy host's weak settings are confirmed live
        for (ClaimType t : new ClaimType[]{ClaimType.LLMNR_DISABLED, ClaimType.RDP_NLA_REQUIRED, ClaimType.NTLMV1_DISABLED,
                ClaimType.SMB_SERVER_SIGNING_REQUIRED}) {
            Verdict v = verdict(r, t, "WS-LEGACY").orElseThrow(() -> new AssertionError("no verdict for " + t));
            assertEquals(VerdictKind.CORROBORATED, v.kind(), t.name());
            assertFalse(v.claim().secure());
        }

        // contradictions rank first and become FAIL findings
        assertEquals(VerdictKind.CONTRADICTED, r.verdicts.get(0).kind());
        assertTrue(r.findings.stream().anyMatch(f -> f.id().equals("TRIAL-SMB1-SRV") && f.status() == Status.FAIL));
        assertTrue(r.trial.contradicted() >= 2);
        assertTrue(r.trial.coverage() > 0 && r.trial.coverage() < 1, "coverage is honest: some claims stay untested");
        assertTrue(r.trial.warnings().isEmpty(), "snapshot and capture are close in time");

        String md = Files.readString(out.resolve("report.md"));
        assertTrue(md.indexOf("## Testimony vs evidence") < md.indexOf("## Score and coverage"), "the trial leads the report");
        assertTrue(md.contains("Trial coverage:"));
        String html = Files.readString(out.resolve("report.html"));
        assertTrue(html.contains("CONTRADICTED"));
    }

    @Test
    void trialAndReportCommandsGiveTheSameVerdicts() throws Exception {
        Path netOnly = dir.resolve("net");
        assertEquals(0, Main.commandLine().execute("net", "--pcap", pcap.toString(), "--format", "json", "--out", netOnly.toString()));
        Path t = dir.resolve("trial2");
        assertEquals(0, Main.commandLine().execute("trial", "--host", hardened.toString(), "--net", netOnly.resolve("report.json").toString(),
                "--out", t.toString(), "--format", "json"));
        Path m = dir.resolve("merged");
        assertEquals(0, Main.commandLine().execute("report", "--inputs", hardened + "," + netOnly.resolve("report.json"),
                "--out", m.toString(), "--format", "json"));
        Report a = ReportWriter.read(t.resolve("report.json"));
        Report b = ReportWriter.read(m.resolve("report.json"));
        assertEquals(a.trial.contradicted(), b.trial.contradicted());
        assertEquals(a.verdicts.size(), b.verdicts.size());
        assertTrue(a.verdicts.stream().anyMatch(v -> v.kind() == VerdictKind.UNCLAIMED), "unaudited WS-LEGACY behaviour is unclaimed");
    }

    @Test
    void baselineShowsWhatChanged() throws Exception {
        Path out = dir.resolve("withBaseline");
        assertEquals(0, Main.commandLine().execute("report", "--inputs", hardened.toString(), "--baseline", legacy.toString(),
                "--out", out.toString(), "--format", "json,md"));
        Report r = ReportWriter.read(out.resolve("report.json"));
        assertNotNull(r.baseline);
        assertFalse(r.baseline.improved().isEmpty() && r.baseline.disappeared().isEmpty());
        assertTrue(Files.readString(out.resolve("report.md")).contains("## Compared with baseline"));
    }
}
