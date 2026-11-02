package dev.gainsay.cli;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.net.synth.Scenarios;
import dev.gainsay.report.ReportWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Brief requirement: a synthetic pcap with cleartext HTTP, Telnet, an SMB1 negotiate and a TLS 1.0
 * hello, run through {@code gainsay net --pcap}, must produce those findings with redacted evidence.
 */
class NetIntegrationTest {

    @Test
    void netCommandReportsTheFourClassicsWithRedactedEvidence(@TempDir Path dir) throws Exception {
        Path pcap = Scenarios.brief().write(dir.resolve("synthetic.pcap"));
        Path out = dir.resolve("out");
        int code = Main.commandLine().execute("net", "--pcap", pcap.toString(), "--out", out.toString());
        assertEquals(0, code);

        Report r = ReportWriter.read(out.resolve("report.json"));
        Map<String, Status> worst = r.findings.stream().collect(Collectors.toMap(Finding::id, Finding::status,
                (a, b) -> a.badness() >= b.badness() ? a : b));
        assertEquals(Status.FAIL, worst.get("NET-HTTP-001"));
        assertEquals(Status.FAIL, worst.get("NET-HTTP-002"));
        assertEquals(Status.FAIL, worst.get("NET-LEGACY-001"));
        assertEquals(Status.FAIL, worst.get("NET-SMB-001"));
        assertEquals(Status.FAIL, worst.get("NET-TLS-001"));
        assertEquals(1, r.captures.size());
        assertEquals(0, r.captures.get(0).malformed());

        Finding http = r.findings.stream().filter(f -> f.id().equals("NET-HTTP-002")).findFirst().orElseThrow();
        assertTrue(http.evidence().get(0).detail().contains("****"));
        assertTrue(http.evidence().get(0).reproduce().startsWith("tshark -r synthetic.pcap -Y"));

        for (String file : new String[]{"report.json", "report.md", "report.html"}) {
            String text = Files.readString(out.resolve(file));
            assertFalse(text.contains(Scenarios.PASSWORD), file + " leaks the password");
            assertFalse(text.contains("YWxpY2U6aHVudGVyMg=="), file + " leaks the Basic credential");
            assertFalse(text.contains("0123456789abcdef"), file + " leaks the session cookie");
            assertFalse(text.contains("letmein"), file + " leaks the Telnet password");
        }
        String html = Files.readString(out.resolve("report.html"));
        assertTrue(html.contains("default-src 'none'"));
        assertFalse(html.contains("<script"));
    }

    @Test
    void usageErrorsExitWithTwo(@TempDir Path dir) {
        assertEquals(2, Main.commandLine().execute("net"));
        assertEquals(2, Main.commandLine().execute("net", "--pcap", "a.pcap", "--iface", "eth0"));
    }

    @Test
    void runtimeErrorsExitWithThree(@TempDir Path dir) throws Exception {
        Path notPcap = Files.writeString(dir.resolve("x.pcap"), "definitely not a capture");
        assertEquals(3, Main.commandLine().execute("net", "--pcap", notPcap.toString(), "--out", dir.resolve("o").toString()));
    }

    @Test
    void failOnReturnsOne(@TempDir Path dir) throws Exception {
        Path pcap = Scenarios.brief().write(dir.resolve("s.pcap"));
        assertEquals(1, Main.commandLine().execute("net", "--pcap", pcap.toString(), "--out", dir.resolve("o").toString(), "--fail-on", "high"));
    }
}
