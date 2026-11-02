package dev.gainsay.report;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportWritersTest {

    static Report sample() {
        Report r = new Report();
        r.kinds.add("net");
        r.findings.add(Finding.builder("NET-HTTP-001", Plane.NET).category("Cleartext").title("<script>alert(1)</script>")
                .severity(Severity.HIGH).status(Status.FAIL).subject("10.0.0.1:80")
                .summary("GET /a|b `x` <img src=x onerror=alert(1)>")
                .evidence(new Evidence("packet", "10.0.0.2 -> 10.0.0.1:80", "Authorization: Basic dXNlcjpwYXNz", "tshark -Y http"))
                .rationale("why").howVerified("how").remediation("fix").build());
        r.findings.add(Finding.builder("HOST-X", Plane.HOST).category("Cat").title("cannot run").severity(Severity.MEDIUM)
                .status(Status.UNKNOWN).summary("Could not run: denied").build());
        return ReportComposer.compose(List.of(r), null);
    }

    @Test
    void htmlIsSelfContainedEscapedAndOffline() {
        String html = HtmlReportWriter.render(sample());
        assertTrue(html.contains("Content-Security-Policy"));
        assertTrue(html.contains("default-src 'none'"));
        assertFalse(html.contains("<script>"), "untrusted text must be escaped");
        assertFalse(html.contains("<img"), "untrusted text must be escaped");
        assertFalse(html.matches("(?s).*(src|href)=\"https?:.*"), "no external resources");
        assertFalse(html.contains("dXNlcjpwYXNz"), "credentials redacted");
        assertTrue(html.contains("Appendix: checks that could not run"));
    }

    @Test
    void markdownEscapesTablesAndHtml() {
        String md = MarkdownReportWriter.render(sample());
        assertFalse(md.contains("<script>"));
        assertTrue(md.contains("&lt;script&gt;"));
        assertTrue(md.contains("\\|"), "pipes escaped");
        assertTrue(md.contains("## Top risks"));
    }

    @Test
    void jsonRoundTripsAndKeepsSchema(@TempDir Path dir) throws Exception {
        Report r = sample();
        ReportWriter.write(r, dir, List.of("json", "md", "html"));
        assertTrue(Files.exists(dir.resolve("report.md")));
        assertTrue(Files.exists(dir.resolve("report.html")));
        Report back = ReportWriter.read(dir.resolve("report.json"));
        assertEquals(Report.SCHEMA, back.schema);
        assertEquals(r.findings.size(), back.findings.size());
        assertEquals(r.score.score(), back.score.score());
    }

    @Test
    void baselineShowsRegressionsAndImprovements() {
        Report before = sample();
        Report after = new Report();
        after.findings.add(Finding.builder("NET-HTTP-001", Plane.NET).category("Cleartext").title("t").severity(Severity.HIGH)
                .status(Status.PASS).subject("10.0.0.1:80").build());
        after.findings.add(Finding.builder("HOST-NEW", Plane.HOST).category("Cat").title("new").severity(Severity.LOW)
                .status(Status.FAIL).build());
        Report composed = ReportComposer.compose(List.of(after), before);
        assertEquals(1, composed.baseline.improved().size());
        assertEquals(1, composed.baseline.appeared().size());
    }
}
