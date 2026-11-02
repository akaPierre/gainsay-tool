package dev.gainsay.cli;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;
import dev.gainsay.report.ReportComposer;
import dev.gainsay.report.ReportWriter;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.List;

/** Options shared by every command that writes a report, plus the common "compose, write, exit code" tail. */
public final class OutputOptions {

    @Option(names = "--out", paramLabel = "DIR", description = "Output directory (default: ${DEFAULT-VALUE}).", defaultValue = "out")
    Path out;

    @Option(names = "--format", paramLabel = "FMT", split = ",", description = "Report formats: json, md, html (default: ${DEFAULT-VALUE}).",
            defaultValue = "json,md,html")
    List<String> formats;

    @Option(names = "--fail-on", paramLabel = "SEVERITY", description = "Exit with code 1 if a FAIL finding of at least this severity exists "
            + "(INFO, LOW, MEDIUM, HIGH, CRITICAL).")
    Severity failOn;

    @Option(names = "--baseline", paramLabel = "OLD.json", description = "Previous report.json to compare against.")
    Path baseline;

    /** Composes the inputs, writes the report, prints a short summary and returns the exit code. */
    int finish(List<Report> inputs, PrintWriter out) throws IOException {
        Report base = baseline == null ? null : ReportWriter.read(baseline);
        Report r = ReportComposer.compose(inputs, base);
        List<Path> written = ReportWriter.write(r, this.out, formats);
        printSummary(r, out);
        written.forEach(p -> out.println("  wrote " + p));
        out.flush();
        return exitCode(r);
    }

    int exitCode(Report r) {
        if (failOn == null) {
            return 0;
        }
        for (Finding f : r.findings) {
            if (f.status() == Status.FAIL && f.severity().atLeast(failOn) && f.severity() != Severity.INFO) {
                return 1;
            }
        }
        return 0;
    }

    static void printSummary(Report r, PrintWriter out) {
        Terminal.summary(r, out);
    }
}
