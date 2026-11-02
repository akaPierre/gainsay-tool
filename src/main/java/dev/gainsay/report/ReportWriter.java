package dev.gainsay.report;

import dev.gainsay.core.Json;
import dev.gainsay.core.Report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/** Writes the requested formats ({@code json}, {@code md}, {@code html}) into an output directory. */
public final class ReportWriter {

    private ReportWriter() {
    }

    public static List<Path> write(Report report, Path outDir, Collection<String> formats) throws IOException {
        Files.createDirectories(outDir);
        List<Path> written = new ArrayList<>();
        for (String raw : formats) {
            String fmt = raw.trim().toLowerCase(Locale.ROOT);
            Path p;
            switch (fmt) {
                case "json" -> {
                    p = outDir.resolve("report.json");
                    Json.MAPPER.writeValue(p.toFile(), report);
                }
                case "md", "markdown" -> {
                    p = outDir.resolve("report.md");
                    Files.writeString(p, MarkdownReportWriter.render(report), StandardCharsets.UTF_8);
                }
                case "html" -> {
                    p = outDir.resolve("report.html");
                    Files.writeString(p, HtmlReportWriter.render(report), StandardCharsets.UTF_8);
                }
                default -> throw new IllegalArgumentException("Unknown format: " + raw + " (use json, md, html)");
            }
            written.add(p);
        }
        return written;
    }

    public static Report read(Path file) throws IOException {
        Report r = Json.MAPPER.readValue(file.toFile(), Report.class);
        if (r.schema == null || !r.schema.startsWith("gainsay.report/")) {
            throw new IOException(file + " is not a Gainsay report (schema " + r.schema + ")");
        }
        return r;
    }
}
