package dev.gainsay.host;

import dev.gainsay.host.HostPolicy.BuildEntry;
import dev.gainsay.host.HostPolicy.EolEntry;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads the pipe-separated local lists. Defaults ship inside the jar
 * ({@code gainsay/eol-software.txt}, {@code gainsay/windows-builds.txt}); users pass their own copies
 * with {@code --eol-list} / {@code --builds-list}. Lines starting with '#' are comments.
 */
public final class LocalLists {

    static final int MAX_LINES = 10_000;

    private LocalLists() {
    }

    public static List<EolEntry> defaultEol() {
        return parseEol(resourceLines("/gainsay/eol-software.txt"));
    }

    public static List<BuildEntry> defaultBuilds() {
        return parseBuilds(resourceLines("/gainsay/windows-builds.txt"));
    }

    public static List<EolEntry> loadEol(Path p) throws IOException {
        return parseEol(fileLines(p));
    }

    public static List<BuildEntry> loadBuilds(Path p) throws IOException {
        return parseBuilds(fileLines(p));
    }

    static List<EolEntry> parseEol(List<String> lines) {
        List<EolEntry> out = new ArrayList<>();
        for (String line : lines) {
            String[] f = fields(line, 3);
            if (f != null && !f[0].isEmpty()) {
                out.add(new EolEntry(f[0], f[1], f[2]));
            }
        }
        return out;
    }

    static List<BuildEntry> parseBuilds(List<String> lines) {
        List<BuildEntry> out = new ArrayList<>();
        for (String line : lines) {
            String[] f = fields(line, 4);
            if (f == null) {
                continue;
            }
            try {
                out.add(new BuildEntry(Integer.parseInt(f[0]), f[1], f[2], LocalDate.parse(f[3])));
            } catch (NumberFormatException | DateTimeParseException e) {
                // malformed line in a user-edited file: skip it rather than abort the audit
            }
        }
        return out;
    }

    private static String[] fields(String line, int n) {
        String t = line.strip();
        if (t.isEmpty() || t.startsWith("#")) {
            return null;
        }
        String[] parts = t.split("\\|", -1);
        if (parts.length < n) {
            return null;
        }
        String[] out = new String[n];
        for (int i = 0; i < n; i++) {
            out[i] = parts[i].strip();
        }
        return out;
    }

    private static List<String> resourceLines(String name) {
        try (InputStream in = LocalLists.class.getResourceAsStream(name)) {
            if (in == null) {
                return List.of();
            }
            return read(new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<String> fileLines(Path p) throws IOException {
        try (BufferedReader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
            return read(r);
        }
    }

    private static List<String> read(BufferedReader r) throws IOException {
        List<String> lines = new ArrayList<>();
        String l;
        while ((l = r.readLine()) != null && lines.size() < MAX_LINES) {
            lines.add(l.length() > 1000 ? l.substring(0, 1000) : l);
        }
        return lines;
    }
}
