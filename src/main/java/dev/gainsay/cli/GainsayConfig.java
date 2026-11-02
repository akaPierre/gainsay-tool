package dev.gainsay.cli;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dev.gainsay.core.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Optional settings file ({@code gainsay.json} in the working directory, or {@code --config FILE}) so that
 * everyday use needs no long command lines. Command-line options always win over the file.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class GainsayConfig {

    public static final String DEFAULT_FILE = "gainsay.json";

    /** Where {@code audit} keeps its runs (one timestamped folder per run). */
    public String runsDir = "gainsay-runs";
    /** Keep only the newest N runs in {@link #runsDir}; 0 keeps all. */
    public int keepRuns = 0;
    /** auto, pktmon, npcap or none. */
    public String capture = "auto";
    public int captureSeconds = 60;
    /** Capture interface for npcap/libpcap; empty = pick the interface that carries this host's address. */
    public String iface = "";
    /** Named segments: name → list of CIDRs. */
    public Map<String, List<String>> segments = new LinkedHashMap<>();
    public List<String> expectedResolvers = List.of();
    public Integer maxSignatureAgeDays;
    public Integer maxHotfixAgeDays;
    public String eolList;
    public String buildsList;
    public boolean openReport = true;
    /** Look up a random non-existent name during capture so LLMNR/NetBIOS claims can be tested. */
    public boolean exercise = false;

    public static GainsayConfig load(Path explicit) throws IOException {
        Path p = explicit != null ? explicit : Path.of(DEFAULT_FILE);
        if (!Files.exists(p)) {
            if (explicit != null) {
                throw new IOException("config file not found: " + explicit);
            }
            return new GainsayConfig();
        }
        if (Files.size(p) > 1_000_000) {
            throw new IOException("config file too large: " + p);
        }
        return Json.MAPPER.readValue(p.toFile(), GainsayConfig.class);
    }

    /** A starting point written by {@code gainsay init}. */
    public static GainsayConfig example() {
        GainsayConfig c = new GainsayConfig();
        c.segments.put("office", List.of("192.168.1.0/24"));
        c.segments.put("servers", List.of("10.0.10.0/24"));
        c.expectedResolvers = List.of("192.168.1.1");
        c.maxSignatureAgeDays = 3;
        c.maxHotfixAgeDays = 45;
        return c;
    }
}
