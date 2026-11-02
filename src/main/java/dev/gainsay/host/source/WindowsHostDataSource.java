package dev.gainsay.host.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.gainsay.core.HostIdentity;
import dev.gainsay.core.Json;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;

/**
 * Live, read-only collection on Windows.
 *
 * <ol>
 *   <li>A dry run of all checks against {@link RecordingHostDataSource} lists the reads they need.</li>
 *   <li>Registry values are read in batches by one PowerShell script per batch using
 *       {@code Get-Item -LiteralPath Registry::...} and {@code RegistryKey.GetValue} (read-only APIs).</li>
 *   <li>Each structured query from {@link WindowsQueries} runs in its own PowerShell process with a
 *       timeout; failures (access denied, missing provider) become data, not exceptions.</li>
 * </ol>
 * The result is a {@link HostSnapshot}, which can be saved and replayed as a fixture.
 */
public final class WindowsHostDataSource extends SnapshotHostDataSource {

    static final int REGISTRY_BATCH = 40;
    static final int PARALLEL_QUERIES = 4;

    private WindowsHostDataSource(HostSnapshot snapshot) {
        super(snapshot, "live");
    }

    /** Quick read-only check of whether this process runs elevated (Windows only). */
    public static boolean isElevated() {
        if (!isWindows()) {
            return false;
        }
        QueryResult q = runQuery("elevation", Duration.ofSeconds(30));
        return q.ok() && q.first() != null && q.first().path("Elevated").asBoolean(false);
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    /**
     * Collects a snapshot from the local machine.
     *
     * @param dryRun  runs every check once against the given recording source
     * @param timeout per-process timeout
     */
    public static WindowsHostDataSource collect(Consumer<HostDataSource> dryRun, Duration timeout) {
        if (!isWindows()) {
            throw new IllegalStateException("Live host checks need Windows; use --fixture FILE to audit a recorded snapshot.");
        }
        RecordingHostDataSource rec = new RecordingHostDataSource();
        dryRun.accept(rec);
        // The allow-list is small, so every query is collected (checks may branch before asking for one).
        Set<String> ids = new LinkedHashSet<>(List.of("host.identity", "elevation", "os.info"));
        ids.addAll(WindowsQueries.all().keySet());

        HostSnapshot s = new HostSnapshot();
        s.collectedAt = Instant.now();
        ExecutorService pool = Executors.newFixedThreadPool(PARALLEL_QUERIES);
        try {
            Map<String, Future<QueryResult>> futures = new LinkedHashMap<>();
            for (String id : ids) {
                futures.put(id, pool.submit(() -> runQuery(id, timeout)));
            }
            List<String> keys = new ArrayList<>(rec.registryKeys);
            for (int i = 0; i < keys.size(); i += REGISTRY_BATCH) {
                s.registry.putAll(readRegistry(keys.subList(i, Math.min(keys.size(), i + REGISTRY_BATCH)), timeout));
            }
            for (Map.Entry<String, Future<QueryResult>> e : futures.entrySet()) {
                QueryResult q;
                try {
                    q = e.getValue().get();
                } catch (Exception ex) {
                    q = QueryResult.error("query failed: " + ex.getClass().getSimpleName(), false);
                }
                s.queries.put(e.getKey(), q);
            }
        } finally {
            pool.shutdownNow();
        }
        fillHeader(s);
        return new WindowsHostDataSource(s);
    }

    private static void fillHeader(HostSnapshot s) {
        JsonNode id = s.queries.get("host.identity") == null ? null : s.queries.get("host.identity").first();
        if (id != null) {
            List<String> ips = new ArrayList<>();
            id.path("IPs").forEach(n -> ips.add(n.asText()));
            List<String> macs = new ArrayList<>();
            id.path("MACs").forEach(n -> macs.add(n.asText()));
            s.identity = new HostIdentity(id.path("Hostname").asText(""), ips, macs);
        }
        JsonNode el = s.queries.get("elevation") == null ? null : s.queries.get("elevation").first();
        s.elevated = el != null && el.path("Elevated").asBoolean(false);
        JsonNode os = s.queries.get("os.info") == null ? null : s.queries.get("os.info").first();
        if (os != null) {
            s.os = os.path("Caption").asText("Windows") + " (build " + os.path("BuildNumber").asText("?") + ")";
        }
    }

    static QueryResult runQuery(String id, Duration timeout) {
        String script = WindowsQueries.script(id);
        if (script == null) {
            return QueryResult.error("query '" + id + "' is not on the read-only allow-list", false);
        }
        String wrapped = "try { $r = & { " + script + " }; ConvertTo-Json -InputObject @($r) -Depth 4 -Compress } "
                + "catch { $e = $_.Exception; "
                + "$d = ($e -is [System.UnauthorizedAccessException]) -or ($e.HResult -eq -2147217405) -or ($e.HResult -eq -2147024891) "
                + "-or (\"$($e.NativeErrorCode)\" -eq 'AccessDenied') -or (\"$($e.Message)\" -match 'denied|elevat'); "
                + "ConvertTo-Json -InputObject @{ __error = \"$($e.Message)\"; __denied = [bool]$d } -Compress }";
        try {
            PowerShellRunner.Result r = PowerShellRunner.run(wrapped, timeout);
            if (r.timedOut()) {
                return QueryResult.error(r.stderr(), false);
            }
            return parseQueryOutput(r.stdout(), r.stderr());
        } catch (IOException e) {
            return QueryResult.error("could not start powershell.exe: " + e.getMessage(), false);
        }
    }

    static QueryResult parseQueryOutput(String stdout, String stderr) {
        String out = stdout == null ? "" : stdout.strip();
        if (out.isEmpty()) {
            return QueryResult.error("no output" + (stderr == null || stderr.isBlank() ? "" : ": " + firstLine(stderr)), false);
        }
        try {
            JsonNode n = Json.MAPPER.readTree(out);
            if (n.isObject() && n.has("__error")) {
                return QueryResult.error(n.path("__error").asText("error"), n.path("__denied").asBoolean(false));
            }
            return new QueryResult(ReadState.OK, n.isArray() ? n : Json.MAPPER.createArrayNode().add(n), null, false);
        } catch (IOException e) {
            return QueryResult.error("unparseable output: " + firstLine(out), false);
        }
    }

    static Map<String, RegistryValue> readRegistry(List<String> keys, Duration timeout) {
        StringBuilder specs = new StringBuilder();
        for (String k : keys) {
            if (specs.length() > 0) {
                specs.append(',');
            }
            specs.append('\'').append(k.replace("'", "''")).append('\'');
        }
        String script = "$specs = @(" + specs + "); $out = [ordered]@{}; "
                + "foreach ($s in $specs) { $i = $s.LastIndexOf('|'); $p = 'Registry::' + $s.Substring(0, $i); $n = $s.Substring($i + 1); "
                + "try { if (-not (Test-Path -LiteralPath $p)) { $out[$s] = @{ state = 'ABSENT' }; continue }; "
                + "$k = Get-Item -LiteralPath $p; "
                + "if (-not ($k.GetValueNames() -contains $n)) { $out[$s] = @{ state = 'ABSENT' }; continue }; "
                + "$v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames'); if ($v -is [byte[]]) { $v = [BitConverter]::ToString($v) }; "
                + "$out[$s] = @{ state = 'OK'; type = $k.GetValueKind($n).ToString(); value = $v } } "
                + "catch { $out[$s] = @{ state = 'ERROR'; reason = \"$($_.Exception.Message)\" } } }; "
                + "ConvertTo-Json -InputObject $out -Depth 4 -Compress";
        Map<String, RegistryValue> result = new LinkedHashMap<>();
        try {
            PowerShellRunner.Result r = PowerShellRunner.run(script, timeout);
            JsonNode n = r.timedOut() || r.stdout().isBlank() ? null : Json.MAPPER.readTree(r.stdout().strip());
            for (String k : keys) {
                JsonNode v = n == null ? null : n.get(k);
                result.put(k, v instanceof ObjectNode o ? toValue(o) : RegistryValue.error(
                        r.timedOut() ? "timed out" : "registry batch produced no result for this value"));
            }
        } catch (IOException e) {
            keys.forEach(k -> result.put(k, RegistryValue.error("registry read failed: " + e.getMessage())));
        }
        return result;
    }

    private static RegistryValue toValue(ObjectNode o) {
        return switch (o.path("state").asText()) {
            case "OK" -> new RegistryValue(ReadState.OK, o.path("type").asText(null), o.get("value"), null);
            case "ABSENT" -> RegistryValue.absent();
            default -> RegistryValue.error(o.path("reason").asText("error"));
        };
    }

    private static String firstLine(String s) {
        String t = s.strip();
        int nl = t.indexOf('\n');
        t = nl >= 0 ? t.substring(0, nl) : t;
        return t.length() > 200 ? t.substring(0, 200) : t;
    }
}
