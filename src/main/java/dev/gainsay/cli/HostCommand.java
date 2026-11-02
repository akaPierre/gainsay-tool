package dev.gainsay.cli;

import dev.gainsay.core.Json;
import dev.gainsay.core.Report;
import dev.gainsay.host.Check;
import dev.gainsay.host.HostAuditor;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.LocalLists;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.host.source.FixtureHostDataSource;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.WindowsHostDataSource;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "host", description = "Audit Windows host settings (testimony). Read-only.")
public final class HostCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Mixin
    OutputOptions output;

    @Option(names = "--fixture", paramLabel = "FILE", description = "Audit a recorded host snapshot instead of the live machine.")
    Path fixture;

    @Option(names = "--save-snapshot", paramLabel = "FILE", description = "Also save the live snapshot (no secrets) for later replay with --fixture.")
    Path saveSnapshot;

    @Option(names = "--eol-list", paramLabel = "FILE", description = "Custom end-of-life software list.")
    Path eolList;

    @Option(names = "--builds-list", paramLabel = "FILE", description = "Custom Windows build lifecycle table.")
    Path buildsList;

    @Option(names = "--max-signature-age", paramLabel = "DAYS", description = "AV signature age threshold (default 3).")
    Integer maxSignatureAge;

    @Option(names = "--max-hotfix-age", paramLabel = "DAYS", description = "Newest hotfix age threshold (default 45).")
    Integer maxHotfixAge;

    @Option(names = "--timeout", paramLabel = "SEC", description = "Per-query timeout for live reads (default ${DEFAULT-VALUE}).", defaultValue = "60")
    int timeoutSec;

    @Override
    public Integer call() throws Exception {
        var out = spec.commandLine().getOut();
        var err = spec.commandLine().getErr();
        HostPolicy policy = HostPolicy.defaults()
                .withLists(eolList == null ? null : LocalLists.loadEol(eolList), buildsList == null ? null : LocalLists.loadBuilds(buildsList))
                .withAges(maxSignatureAge, maxHotfixAge);
        List<Check> checks = CheckCatalog.all(policy);
        HostDataSource ds;
        if (fixture != null) {
            ds = FixtureHostDataSource.load(fixture);
        } else if (!WindowsHostDataSource.isWindows()) {
            err.println("Live host checks need Windows (they read the registry, WMI and Windows cmdlets).");
            err.println("On this OS, audit a recorded snapshot instead:  gainsay host --fixture samples/fixtures/host-hardened.json");
            return 2;
        } else {
            err.println("Collecting host data (read-only)...");
            WindowsHostDataSource live = WindowsHostDataSource.collect(rec -> HostAuditor.dryRun(rec, checks), Duration.ofSeconds(timeoutSec));
            if (saveSnapshot != null) {
                Path parent = saveSnapshot.toAbsolutePath().getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Json.MAPPER.writeValue(saveSnapshot.toFile(), live.snapshot());
                err.println("Snapshot saved to " + saveSnapshot);
            }
            ds = live;
        }
        Report r = HostAuditor.audit(ds, checks);
        return output.finish(List.of(r), out);
    }
}
