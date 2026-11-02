package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.HostPolicy.BuildEntry;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * HOST-PATCH-001. Implementation: WMI {@code Win32_OperatingSystem.BuildNumber} and {@code Caption},
 * looked up in the local, user-editable lifecycle table {@code windows-builds.txt}. The edition matters:
 * the same build (e.g. 19044) is out of support as Windows 10 Pro but supported as LTSC.
 */
public final class SupportedBuildCheck extends AbstractCheck {

    private final List<BuildEntry> builds;

    public SupportedBuildCheck(HostPolicy policy) {
        super("HOST-PATCH-001", "The Windows build still receives security updates", Categories.PATCHING, Severity.HIGH,
                "Once a build leaves servicing, newly found vulnerabilities in it are never fixed, so every later patch Tuesday widens the gap.",
                "Read BuildNumber and Caption from Win32_OperatingSystem and looked up the end-of-servicing date in the local lifecycle table.",
                "Upgrade to a supported feature update (Settings > Windows Update) or enrol in Extended Security Updates where available.",
                List.of("https://learn.microsoft.com/lifecycle/products/"));
        this.builds = policy.windowsBuilds();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("os.info");
        if (!q.ok() || q.first() == null) {
            return unknown(ds, q.ok() ? "Win32_OperatingSystem returned nothing" : reason(q), List.of());
        }
        JsonNode os = q.first();
        String caption = os.path("Caption").asText("");
        int build = os.path("BuildNumber").asInt(-1);
        Evidence ev = queryEvidence("os.info", "Caption=\"" + caption + "\", BuildNumber=" + build,
                "Get-CimInstance Win32_OperatingSystem | Select Caption, BuildNumber");
        BuildEntry match = builds.stream().filter(b -> b.matches(build, caption)).findFirst().orElse(null);
        if (match == null) {
            return unknown(ds, "build " + build + " (" + caption + ") is not in the local lifecycle table; add it to windows-builds.txt", List.of(ev));
        }
        LocalDate today = ds.collectedAt().atZone(ZoneOffset.UTC).toLocalDate();
        long days = ChronoUnit.DAYS.between(today, match.endOfServicing());
        String what = match.name() + ", end of servicing " + match.endOfServicing();
        if (days < 0) {
            return fail(ds, what + " — out of support for " + (-days) + " days.", List.of(ev));
        }
        if (days <= 90) {
            return warn(ds, what + " — support ends in " + days + " days.", List.of(ev));
        }
        return pass(ds, what + ".", List.of(ev));
    }
}
