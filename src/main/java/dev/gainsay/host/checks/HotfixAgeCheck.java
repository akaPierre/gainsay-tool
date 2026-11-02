package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * HOST-PATCH-002. Implementation: {@code Get-HotFix} (WMI {@code Win32_QuickFixEngineering}), newest
 * {@code InstalledOn}. QFE lists cumulative updates and servicing-stack updates; it does not list
 * Store/Defender updates, which is fine for this purpose.
 */
public final class HotfixAgeCheck extends AbstractCheck {

    private final int maxDays;

    public HotfixAgeCheck(HostPolicy policy) {
        super("HOST-PATCH-002", "Security updates were installed recently", Categories.PATCHING, Severity.HIGH,
                "Microsoft ships cumulative security updates monthly. A machine whose newest update is months old is missing fixes for "
                        + "vulnerabilities that are already public.",
                "Took the most recent InstalledOn date from Get-HotFix.",
                "Run Windows Update and install the latest cumulative update; investigate why updates stalled (paused, WSUS, disk space).",
                List.of("https://learn.microsoft.com/windows/deployment/update/"));
        this.maxDays = policy.maxHotfixAgeDays();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("hotfixes");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        LocalDate newest = null;
        String newestId = null;
        for (JsonNode h : q.list()) {
            String d = h.path("InstalledOn").asText("");
            try {
                LocalDate date = LocalDate.parse(d);
                if (newest == null || date.isAfter(newest)) {
                    newest = date;
                    newestId = h.path("HotFixID").asText("?");
                }
            } catch (DateTimeParseException e) {
                // some QFE rows have no date; ignore them
            }
        }
        if (newest == null) {
            return unknown(ds, "no hotfix with an installation date was listed", List.of());
        }
        long age = ChronoUnit.DAYS.between(newest, ds.collectedAt().atZone(ZoneOffset.UTC).toLocalDate());
        Evidence ev = queryEvidence("hotfixes", "newest: " + newestId + " installed " + newest + " (" + age + " days ago)",
                "Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 3");
        if (age <= maxDays) {
            return pass(ds, "Latest update " + newestId + " was installed " + age + " days ago.", List.of(ev));
        }
        if (age <= 2L * maxDays) {
            return warn(ds, "Latest update was installed " + age + " days ago (threshold " + maxDays + ").", List.of(ev));
        }
        return fail(ds, "No update installed for " + age + " days.", List.of(ev));
    }
}
