package dev.gainsay.host;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.verdict.ClaimStrength;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.ReadState;
import dev.gainsay.host.source.RegistryValue;

import java.util.ArrayList;
import java.util.List;

/**
 * A Windows setting that may live in several registry locations, in precedence order.
 *
 * <p>This models a key lesson of Windows hardening: Group Policy writes under
 * {@code HKLM\SOFTWARE\Policies\...} and wins over the "preference" value elsewhere; if neither is
 * present the OS default applies, and the default can differ between builds. Every location is read
 * (so evidence shows the full picture) and the first one present wins.
 */
public final class RegistrySetting {

    /** One place the value can live. */
    public record Location(String key, String name, ClaimStrength strength) {
    }

    /** The effective value and where it came from. */
    public record Resolved(Long value, String text, ClaimStrength origin, Location location, boolean error,
                           String errorReason, List<Evidence> evidence) {

        public boolean fromDefault() {
            return origin == ClaimStrength.DEFAULT;
        }

        /** Where the effective value came from, for claims and summaries. */
        public String basis() {
            return location == null ? "OS default (not configured)" : location.key() + "\\" + location.name();
        }
    }

    private final List<Location> locations;
    private final Long defaultValue;

    private RegistrySetting(List<Location> locations, Long defaultValue) {
        this.locations = locations;
        this.defaultValue = defaultValue;
    }

    public static RegistrySetting of(Long defaultValue, Location... locations) {
        return new RegistrySetting(List.of(locations), defaultValue);
    }

    public static Location policy(String key, String name) {
        return new Location(key, name, ClaimStrength.POLICY);
    }

    public static Location local(String key, String name) {
        return new Location(key, name, ClaimStrength.LOCAL);
    }

    public Resolved resolve(HostDataSource ds) {
        List<Evidence> evidence = new ArrayList<>();
        Resolved winner = null;
        String firstError = null;
        for (Location loc : locations) {
            RegistryValue v = ds.registry(loc.key(), loc.name());
            evidence.add(evidence(loc, v));
            if (winner != null) {
                continue;
            }
            if (v.state() == ReadState.OK) {
                winner = new Resolved(v.asLong(), v.asText(), loc.strength(), loc, false, null, evidence);
            } else if (v.state() == ReadState.ERROR && firstError == null) {
                firstError = v.reason();
            }
        }
        if (winner != null) {
            return winner;
        }
        if (firstError != null) {
            return new Resolved(null, null, null, null, true, firstError, evidence);
        }
        return new Resolved(defaultValue, defaultValue == null ? null : String.valueOf(defaultValue),
                ClaimStrength.DEFAULT, null, false, null, evidence);
    }

    static Evidence evidence(Location loc, RegistryValue v) {
        String psPath = "HKLM:" + loc.key().substring(loc.key().indexOf('\\'));
        return new Evidence("registry", loc.key(), loc.name() + " = " + v.display(),
                "Get-ItemPropertyValue -LiteralPath '" + psPath + "' -Name " + quoteName(loc.name())
                        + "   # or: reg query \"" + loc.key() + "\" /v " + quoteName(loc.name()));
    }

    private static String quoteName(String n) {
        return n.contains(" ") ? "'" + n + "'" : n;
    }
}
