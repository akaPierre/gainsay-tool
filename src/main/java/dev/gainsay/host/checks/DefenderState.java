package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

/**
 * Interprets Microsoft Defender's running mode. When another AV registers with Security Center,
 * Defender switches to passive mode ({@code AMRunningMode = "Passive Mode"}) and its own settings
 * stop mattering, so Defender-specific checks become NOT_APPLICABLE rather than failing.
 */
final class DefenderState {

    enum Mode { ACTIVE, PASSIVE_OR_OFF, UNKNOWN }

    private DefenderState() {
    }

    static Mode mode(HostDataSource ds) {
        QueryResult q = ds.query("defender.status");
        if (!q.ok() || q.first() == null) {
            return Mode.UNKNOWN;
        }
        JsonNode s = q.first();
        String running = s.path("AMRunningMode").asText("");
        boolean av = s.path("AntivirusEnabled").asBoolean(false);
        if (!av || running.toLowerCase().contains("passive") || running.toLowerCase().contains("edr")) {
            return Mode.PASSIVE_OR_OFF;
        }
        return Mode.ACTIVE;
    }

    /**
     * Security Center's undocumented-but-stable {@code productState} bitfield (reverse-engineered by the
     * community; Microsoft does not document it): bit 0x1000 = real-time scanning on, bit 0x10 =
     * definitions out of date. E.g. 397568 = 0x061100 → on, up to date; 393472 = 0x060100 → off.
     */
    static boolean productEnabled(long productState) {
        return (productState & 0x1000) != 0;
    }

    static boolean productUpToDate(long productState) {
        return (productState & 0x10) == 0;
    }
}
