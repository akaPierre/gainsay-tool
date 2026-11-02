package dev.gainsay.host;

import java.time.LocalDate;
import java.util.List;
import java.util.Locale;

/**
 * Tunable thresholds and the two local, user-editable lists (end-of-life software and Windows build
 * lifecycle). No online lookups are ever made.
 */
public record HostPolicy(
        int maxSignatureAgeDays,
        int maxHotfixAgeDays,
        int minPasswordLength,
        int maxLockoutThreshold,
        long minSecurityLogKb,
        List<EolEntry> eolSoftware,
        List<BuildEntry> windowsBuilds) {

    /** {@code pattern | version prefix | reason}: matches when DisplayName contains pattern (case-insensitive). */
    public record EolEntry(String pattern, String versionPrefix, String reason) {
        public boolean matches(String displayName, String version) {
            if (displayName == null || !displayName.toLowerCase(Locale.ROOT).contains(pattern.toLowerCase(Locale.ROOT))) {
                return false;
            }
            return versionPrefix.isEmpty() || (version != null && version.startsWith(versionPrefix));
        }
    }

    /** {@code build | caption contains | name | end of servicing}. */
    public record BuildEntry(int build, String captionContains, String name, LocalDate endOfServicing) {
        public boolean matches(int b, String caption) {
            return build == b && (captionContains.isEmpty()
                    || (caption != null && caption.toLowerCase(Locale.ROOT).contains(captionContains.toLowerCase(Locale.ROOT))));
        }
    }

    public static HostPolicy defaults() {
        return new HostPolicy(3, 45, 14, 10, 196_608, LocalLists.defaultEol(), LocalLists.defaultBuilds());
    }

    public HostPolicy withLists(List<EolEntry> eol, List<BuildEntry> builds) {
        return new HostPolicy(maxSignatureAgeDays, maxHotfixAgeDays, minPasswordLength, maxLockoutThreshold,
                minSecurityLogKb, eol == null ? eolSoftware : eol, builds == null ? windowsBuilds : builds);
    }

    public HostPolicy withAges(Integer signatureDays, Integer hotfixDays) {
        return new HostPolicy(signatureDays == null ? maxSignatureAgeDays : signatureDays,
                hotfixDays == null ? maxHotfixAgeDays : hotfixDays, minPasswordLength, maxLockoutThreshold,
                minSecurityLogKb, eolSoftware, windowsBuilds);
    }
}
