package dev.gainsay.host.source;

import dev.gainsay.core.HostIdentity;

import java.time.Instant;

/**
 * The only way host checks touch the system. Implementations:
 * <ul>
 *   <li>{@link WindowsHostDataSource}: live, read-only reads via an allow-list of PowerShell
 *       queries (registry, CIM/WMI, cmdlets).</li>
 *   <li>{@link FixtureHostDataSource}: a recorded JSON snapshot, so every check is testable on any OS.</li>
 * </ul>
 * Both serve the same {@link HostSnapshot} shape, which is also what {@code --save-snapshot} writes.
 */
public interface HostDataSource {

    /**
     * Reads one registry value.
     *
     * @param key  full key in {@code reg.exe} form, e.g. {@code HKLM\SYSTEM\CurrentControlSet\Control\Lsa}
     * @param name value name
     */
    RegistryValue registry(String key, String name);

    /** Runs (or replays) one allow-listed query by id; see {@link WindowsQueries}. */
    QueryResult query(String queryId);

    HostIdentity identity();

    /** When the data was collected; checks use this as "now" so fixture results are reproducible. */
    Instant collectedAt();

    boolean elevated();

    /** OS caption and build, for the report header. */
    String os();

    /** "live" or the fixture path. */
    String sourceLabel();
}
