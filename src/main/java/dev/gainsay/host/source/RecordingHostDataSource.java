package dev.gainsay.host.source;

import dev.gainsay.core.HostIdentity;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Dry-run data source: answers every read with ERROR while remembering what was asked. Running all
 * checks against it once yields the exact set of registry values and queries to collect, so the live
 * collector reads everything in a few batched PowerShell calls and checks never declare reads twice.
 */
final class RecordingHostDataSource implements HostDataSource {

    final Set<String> registryKeys = new LinkedHashSet<>();
    final Set<String> queryIds = new LinkedHashSet<>();

    @Override
    public RegistryValue registry(String key, String name) {
        registryKeys.add(HostSnapshot.registryKey(key, name));
        return RegistryValue.error("recording");
    }

    @Override
    public QueryResult query(String queryId) {
        queryIds.add(queryId);
        return QueryResult.error("recording", false);
    }

    @Override
    public HostIdentity identity() {
        return new HostIdentity("", null, null);
    }

    @Override
    public Instant collectedAt() {
        return Instant.now();
    }

    @Override
    public boolean elevated() {
        return false;
    }

    @Override
    public String os() {
        return "";
    }

    @Override
    public String sourceLabel() {
        return "recording";
    }
}
