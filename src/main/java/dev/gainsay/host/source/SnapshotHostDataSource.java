package dev.gainsay.host.source;

import dev.gainsay.core.HostIdentity;

import java.time.Instant;

/** A {@link HostDataSource} that serves reads from a {@link HostSnapshot}. */
public class SnapshotHostDataSource implements HostDataSource {

    protected final HostSnapshot snapshot;
    private final String label;

    protected SnapshotHostDataSource(HostSnapshot snapshot, String label) {
        this.snapshot = snapshot;
        this.label = label;
    }

    @Override
    public RegistryValue registry(String key, String name) {
        RegistryValue v = snapshot.registry.get(HostSnapshot.registryKey(key, name));
        return v != null ? v : RegistryValue.error("value was not collected in this snapshot");
    }

    @Override
    public QueryResult query(String queryId) {
        QueryResult q = snapshot.queries.get(queryId);
        return q != null ? q : QueryResult.error("query '" + queryId + "' was not collected in this snapshot", false);
    }

    @Override
    public HostIdentity identity() {
        return snapshot.identity;
    }

    @Override
    public Instant collectedAt() {
        return snapshot.collectedAt != null ? snapshot.collectedAt : Instant.now();
    }

    @Override
    public boolean elevated() {
        return snapshot.elevated;
    }

    @Override
    public String os() {
        return snapshot.os;
    }

    @Override
    public String sourceLabel() {
        return label;
    }

    public HostSnapshot snapshot() {
        return snapshot;
    }
}
