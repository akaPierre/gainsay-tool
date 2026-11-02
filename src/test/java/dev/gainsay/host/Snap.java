package dev.gainsay.host;

import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.TextNode;
import dev.gainsay.core.HostIdentity;
import dev.gainsay.core.Json;
import dev.gainsay.host.source.HostSnapshot;
import dev.gainsay.host.source.QueryResult;
import dev.gainsay.host.source.ReadState;
import dev.gainsay.host.source.RegistryValue;
import dev.gainsay.host.source.SnapshotHostDataSource;

import java.time.Instant;
import java.util.List;

/**
 * Test builder for host snapshots. Unset registry values read as ABSENT (so each test only states
 * what matters); unset queries read as ERROR.
 */
public final class Snap {

    final HostSnapshot s = new HostSnapshot();

    public Snap() {
        s.collectedAt = Instant.parse("2026-10-30T10:00:00Z");
        s.identity = new HostIdentity("TEST", List.of("10.0.0.9"), List.of("aa:bb:cc:dd:ee:ff"));
        s.os = "Windows (test)";
    }

    public Snap dword(String key, String name, long value) {
        s.registry.put(HostSnapshot.registryKey(key, name), new RegistryValue(ReadState.OK, "DWord",
                value > Integer.MAX_VALUE ? LongNode.valueOf(value) : IntNode.valueOf((int) value), null));
        return this;
    }

    public Snap string(String key, String name, String value) {
        s.registry.put(HostSnapshot.registryKey(key, name), new RegistryValue(ReadState.OK, "String", TextNode.valueOf(value), null));
        return this;
    }

    public Snap regError(String key, String name) {
        s.registry.put(HostSnapshot.registryKey(key, name), RegistryValue.error("Access is denied"));
        return this;
    }

    public Snap query(String id, String jsonRows) {
        try {
            s.queries.put(id, new QueryResult(ReadState.OK, Json.MAPPER.readTree(jsonRows), null, false));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
        return this;
    }

    public Snap queryError(String id, boolean denied) {
        s.queries.put(id, QueryResult.error("Access denied", denied));
        return this;
    }

    public Snap build(int build, String caption) {
        return query("os.info", "[{\"Caption\":\"" + caption + "\",\"BuildNumber\":\"" + build + "\",\"ProductType\":1}]");
    }

    public SnapshotHostDataSource ds() {
        return new TestDs(s);
    }

    static final class TestDs extends SnapshotHostDataSource {
        TestDs(HostSnapshot s) {
            super(s, "test");
        }

        @Override
        public RegistryValue registry(String key, String name) {
            RegistryValue v = snapshot.registry.get(HostSnapshot.registryKey(key, name));
            return v == null ? RegistryValue.absent() : v;
        }
    }
}
