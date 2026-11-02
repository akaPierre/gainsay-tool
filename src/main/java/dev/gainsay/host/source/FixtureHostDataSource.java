package dev.gainsay.host.source;

import dev.gainsay.core.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Replays a recorded {@link HostSnapshot} JSON file. This is how host checks run on Linux/macOS and
 * in unit tests, and how a snapshot taken on one machine can be audited on another.
 */
public final class FixtureHostDataSource extends SnapshotHostDataSource {

    /** Fixtures are small; refuse anything absurd rather than loading it into memory. */
    static final long MAX_FIXTURE_BYTES = 32L * 1024 * 1024;

    private FixtureHostDataSource(HostSnapshot snapshot, String label) {
        super(snapshot, label);
    }

    public static FixtureHostDataSource load(Path file) throws IOException {
        if (Files.size(file) > MAX_FIXTURE_BYTES) {
            throw new IOException("fixture larger than " + MAX_FIXTURE_BYTES + " bytes: " + file);
        }
        HostSnapshot s = Json.MAPPER.readValue(file.toFile(), HostSnapshot.class);
        if (s.schema == null || !s.schema.startsWith("gainsay.host-snapshot/")) {
            throw new IOException(file + " is not a Gainsay host snapshot (schema " + s.schema + ")");
        }
        return new FixtureHostDataSource(s, "fixture " + file.getFileName());
    }

    public static FixtureHostDataSource of(HostSnapshot snapshot) {
        return new FixtureHostDataSource(snapshot, "in-memory snapshot");
    }
}
