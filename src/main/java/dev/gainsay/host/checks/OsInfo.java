package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

/** OS build lookups for settings whose default changed between Windows builds. */
final class OsInfo {

    /** Windows 11 24H2 / Server 2025: first build where SMB signing is required by default. */
    static final int BUILD_24H2 = 26100;

    private OsInfo() {
    }

    static int build(HostDataSource ds) {
        QueryResult q = ds.query("os.info");
        JsonNode r = q.ok() ? q.first() : null;
        return r == null ? -1 : r.path("BuildNumber").asInt(-1);
    }
}
