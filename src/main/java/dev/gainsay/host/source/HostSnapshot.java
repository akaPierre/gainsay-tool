package dev.gainsay.host.source;

import dev.gainsay.core.HostIdentity;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Everything read from a host in one run. Serialized as a fixture (schema {@value #SCHEMA}).
 * Registry entries are keyed {@code "<key>|<valueName>"}. By construction it never contains secret
 * values: the auto-logon query reports only whether a DefaultPassword value <em>exists</em>.
 */
public final class HostSnapshot {

    public static final String SCHEMA = "gainsay.host-snapshot/1";

    public String schema = SCHEMA;
    public Instant collectedAt;
    public String platform = "windows";
    public String os = "";
    public boolean elevated;
    public HostIdentity identity = new HostIdentity("", null, null);
    public Map<String, RegistryValue> registry = new LinkedHashMap<>();
    public Map<String, QueryResult> queries = new LinkedHashMap<>();

    public static String registryKey(String key, String name) {
        return key + "|" + name;
    }
}
