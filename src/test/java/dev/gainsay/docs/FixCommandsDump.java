package dev.gainsay.docs;

import dev.gainsay.core.Fix;
import dev.gainsay.core.Json;
import dev.gainsay.host.Check;
import dev.gainsay.host.FixCommands;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.checks.CheckCatalog;

import java.util.LinkedHashMap;
import java.util.Map;

/** Prints every fix command as JSON (id → command) so it can be syntax-checked by PowerShell's parser. */
public final class FixCommandsDump {
    public static void main(String[] args) throws Exception {
        Map<String, String> out = new LinkedHashMap<>();
        for (Check c : CheckCatalog.all(HostPolicy.defaults())) {
            Fix f = FixCommands.forCheck(c.id());
            if (f != null && f.command() != null) {
                out.put(c.id(), f.command());
            }
        }
        System.out.println(Json.MAPPER.writeValueAsString(out));
    }
}
