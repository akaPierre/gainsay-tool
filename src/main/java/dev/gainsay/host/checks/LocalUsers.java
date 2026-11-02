package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;

/** Helpers over the {@code local.users} query ({@code Get-LocalUser}). */
final class LocalUsers {

    static final String REPRODUCE = "Get-LocalUser | Select Name, Enabled, PasswordRequired, SID";

    private LocalUsers() {
    }

    /** Well-known RIDs: 500 built-in Administrator, 501 Guest. The account name can be changed; the RID cannot. */
    static boolean hasRid(JsonNode user, int rid) {
        return user.path("SID").asText("").endsWith("-" + rid);
    }

    static Evidence evidence(JsonNode u) {
        return new Evidence("cmdlet", "local.users", u.path("Name").asText("?") + " SID=" + u.path("SID").asText("?")
                + " Enabled=" + u.path("Enabled").asText("?") + " PasswordRequired=" + u.path("PasswordRequired").asText("?"), REPRODUCE);
    }
}
