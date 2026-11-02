package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-ACC-004. Implementation: {@code Get-LocalUser} (SAM via the LocalAccounts module); the built-in
 * Administrator is the account whose SID ends in {@code -500}, whatever it has been renamed to.
 */
public final class BuiltinAdminCheck extends AbstractCheck {

    public BuiltinAdminCheck() {
        super("HOST-ACC-004", "Built-in Administrator is disabled", Categories.ACCOUNTS, Severity.MEDIUM,
                "RID 500 is exempt from account lockout and, by default, from UAC remote restrictions, which makes it the favourite target for password "
                        + "guessing and pass-the-hash. Renaming it hides the name, not the SID.",
                "Found the local account with SID suffix -500 and read its Enabled flag.",
                "Disable-LocalUser -SID (the -500 SID). Use named admin accounts, and Windows LAPS if a local admin password must exist.",
                List.of("https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-h--securing-local-administrator-accounts-and-groups"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("local.users");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        for (JsonNode u : q.list()) {
            if (!LocalUsers.hasRid(u, 500)) {
                continue;
            }
            String name = u.path("Name").asText("?");
            if (!u.path("Enabled").asBoolean(false)) {
                return pass(ds, "The built-in Administrator (" + name + ") is disabled.", List.of(LocalUsers.evidence(u)));
            }
            if (name.equalsIgnoreCase("Administrator")) {
                return fail(ds, "The built-in Administrator is enabled and still named 'Administrator'.", List.of(LocalUsers.evidence(u)));
            }
            return warn(ds, "The built-in Administrator is enabled (renamed to '" + name + "'; renaming does not change its SID).",
                    List.of(LocalUsers.evidence(u)));
        }
        return unknown(ds, "no local account with RID 500 was listed (domain controller?)", List.of());
    }
}
