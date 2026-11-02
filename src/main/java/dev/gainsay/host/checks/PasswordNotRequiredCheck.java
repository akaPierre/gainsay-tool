package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-ACC-008. Implementation: {@code Get-LocalUser.PasswordRequired}, which reflects the
 * {@code UF_PASSWD_NOTREQD} flag in the account's userAccountControl. Windows cannot tell whether the
 * password is actually blank without trying to log on with it, and Gainsay never tests credentials, so
 * an enabled account with this flag is a WARN ("may have a blank password"), never a confirmed FAIL.
 */
public final class PasswordNotRequiredCheck extends AbstractCheck {

    public PasswordNotRequiredCheck() {
        super("HOST-ACC-008", "No enabled account is allowed a blank password", Categories.ACCOUNTS, Severity.HIGH,
                "An account flagged 'password not required' can have an empty password; by default Windows blocks blank passwords over the network "
                        + "(LimitBlankPasswordUse), but anyone at the console can log on. Local accounts linked to a Microsoft account, or created "
                        + "during setup, often carry the flag although they do have a password, so confirm before acting.",
                "Listed enabled local accounts whose PasswordRequired flag is false. Credentials were not tested.",
                "Set a strong password for the account and clear the flag: net user <name> /passwordreq:yes.",
                List.of("https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("local.users");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        List<Evidence> ev = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (JsonNode u : q.list()) {
            if (u.path("Enabled").asBoolean(false) && !u.path("PasswordRequired").asBoolean(true)) {
                names.add(u.path("Name").asText("?"));
                ev.add(LocalUsers.evidence(u));
            }
        }
        if (names.isEmpty()) {
            return pass(ds, "Every enabled local account requires a password.", ev);
        }
        return warn(ds, "Enabled account(s) flagged 'password not required' (may have a blank password): " + String.join(", ", names) + ".", ev);
    }
}
