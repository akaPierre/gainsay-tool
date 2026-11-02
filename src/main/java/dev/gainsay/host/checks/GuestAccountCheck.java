package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/** HOST-ACC-005. Implementation: {@code Get-LocalUser}, account with SID suffix {@code -501} (Guest). */
public final class GuestAccountCheck extends AbstractCheck {

    public GuestAccountCheck() {
        super("HOST-ACC-005", "Guest account is disabled", Categories.ACCOUNTS, Severity.MEDIUM,
                "An enabled Guest account gives anyone an unauthenticated foothold for local logon and, depending on share permissions, network access.",
                "Found the local account with SID suffix -501 and read its Enabled flag.",
                "Disable-LocalUser -Name Guest (GPO: 'Accounts: Guest account status' = Disabled).",
                List.of("https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("local.users");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        for (JsonNode u : q.list()) {
            if (LocalUsers.hasRid(u, 501)) {
                return u.path("Enabled").asBoolean(false)
                        ? fail(ds, "The Guest account is enabled.", List.of(LocalUsers.evidence(u)))
                        : pass(ds, "The Guest account is disabled.", List.of(LocalUsers.evidence(u)));
            }
        }
        return pass(ds, "No Guest account (RID 501) exists.", List.of());
    }
}
