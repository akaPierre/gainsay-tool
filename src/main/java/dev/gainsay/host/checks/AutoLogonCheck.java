package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-ACC-009. Implementation: {@code HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon}:
 * {@code AutoAdminLogon} (REG_SZ "1" = on) and {@code DefaultPassword} (REG_SZ, stored in clear text and
 * readable by any local administrator). Gainsay reads only the value <em>names</em> of this key for
 * DefaultPassword; the password is never read, stored or reported.
 */
public final class AutoLogonCheck extends AbstractCheck {

    public AutoLogonCheck() {
        super("HOST-ACC-009", "Automatic logon does not store a cleartext password", Categories.ACCOUNTS, Severity.CRITICAL,
                "Auto-logon with DefaultPassword keeps an account's password in clear text in the registry, and anyone who powers the machine on is logged in.",
                "Read AutoAdminLogon and checked whether a DefaultPassword value exists under the Winlogon key (presence only).",
                "Set AutoAdminLogon to 0 and delete the DefaultPassword value. If a kiosk needs auto-logon, use Sysinternals Autologon (stores an LSA secret) "
                        + "or Assigned Access.",
                List.of("https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("winlogon.autologon");
        if (!q.ok() || q.first() == null) {
            return unknown(ds, q.ok() ? "no data" : reason(q), List.of());
        }
        JsonNode w = q.first();
        boolean auto = "1".equals(w.path("AutoAdminLogon").asText("").trim());
        boolean pwd = w.path("DefaultPasswordPresent").asBoolean(false);
        Evidence ev = new Evidence("registry", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "AutoAdminLogon=" + (auto ? "1" : w.path("AutoAdminLogon").asText("(absent)")) + ", DefaultPassword " + (pwd ? "present (value not read)" : "absent"),
                "(Get-Item 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon').GetValueNames()");
        if (auto && pwd) {
            return fail(ds, "Auto-logon is on and a cleartext DefaultPassword is stored in the registry.", List.of(ev));
        }
        if (pwd) {
            return warn(ds, "A leftover DefaultPassword value exists in the registry although auto-logon is off.", List.of(ev));
        }
        if (auto) {
            return warn(ds, "Auto-logon is on (password kept as an LSA secret, not in clear text); anyone at the console is logged in.", List.of(ev));
        }
        return pass(ds, "Auto-logon is off and no DefaultPassword is stored.", List.of(ev));
    }
}
