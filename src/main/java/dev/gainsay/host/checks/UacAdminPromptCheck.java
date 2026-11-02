package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-ACC-002. Implementation: {@code ...\Policies\System\ConsentPromptBehaviorAdmin} (DWORD):
 * 0 elevate without prompting, 1 credentials on secure desktop, 2 consent on secure desktop,
 * 3 credentials, 4 consent, 5 consent for non-Windows binaries (default).
 */
public final class UacAdminPromptCheck extends RegistryCheck {

    public UacAdminPromptCheck() {
        super("HOST-ACC-002", "Administrators are prompted before elevation", Categories.ACCOUNTS, Severity.MEDIUM,
                "Value 0 ('elevate without prompting') keeps UAC technically on but removes the moment where a human can refuse an unexpected elevation.",
                "Read ConsentPromptBehaviorAdmin; absent means the default (5).",
                "Set ConsentPromptBehaviorAdmin to 2 (consent on the secure desktop) or at least 5 (default). "
                        + "GPO: 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'.",
                List.of("https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration"),
                RegistrySetting.of(5L, RegistrySetting.local(Reg.UAC, "ConsentPromptBehaviorAdmin")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        long v = r.value() == null ? 5 : r.value();
        if (v == 0) {
            return fail(ds, "Administrators are elevated without any prompt (ConsentPromptBehaviorAdmin=0).", r.evidence());
        }
        return pass(ds, "Administrators are prompted before elevation (ConsentPromptBehaviorAdmin=" + v + ") " + origin(r) + ".", r.evidence());
    }
}
