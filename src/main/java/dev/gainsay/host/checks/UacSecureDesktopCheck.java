package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-ACC-003. Implementation: {@code ...\Policies\System\PromptOnSecureDesktop} (DWORD, 1 = default).
 * The secure desktop is a separate desktop that only SYSTEM processes can draw on or send input to.
 */
public final class UacSecureDesktopCheck extends RegistryCheck {

    public UacSecureDesktopCheck() {
        super("HOST-ACC-003", "UAC prompts appear on the secure desktop", Categories.ACCOUNTS, Severity.LOW,
                "On the normal desktop, other processes running as the user can screenshot, overlay or send clicks to the UAC prompt.",
                "Read PromptOnSecureDesktop; absent means the default (1).",
                "Set PromptOnSecureDesktop=1 (GPO: 'User Account Control: Switch to the secure desktop when prompting for elevation').",
                List.of("https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration"),
                RegistrySetting.of(1L, RegistrySetting.local(Reg.UAC, "PromptOnSecureDesktop")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        if (r.value() == null || r.value() != 0) {
            return pass(ds, "UAC prompts use the secure desktop " + origin(r) + ".", r.evidence());
        }
        return fail(ds, "UAC prompts appear on the interactive desktop, where other user processes can interfere with them.", r.evidence());
    }
}
