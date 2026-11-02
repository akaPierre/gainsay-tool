package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-ACC-001. Implementation: {@code HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA}
 * (DWORD, 1 = UAC on, the default; 0 = "Admin Approval Mode" off, every admin process runs with a full token).
 * The Group Policy "User Account Control: Run all administrators in Admin Approval Mode" writes this same value.
 */
public final class UacEnabledCheck extends RegistryCheck {

    public UacEnabledCheck() {
        super("HOST-ACC-001", "User Account Control is enabled", Categories.ACCOUNTS, Severity.HIGH,
                "With UAC off, any program an administrator starts (including a malicious attachment) silently gets full administrative rights. "
                        + "UAC also turns off file/registry virtualisation and protected-mode features when disabled.",
                "Read EnableLUA under the UAC policy key; absent means the default (enabled).",
                "Set EnableLUA=1 (Group Policy: Security Options > 'User Account Control: Run all administrators in Admin Approval Mode' = Enabled) and reboot.",
                List.of("https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration"),
                RegistrySetting.of(1L, RegistrySetting.local(Reg.UAC, "EnableLUA")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        if (r.value() != null && r.value() != 0) {
            return pass(ds, "UAC is enabled " + origin(r) + ".", r.evidence());
        }
        return fail(ds, "UAC is disabled (EnableLUA=0): administrator processes always run elevated.", r.evidence());
    }
}
