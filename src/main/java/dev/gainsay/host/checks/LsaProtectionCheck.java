package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-CRED-001. Implementation: {@code HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL}
 * (DWORD: 1 = LSASS runs as a Protected Process Light with a UEFI variable lock, 2 = PPL without the lock,
 * 0 = off). Windows 11 22H2+ can enable it by default on some new installs, so "absent" is reported as
 * build-dependent rather than as a hard failure.
 */
public final class LsaProtectionCheck extends RegistryCheck {

    public LsaProtectionCheck() {
        super("HOST-CRED-001", "LSA protection (RunAsPPL) is on", Categories.CREDENTIALS, Severity.HIGH,
                "LSASS holds credential material for logged-on users. As a protected process, it refuses memory reads and code injection from "
                        + "non-protected processes, even administrators, which blocks Mimikatz-style dumping.",
                "Read RunAsPPL from the Lsa key.",
                "Set RunAsPPL=1 (DWORD) under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (or Windows Security > Device security > Core isolation > "
                        + "Local Security Authority protection) and reboot. Check that no LSA plug-ins are unsigned first.",
                List.of("https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"),
                RegistrySetting.of(null, RegistrySetting.local(Reg.LSA, "RunAsPPL")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        if (r.value() == null) {
            return warn(ds, "RunAsPPL is not configured; whether LSA protection is on depends on the build and install type.", r.evidence());
        }
        return r.value() == 1 || r.value() == 2 ? pass(ds, "LSASS runs as a protected process (RunAsPPL=" + r.value() + ").", r.evidence())
                : fail(ds, "LSA protection is off (RunAsPPL=" + r.value() + ").", r.evidence());
    }
}
