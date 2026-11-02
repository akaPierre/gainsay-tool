package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-BOOT-002. Implementation: {@code HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled}
 * (1 = on). Firmware publishes this at boot; it is readable without elevation, unlike
 * {@code Confirm-SecureBootUEFI}. The value is absent on legacy-BIOS boots.
 */
public final class SecureBootCheck extends RegistryCheck {

    public SecureBootCheck() {
        super("HOST-BOOT-002", "UEFI Secure Boot is on", Categories.BOOT, Severity.MEDIUM,
                "Secure Boot makes the firmware refuse unsigned boot loaders, which blocks bootkits that would otherwise load before Windows "
                        + "and its security software.",
                "Read UEFISecureBootEnabled from the SecureBoot\\State key.",
                "Enable Secure Boot in the UEFI firmware settings (the disk must be GPT and the machine in UEFI mode; use MBR2GPT if needed).",
                List.of("https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"),
                RegistrySetting.of(null, RegistrySetting.local(Reg.SECUREBOOT, "UEFISecureBootEnabled")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        if (r.value() == null) {
            return warn(ds, "No Secure Boot state is published: the machine probably boots in legacy BIOS mode.", r.evidence());
        }
        return r.value() == 1 ? pass(ds, "Secure Boot is on.", r.evidence())
                : fail(ds, "Secure Boot is off in the firmware.", r.evidence());
    }
}
