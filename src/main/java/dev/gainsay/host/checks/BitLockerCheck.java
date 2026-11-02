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
 * HOST-BOOT-001. Implementation: WMI {@code root\CIMV2\Security\MicrosoftVolumeEncryption\Win32_EncryptableVolume}
 * for the system drive, property {@code ProtectionStatus} (0 off, 1 on, 2 unknown/locked). This is the same
 * provider {@code manage-bde -status} uses. Reading it requires an elevated prompt.
 */
public final class BitLockerCheck extends AbstractCheck {

    public BitLockerCheck() {
        super("HOST-BOOT-001", "The OS volume is encrypted (BitLocker)", Categories.BOOT, Severity.HIGH,
                "Without full-disk encryption, a lost or stolen laptop hands over every file, cached credential and browser session to whoever "
                        + "boots it from a USB stick.",
                "Read ProtectionStatus of the system drive from Win32_EncryptableVolume (needs elevation).",
                "Turn on BitLocker for the OS drive (manage-bde -on C: -RecoveryPassword) with TPM protection, and escrow the recovery key.",
                List.of("https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("bitlocker");
        if (!q.ok()) {
            return unknown(ds, reason(q) + "; on Home editions the BitLocker provider is absent (Device Encryption may still be on)", List.of());
        }
        JsonNode v = q.first();
        if (v == null) {
            return unknown(ds, "the system drive is not listed as an encryptable volume", List.of());
        }
        int status = v.path("ProtectionStatus").asInt(-1);
        Evidence ev = queryEvidence("bitlocker", v.path("DriveLetter").asText("?") + " ProtectionStatus=" + status,
                "manage-bde -status $env:SystemDrive   # elevated");
        return switch (status) {
            case 1 -> pass(ds, "BitLocker protection is on for the OS volume.", List.of(ev));
            case 0 -> fail(ds, "The OS volume is not protected by BitLocker.", List.of(ev));
            default -> unknown(ds, "ProtectionStatus=" + status + " (unknown or locked)", List.of(ev));
        };
    }
}
