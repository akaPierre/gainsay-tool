package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-AV-004. Implementation: {@code Get-MpComputerStatus.IsTamperProtected}. Tamper Protection is
 * stored at {@code HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection} (5 = on) but that
 * key is protected and only meaningful through the cmdlet, so the cmdlet is the source of truth.
 */
public final class TamperProtectionCheck extends AbstractCheck {

    public TamperProtectionCheck() {
        super("HOST-AV-004", "Defender Tamper Protection is on", Categories.MALWARE, Severity.MEDIUM,
                "Ransomware operators routinely disable Defender with a registry write or Set-MpPreference before encrypting. "
                        + "Tamper Protection makes those changes fail even for local administrators.",
                "Read IsTamperProtected from Get-MpComputerStatus (Defender must be the active AV).",
                "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On (or enforce it from Intune/Defender for Endpoint).",
                List.of("https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("defender.status");
        if (!q.ok() || q.first() == null) {
            return unknown(ds, q.ok() ? "Get-MpComputerStatus returned nothing" : reason(q), List.of());
        }
        if (DefenderState.mode(ds) != DefenderState.Mode.ACTIVE) {
            return notApplicable(ds, "Defender is not the active antivirus.", List.of());
        }
        boolean on = q.first().path("IsTamperProtected").asBoolean(false);
        Evidence ev = queryEvidence("defender.status", "IsTamperProtected=" + on, "Get-MpComputerStatus | Select IsTamperProtected");
        return on ? pass(ds, "Tamper Protection is on.", List.of(ev))
                : fail(ds, "Tamper Protection is off; an administrator-level process can silently disable Defender.", List.of(ev));
    }
}
