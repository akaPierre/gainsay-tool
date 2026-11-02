package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-AV-005. Implementation: {@code Get-MpPreference.MAPSReporting} (0 = disabled, 1 = basic,
 * 2 = advanced). Policy equivalent: {@code HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting}.
 */
public final class CloudProtectionCheck extends AbstractCheck {

    public CloudProtectionCheck() {
        super("HOST-AV-005", "Cloud-delivered protection is on", Categories.MALWARE, Severity.LOW,
                "Cloud lookups (MAPS) let Defender block never-seen-before files within seconds, instead of waiting for the next signature update.",
                "Read MAPSReporting from Get-MpPreference; 0 means cloud-delivered protection is off.",
                "Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection: On.",
                List.of("https://learn.microsoft.com/defender-endpoint/cloud-protection-microsoft-defender-antivirus"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("defender.prefs");
        if (!q.ok() || q.first() == null) {
            return unknown(ds, q.ok() ? "Get-MpPreference returned nothing" : reason(q), List.of());
        }
        if (DefenderState.mode(ds) != DefenderState.Mode.ACTIVE) {
            return notApplicable(ds, "Defender is not the active antivirus.", List.of());
        }
        int maps = q.first().path("MAPSReporting").asInt(-1);
        Evidence ev = queryEvidence("defender.prefs", "MAPSReporting=" + maps, "Get-MpPreference | Select MAPSReporting");
        if (maps > 0) {
            return pass(ds, "Cloud-delivered protection is on (MAPSReporting=" + maps + ").", List.of(ev));
        }
        if (maps == 0) {
            return fail(ds, "Cloud-delivered protection is off.", List.of(ev));
        }
        return unknown(ds, "MAPSReporting not reported", List.of(ev));
    }
}
