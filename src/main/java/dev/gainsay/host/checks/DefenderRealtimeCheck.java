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
 * HOST-AV-002. Implementation: {@code Get-MpComputerStatus} (Defender's WMI provider
 * {@code root\Microsoft\Windows\Defender\MSFT_MpComputerStatus}), property {@code RealTimeProtectionEnabled}.
 * The underlying policy value is {@code HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring}.
 */
public final class DefenderRealtimeCheck extends AbstractCheck {

    public DefenderRealtimeCheck() {
        super("HOST-AV-002", "Real-time protection is on", Categories.MALWARE, Severity.HIGH,
                "On-demand scans find malware after the fact; real-time protection blocks it when a file is written or executed. "
                        + "Malware and careless admins both like to switch it off.",
                "Read RealTimeProtectionEnabled from Get-MpComputerStatus. If another AV is primary (Defender in passive mode), the check does not apply.",
                "Windows Security > Virus & threat protection > Manage settings > Real-time protection: On. Remove any policy setting DisableRealtimeMonitoring=1.",
                List.of("https://learn.microsoft.com/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("defender.status");
        if (!q.ok() || q.first() == null) {
            return unknown(ds, q.ok() ? "Get-MpComputerStatus returned nothing" : reason(q), List.of());
        }
        JsonNode s = q.first();
        Evidence ev = queryEvidence("defender.status", "RealTimeProtectionEnabled=" + s.path("RealTimeProtectionEnabled").asText()
                        + ", AMRunningMode=" + s.path("AMRunningMode").asText("?"),
                "Get-MpComputerStatus | Select RealTimeProtectionEnabled, AMRunningMode");
        if (DefenderState.mode(ds) == DefenderState.Mode.PASSIVE_OR_OFF && thirdPartyActive(ds)) {
            return notApplicable(ds, "Another antivirus is primary; Defender is in passive mode.", List.of(ev));
        }
        if (s.path("RealTimeProtectionEnabled").asBoolean(false)) {
            return pass(ds, "Defender real-time protection is on.", List.of(ev));
        }
        return fail(ds, "Defender real-time protection is off and no other antivirus is active.", List.of(ev));
    }

    /** True if Security Center lists an enabled AV that is not Microsoft Defender. */
    static boolean thirdPartyActive(HostDataSource ds) {
        QueryResult av = ds.query("av.products");
        if (!av.ok()) {
            return false;
        }
        for (JsonNode p : av.list()) {
            String name = p.path("displayName").asText("");
            if (!name.toLowerCase().contains("defender") && DefenderState.productEnabled(p.path("productState").asLong())) {
                return true;
            }
        }
        return false;
    }
}
