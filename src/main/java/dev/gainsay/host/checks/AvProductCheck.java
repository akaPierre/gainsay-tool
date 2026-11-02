package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-AV-001. Implementation: WMI namespace {@code root\SecurityCenter2}, class {@code AntiVirusProduct}.
 * Every AV that integrates with Windows Security Center registers an instance with {@code displayName}
 * and a {@code productState} bitfield (see {@link DefenderState#productEnabled(long)}). The namespace
 * does not exist on Windows Server, where the check is not applicable.
 */
public final class AvProductCheck extends AbstractCheck {

    public AvProductCheck() {
        super("HOST-AV-001", "An antivirus product is registered and enabled", Categories.MALWARE, Severity.HIGH,
                "Without an active anti-malware engine, commodity malware (droppers, ransomware loaders, info-stealers) runs unhindered. "
                        + "Security Center is what Windows itself uses to decide whether the machine is protected.",
                "Enumerated root\\SecurityCenter2\\AntiVirusProduct and decoded each productState: bit 0x1000 means real-time scanning is on.",
                "Turn on Microsoft Defender Antivirus (Windows Security > Virus & threat protection) or install and enable a supported AV product.",
                List.of("https://learn.microsoft.com/windows/security/operating-system-security/system-security/windows-defender-security-center/windows-defender-security-center"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("av.products");
        if (!q.ok()) {
            if (isServer(ds)) {
                return notApplicable(ds, "Security Center (root\\SecurityCenter2) does not exist on Windows Server; check the AV console instead.", List.of());
            }
            return unknown(ds, reason(q), List.of());
        }
        List<Evidence> ev = new ArrayList<>();
        List<String> enabled = new ArrayList<>();
        for (JsonNode p : q.list()) {
            long state = p.path("productState").asLong();
            boolean on = DefenderState.productEnabled(state);
            String name = p.path("displayName").asText("?");
            ev.add(queryEvidence("av.products", String.format("%s productState=%d (0x%06X) → %s, definitions %s", name, state, state,
                    on ? "enabled" : "disabled", DefenderState.productUpToDate(state) ? "up to date" : "OUT OF DATE"),
                    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select displayName, productState"));
            if (on) {
                enabled.add(name);
            }
        }
        if (q.list().isEmpty()) {
            return fail(ds, "No antivirus product is registered with Windows Security Center.", ev);
        }
        if (enabled.isEmpty()) {
            return fail(ds, "Antivirus products are registered but none has real-time scanning enabled.", ev);
        }
        return pass(ds, "Enabled: " + String.join(", ", enabled) + ".", ev);
    }

    static boolean isServer(HostDataSource ds) {
        QueryResult os = ds.query("os.info");
        JsonNode r = os.ok() ? os.first() : null;
        // Win32_OperatingSystem.ProductType: 1 = workstation, 2 = domain controller, 3 = server
        return r != null && r.path("ProductType").asInt(1) != 1;
    }
}
