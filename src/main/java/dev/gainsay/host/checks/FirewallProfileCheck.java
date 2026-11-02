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
 * HOST-FW-001/002/003 (one instance per profile: Domain, Private, Public). Implementation:
 * {@code Get-NetFirewallProfile} (WMI {@code root\StandardCimv2\MSFT_NetFirewallProfile}), property
 * {@code Enabled}. The effective value merges local settings
 * ({@code HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\<Profile>Profile\EnableFirewall})
 * with Group Policy ({@code HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<Profile>Profile}).
 */
public final class FirewallProfileCheck extends AbstractCheck {

    private final String profile;

    public FirewallProfileCheck(String id, String profile) {
        super(id, "Windows Firewall is on for the " + profile + " profile", Categories.FIREWALL, Severity.HIGH,
                "The host firewall is the last filter between the network and every listening service. Windows picks the profile "
                        + "per network (Domain, Private or Public), so a profile that is off is a gap whenever that kind of network is joined.",
                "Read Enabled for the " + profile + " profile from Get-NetFirewallProfile.",
                "Set-NetFirewallProfile -Profile " + profile + " -Enabled True (or via Group Policy: Windows Defender Firewall with Advanced Security).",
                List.of("https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/"));
        this.profile = profile;
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("firewall.profiles");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        for (JsonNode p : q.list()) {
            if (!profile.equalsIgnoreCase(p.path("Name").asText())) {
                continue;
            }
            String enabled = p.path("Enabled").asText("");
            Evidence ev = queryEvidence("firewall.profiles", profile + ": Enabled=" + enabled,
                    "Get-NetFirewallProfile -Profile " + profile + " | Select Name, Enabled");
            return "True".equalsIgnoreCase(enabled) ? pass(ds, "The " + profile + " firewall profile is on.", List.of(ev))
                    : fail(ds, "The " + profile + " firewall profile is off.", List.of(ev));
        }
        return unknown(ds, "profile " + profile + " not listed by Get-NetFirewallProfile", List.of());
    }
}
