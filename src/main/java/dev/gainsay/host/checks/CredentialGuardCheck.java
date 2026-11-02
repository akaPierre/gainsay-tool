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
 * HOST-CRED-002. Implementation: WMI {@code root\Microsoft\Windows\DeviceGuard\Win32_DeviceGuard},
 * property {@code SecurityServicesRunning} (array; 1 = Credential Guard, 2 = HVCI/memory integrity).
 * Configured via {@code HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags} or the DeviceGuard policy.
 */
public final class CredentialGuardCheck extends AbstractCheck {

    public CredentialGuardCheck() {
        super("HOST-CRED-002", "Credential Guard is running", Categories.CREDENTIALS, Severity.MEDIUM,
                "Credential Guard moves NTLM hashes and Kerberos TGTs into a virtualisation-isolated LSA (LSAIso), so even SYSTEM-level malware "
                        + "cannot dump them for pass-the-hash or pass-the-ticket.",
                "Checked whether SecurityServicesRunning in Win32_DeviceGuard contains 1.",
                "Enable virtualization-based security and Credential Guard (Group Policy: Device Guard > Turn On Virtualization Based Security > "
                        + "Credential Guard Configuration), and reboot. Requires a 64-bit CPU with virtualization extensions, UEFI and Secure Boot.",
                List.of("https://learn.microsoft.com/windows/security/identity-protection/credential-guard/"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("deviceguard");
        if (!q.ok() || q.first() == null) {
            return unknown(ds, q.ok() ? "Win32_DeviceGuard returned nothing" : reason(q), List.of());
        }
        JsonNode d = q.first();
        boolean running = false;
        for (JsonNode n : d.path("SecurityServicesRunning")) {
            if (n.asInt() == 1) {
                running = true;
            }
        }
        Evidence ev = queryEvidence("deviceguard", "SecurityServicesRunning=" + d.path("SecurityServicesRunning")
                        + ", VirtualizationBasedSecurityStatus=" + d.path("VirtualizationBasedSecurityStatus").asText("?"),
                "Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard");
        return running ? pass(ds, "Credential Guard is running.", List.of(ev))
                : fail(ds, "Credential Guard is not running.", List.of(ev));
    }
}
