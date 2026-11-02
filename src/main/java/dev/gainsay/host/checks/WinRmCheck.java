package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.ClaimStrength;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-NETCFG-008. Implementation: WMI {@code Win32_Service} Name='WinRM' ({@code StartMode}, {@code State}).
 * Listener details ({@code winrm enumerate winrm/config/listener}) need elevation, so a running service
 * is treated as "exposed on 5985/5986 unless the firewall says otherwise".
 *
 * <p>Trial claim: {@link ClaimType#WINRM_NOT_EXPOSED}. Network evidence: SYN-ACK from this host on 5985/5986.
 */
public final class WinRmCheck extends AbstractCheck {

    public WinRmCheck() {
        super("HOST-NETCFG-008", "WinRM is not running on a workstation", Categories.NETWORK, Severity.MEDIUM,
                "WinRM (PowerShell Remoting) is a full remote-administration channel. On a workstation it is rarely needed and is a favourite "
                        + "lateral-movement path once any admin credential is stolen.",
                "Read StartMode and State of the WinRM service from Win32_Service.",
                "If not needed: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled (and remove its firewall rules). "
                        + "If needed: restrict listeners and firewall scope to admin hosts and use HTTPS (5986).",
                List.of("https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management"));
    }

    record State(Boolean running, Evidence evidence, String error) {
    }

    State state(HostDataSource ds) {
        QueryResult q = ds.query("service.state");
        if (!q.ok()) {
            return new State(null, null, reason(q));
        }
        for (JsonNode s : q.list()) {
            if ("WinRM".equalsIgnoreCase(s.path("Name").asText())) {
                Evidence ev = queryEvidence("service.state", "WinRM StartMode=" + s.path("StartMode").asText("?") + ", State=" + s.path("State").asText("?"),
                        "Get-CimInstance Win32_Service -Filter \"Name='WinRM'\" | Select StartMode, State");
                return new State("Running".equalsIgnoreCase(s.path("State").asText()), ev, null);
            }
        }
        return new State(null, null, "service WinRM not listed");
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        State s = state(ds);
        if (s.running() == null) {
            return unknown(ds, s.error(), List.of());
        }
        if (!s.running()) {
            return pass(ds, "WinRM is not running.", List.of(s.evidence()));
        }
        if (AvProductCheck.isServer(ds)) {
            return warn(ds, "WinRM is running (expected on servers; restrict who can reach 5985/5986).", List.of(s.evidence()));
        }
        return fail(ds, "WinRM is running on a workstation.", List.of(s.evidence()));
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        State s = state(ds);
        if (s.running() == null) {
            return List.of();
        }
        return List.of(new Claim(ClaimType.WINRM_NOT_EXPOSED, ds.identity(), !s.running(),
                "WinRM service " + (s.running() ? "running" : "not running"), ClaimStrength.MEASURED, "Win32_Service WinRM", id()));
    }
}
