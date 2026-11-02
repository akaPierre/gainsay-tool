package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-NETCFG-005. Implementation:
 * <ul>
 *   <li>RDP on/off: {@code fDenyTSConnections} (1 = deny = RDP off), Group Policy at
 *       {@code HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services} wins over the local value at
 *       {@code HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server}. Default: 1.</li>
 *   <li>NLA: {@code UserAuthentication} (1 = Network Level Authentication required), policy key above or
 *       {@code ...\Terminal Server\WinStations\RDP-Tcp}. Default: 1.</li>
 * </ul>
 * Trial claims: {@link ClaimType#RDP_DISABLED} (evidence: SYN-ACK on 3389) and, when RDP is on,
 * {@link ClaimType#RDP_NLA_REQUIRED} (evidence: the protocol the server selects in its X.224 Connection Confirm).
 */
public final class RdpCheck extends AbstractCheck {

    private static final RegistrySetting DENY = RegistrySetting.of(1L,
            RegistrySetting.policy(Reg.TS_POLICY, "fDenyTSConnections"), RegistrySetting.local(Reg.TS, "fDenyTSConnections"));
    private static final RegistrySetting NLA = RegistrySetting.of(1L,
            RegistrySetting.policy(Reg.TS_POLICY, "UserAuthentication"), RegistrySetting.local(Reg.TS_RDP_TCP, "UserAuthentication"));

    public RdpCheck() {
        super("HOST-NETCFG-005", "Remote Desktop is off, or requires Network Level Authentication", Categories.NETWORK, Severity.HIGH,
                "Exposed RDP is one of the most common initial-access routes for ransomware. Without NLA, the server builds a full logon session "
                        + "(and shows the logon screen) before the user is authenticated, which exposes pre-auth bugs such as BlueKeep.",
                "Resolved fDenyTSConnections and UserAuthentication, policy key first, then the local key, then the Windows default.",
                "If RDP is not needed: set fDenyTSConnections=1. If it is: require NLA (UserAuthentication=1), restrict it to a management network "
                        + "or VPN, and never expose 3389 to the internet.",
                List.of("https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        Resolved deny = DENY.resolve(ds);
        Resolved nla = NLA.resolve(ds);
        List<Evidence> ev = new ArrayList<>(deny.evidence());
        ev.addAll(nla.evidence());
        if (deny.error()) {
            return unknown(ds, deny.errorReason(), ev);
        }
        if (deny.value() != null && deny.value() != 0) {
            return pass(ds, "Remote Desktop is off " + RegistryCheck.origin(deny) + ".", ev);
        }
        if (nla.error()) {
            return unknown(ds, "RDP is on, NLA state unreadable: " + nla.errorReason(), ev);
        }
        if (nla.value() != null && nla.value() != 0) {
            return warn(ds, "Remote Desktop is on and requires NLA " + RegistryCheck.origin(nla) + "; make sure it is not reachable from untrusted networks.", ev);
        }
        return fail(ds, "Remote Desktop is on WITHOUT Network Level Authentication.", ev);
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        Resolved deny = DENY.resolve(ds);
        Resolved nla = NLA.resolve(ds);
        List<Claim> out = new ArrayList<>();
        if (deny.error()) {
            return out;
        }
        boolean off = deny.value() != null && deny.value() != 0;
        out.add(new Claim(ClaimType.RDP_DISABLED, ds.identity(), off, "Remote Desktop " + (off ? "off" : "on"),
                deny.origin(), deny.basis(), id()));
        if (!off && !nla.error()) {
            boolean required = nla.value() != null && nla.value() != 0;
            out.add(new Claim(ClaimType.RDP_NLA_REQUIRED, ds.identity(), required, "RDP NLA " + (required ? "required" : "not required"),
                    nla.origin(), nla.basis(), id()));
        }
        return out;
    }
}
