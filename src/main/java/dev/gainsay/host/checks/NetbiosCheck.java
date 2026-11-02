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

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-NETCFG-007. Implementation: per network interface,
 * {@code HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}\NetbiosOptions}
 * (0 = use the DHCP server's setting, which usually means enabled; 1 = enabled; 2 = disabled).
 * It must be 2 on every interface; one VPN or virtual adapter left at 0 is enough to keep NBT-NS alive.
 *
 * <p>Trial claim: {@link ClaimType#NETBIOS_DISABLED}. Network evidence: UDP/137 name queries or a
 * listening TCP/139 on this host.
 */
public final class NetbiosCheck extends AbstractCheck {

    public NetbiosCheck() {
        super("HOST-NETCFG-007", "NetBIOS over TCP/IP is disabled on every interface", Categories.NETWORK, Severity.MEDIUM,
                "NBT-NS is the broadcast fallback after DNS and LLMNR; like LLMNR it lets any host on the segment answer a lookup and harvest NTLM hashes. "
                        + "It also exposes the host name, domain and logged-on user to anyone who asks over UDP/137.",
                "Enumerated NetbiosOptions under NetBT\\Parameters\\Interfaces for each adapter.",
                "Set NetbiosOptions=2 on every interface (adapter > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP), or push DHCP option 001 = 0x2.",
                List.of("https://learn.microsoft.com/troubleshoot/windows-server/networking/netbios-over-tcpip-disabled"));
    }

    record State(Boolean disabled, String summary, List<Evidence> evidence, String error) {
    }

    State state(HostDataSource ds) {
        QueryResult q = ds.query("netbt.interfaces");
        if (!q.ok()) {
            return new State(null, null, List.of(), reason(q));
        }
        List<Evidence> ev = new ArrayList<>();
        int enabled = 0, dhcp = 0, off = 0;
        for (JsonNode i : q.list()) {
            int opt = i.path("NetbiosOptions").isNull() ? 0 : i.path("NetbiosOptions").asInt(0);
            ev.add(new Evidence("registry", "NetBT\\Parameters\\Interfaces\\" + i.path("Interface").asText("?"), "NetbiosOptions = " + opt,
                    "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | % { $_.PSChildName + ' ' + $_.GetValue('NetbiosOptions') }"));
            switch (opt) {
                case 2 -> off++;
                case 1 -> enabled++;
                default -> dhcp++;
            }
        }
        if (off + enabled + dhcp == 0) {
            return new State(null, null, ev, "no NetBT interfaces listed");
        }
        String summary = off + " interface(s) disabled, " + enabled + " explicitly enabled, " + dhcp + " left to DHCP";
        return new State(enabled == 0 && dhcp == 0, summary, ev, null);
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        State s = state(ds);
        if (s.disabled() == null) {
            return unknown(ds, s.error(), s.evidence());
        }
        return s.disabled() ? pass(ds, "NetBIOS over TCP/IP is disabled on every interface.", s.evidence())
                : fail(ds, "NetBIOS over TCP/IP is not disabled everywhere: " + s.summary() + ".", s.evidence());
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        State s = state(ds);
        if (s.disabled() == null) {
            return List.of();
        }
        return List.of(new Claim(ClaimType.NETBIOS_DISABLED, ds.identity(), s.disabled(),
                "NetBIOS over TCP/IP " + (s.disabled() ? "disabled on all interfaces" : "active (" + s.summary() + ")"),
                ClaimStrength.LOCAL, "NetBT\\Parameters\\Interfaces\\*\\NetbiosOptions", id()));
    }
}
