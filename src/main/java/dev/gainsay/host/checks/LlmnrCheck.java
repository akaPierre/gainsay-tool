package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-NETCFG-006. Implementation: Group Policy "Turn off multicast name resolution" =
 * {@code HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast} (DWORD, 0 = LLMNR off).
 * There is no non-policy switch; absent means LLMNR is on.
 *
 * <p>Trial claim: {@link ClaimType#LLMNR_DISABLED}. Network evidence: UDP/5355 queries from this host
 * (violates), or DNS NXDOMAIN answers not followed by LLMNR (weakly conforms).
 */
public final class LlmnrCheck extends RegistryCheck {

    public LlmnrCheck() {
        super("HOST-NETCFG-006", "LLMNR is disabled", Categories.NETWORK, Severity.MEDIUM,
                "When DNS fails, Windows asks the whole local segment via LLMNR multicast. Anyone on the segment can answer and capture an NTLM "
                        + "hash in return (the classic Responder attack).",
                "Read EnableMulticast from the DNSClient policy key; absent means LLMNR is enabled.",
                "Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled.",
                List.of("https://attack.mitre.org/techniques/T1557/001/"),
                RegistrySetting.of(1L, RegistrySetting.policy(Reg.DNSCLIENT_POLICY, "EnableMulticast")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        return r.value() != null && r.value() == 0 ? pass(ds, "LLMNR is disabled by policy.", r.evidence())
                : fail(ds, "LLMNR is enabled " + origin(r) + ".", r.evidence());
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        Resolved r = resolve(ds);
        if (r.error()) {
            return List.of();
        }
        boolean off = r.value() != null && r.value() == 0;
        return List.of(new Claim(ClaimType.LLMNR_DISABLED, ds.identity(), off, "LLMNR " + (off ? "disabled" : "enabled"),
                r.origin(), r.basis(), id()));
    }
}
