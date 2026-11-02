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
 * HOST-CRED-004. Implementation: {@code HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel}
 * (GPO "Network security: LAN Manager authentication level"): 0–2 can send LM/NTLMv1, 3 sends NTLMv2
 * only, 4 also refuses LM, 5 also refuses LM and NTLMv1 (best). Absent = 3 on Vista and later.
 *
 * <p>Trial claim: {@link ClaimType#NTLMV1_DISABLED}. Network evidence: the length of the NT challenge
 * response in NTLMSSP AUTHENTICATE messages sent by this host (24 bytes = NTLMv1).
 */
public final class NtlmV1Check extends RegistryCheck {

    public NtlmV1Check() {
        super("HOST-CRED-004", "NTLMv1 and LM are not used (LmCompatibilityLevel ≥ 3)", Categories.CREDENTIALS, Severity.HIGH,
                "NTLMv1 responses can be cracked back to the NT hash quickly (DES-based; with a chosen challenge, rainbow tables make it trivial). "
                        + "Whoever captures one effectively has the account's password hash.",
                "Read LmCompatibilityLevel from the Lsa key; absent means the default (3).",
                "Set LmCompatibilityLevel=5 (GPO: 'Network security: LAN Manager authentication level' = Send NTLMv2 response only. Refuse LM & NTLM).",
                List.of("https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"),
                RegistrySetting.of(3L, RegistrySetting.local(Reg.LSA, "LmCompatibilityLevel")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        long v = r.value() == null ? 3 : r.value();
        if (v >= 3) {
            return pass(ds, "LmCompatibilityLevel=" + v + " " + origin(r) + ": only NTLMv2 is sent" + (v == 5 ? " and LM/NTLMv1 are refused." : "."), r.evidence());
        }
        return fail(ds, "LmCompatibilityLevel=" + v + ": the host may send LM/NTLMv1 responses.", r.evidence());
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        Resolved r = resolve(ds);
        if (r.error()) {
            return List.of();
        }
        long v = r.value() == null ? 3 : r.value();
        return List.of(new Claim(ClaimType.NTLMV1_DISABLED, ds.identity(), v >= 3, "LmCompatibilityLevel=" + v
                + (v >= 3 ? " (NTLMv2 only)" : " (NTLMv1 allowed)"), r.origin(), r.basis(), id()));
    }
}
