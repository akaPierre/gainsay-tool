package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.ClaimStrength;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-NETCFG-003. Implementation: {@code Get-SmbServerConfiguration.RequireSecuritySignature}, i.e.
 * {@code HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature}
 * (GPO: "Microsoft network server: Digitally sign communications (always)"). Default: required on
 * Windows 11 24H2 / Server 2025 (build 26100+), not required before.
 *
 * <p>Trial claim: {@link ClaimType#SMB_SERVER_SIGNING_REQUIRED}. Network evidence: the SecurityMode
 * field of this host's SMB2 NEGOTIATE response (bit 0x02 = SIGNING_REQUIRED).
 */
public final class SmbServerSigningCheck extends AbstractCheck {

    public SmbServerSigningCheck() {
        super("HOST-NETCFG-003", "SMB server requires signing", Categories.NETWORK, Severity.MEDIUM,
                "Without mandatory signing, an attacker on the path can relay NTLM authentication to this server (NTLM relay) or tamper with SMB traffic.",
                "Read RequireSecuritySignature from Get-SmbServerConfiguration (falls back to the LanmanServer registry value and the build default).",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true (GPO: 'Microsoft network server: Digitally sign communications (always)').",
                List.of("https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview"));
    }

    record State(Boolean required, ClaimStrength strength, String basis, List<Evidence> evidence, String error) {
    }

    State state(HostDataSource ds) {
        QueryResult q = ds.query("smb.server");
        RegistrySetting setting = RegistrySetting.of(OsInfo.build(ds) >= OsInfo.BUILD_24H2 ? 1L : 0L,
                RegistrySetting.local(Reg.LANMAN_SERVER, "RequireSecuritySignature"));
        Resolved reg = setting.resolve(ds);
        List<Evidence> ev = new ArrayList<>();
        JsonNode s = q.ok() ? q.first() : null;
        if (s != null && s.has("RequireSecuritySignature")) {
            boolean req = s.path("RequireSecuritySignature").asBoolean(false);
            ev.add(queryEvidence("smb.server", "RequireSecuritySignature=" + req, "Get-SmbServerConfiguration | Select RequireSecuritySignature"));
            ev.addAll(reg.evidence());
            return new State(req, ClaimStrength.MEASURED, "Get-SmbServerConfiguration.RequireSecuritySignature", ev, null);
        }
        ev.addAll(reg.evidence());
        if (reg.error()) {
            return new State(null, null, null, ev, reg.errorReason());
        }
        return new State(reg.value() != null && reg.value() != 0, reg.origin(), reg.basis(), ev, null);
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        State st = state(ds);
        if (st.required() == null) {
            return unknown(ds, st.error(), st.evidence());
        }
        return st.required() ? pass(ds, "The SMB server requires signing.", st.evidence())
                : fail(ds, "The SMB server does not require signing (NTLM relay to this host is possible).", st.evidence());
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        State st = state(ds);
        if (st.required() == null) {
            return List.of();
        }
        return List.of(new Claim(ClaimType.SMB_SERVER_SIGNING_REQUIRED, ds.identity(), st.required(),
                "SMB server signing " + (st.required() ? "required" : "not required"), st.strength(), st.basis(), id()));
    }
}
