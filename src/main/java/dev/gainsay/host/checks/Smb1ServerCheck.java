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
 * HOST-NETCFG-001. Implementation: {@code Get-SmbServerConfiguration.EnableSMB1Protocol}, which reflects
 * both the optional feature "SMB 1.0/CIFS Server" and the legacy switch
 * {@code HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1} (DWORD, 0 = off).
 * When the cmdlet is unavailable the registry value is used instead.
 *
 * <p>Trial claim: {@link ClaimType#SMB1_SERVER_DISABLED}. Network evidence: an SMB1 NEGOTIATE response
 * from this host accepting a dialect.
 */
public final class Smb1ServerCheck extends AbstractCheck {

    private static final RegistrySetting SMB1 = RegistrySetting.of(null, RegistrySetting.local(Reg.LANMAN_SERVER, "SMB1"));

    public Smb1ServerCheck() {
        super("HOST-NETCFG-001", "SMB1 server is disabled", Categories.NETWORK, Severity.HIGH,
                "SMBv1 has no pre-authentication integrity, no encryption and was the vector for WannaCry/NotPetya (EternalBlue, MS17-010). "
                        + "Nothing modern needs it.",
                "Read EnableSMB1Protocol from Get-SmbServerConfiguration (falls back to LanmanServer\\Parameters\\SMB1).",
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server (or Set-SmbServerConfiguration -EnableSMB1Protocol $false), then reboot.",
                List.of("https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"));
    }

    record State(Boolean enabled, ClaimStrength strength, String basis, List<Evidence> evidence, String error) {
    }

    State state(HostDataSource ds) {
        QueryResult q = ds.query("smb.server");
        Resolved reg = SMB1.resolve(ds);
        List<Evidence> ev = new ArrayList<>();
        JsonNode s = q.ok() ? q.first() : null;
        if (s != null && s.has("EnableSMB1Protocol")) {
            boolean on = s.path("EnableSMB1Protocol").asBoolean(false);
            ev.add(queryEvidence("smb.server", "EnableSMB1Protocol=" + on, "Get-SmbServerConfiguration | Select EnableSMB1Protocol"));
            ev.addAll(reg.evidence());
            return new State(on, ClaimStrength.MEASURED, "Get-SmbServerConfiguration.EnableSMB1Protocol", ev, null);
        }
        ev.addAll(reg.evidence());
        if (reg.error() || reg.value() == null) {
            return new State(null, null, null, ev, q.ok() ? "SMB1 state not reported" : reason(q));
        }
        return new State(reg.value() != 0, ClaimStrength.LOCAL, reg.basis(), ev, null);
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        State st = state(ds);
        if (st.enabled() == null) {
            return unknown(ds, st.error(), st.evidence());
        }
        return st.enabled() ? fail(ds, "The SMB1 server protocol is enabled.", st.evidence())
                : pass(ds, "The SMB1 server protocol is disabled.", st.evidence());
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        State st = state(ds);
        if (st.enabled() == null) {
            return List.of();
        }
        return List.of(new Claim(ClaimType.SMB1_SERVER_DISABLED, ds.identity(), !st.enabled(),
                "SMB1 server " + (st.enabled() ? "enabled" : "disabled"), st.strength(), st.basis(), id()));
    }
}
