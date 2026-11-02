package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.ClaimStrength;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-NETCFG-002. Implementation: the SMB1 client is the kernel driver {@code mrxsmb10};
 * {@code HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start} = 4 means disabled, 2/3 means it loads.
 * If the key does not exist, the "SMB 1.0/CIFS Client" feature is not installed (the default on
 * Windows 10 1709+ clean installs), which is also safe.
 *
 * <p>Trial claim: {@link ClaimType#SMB1_CLIENT_DISABLED}. Network evidence: an SMB1-format NEGOTIATE
 * from this host offering the dialect "NT LM 0.12".
 */
public final class Smb1ClientCheck extends RegistryCheck {

    private static final RegistrySetting START = RegistrySetting.of(null, RegistrySetting.local(Reg.MRXSMB10, "Start"));

    public Smb1ClientCheck() {
        super("HOST-NETCFG-002", "SMB1 client is disabled", Categories.NETWORK, Severity.MEDIUM,
                "An SMB1-capable client can be downgraded to SMB1 by a rogue or legacy server, exposing credentials and data to SMB1's weaknesses.",
                "Read the Start value of the mrxsmb10 driver service; absent means the SMB1 client feature is not installed.",
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client (or sc.exe config mrxsmb10 start= disabled), then reboot.",
                List.of("https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"),
                START);
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        if (r.value() == null) {
            return pass(ds, "The SMB1 client driver (mrxsmb10) is not installed.", r.evidence());
        }
        return r.value() == 4 ? pass(ds, "The SMB1 client driver is disabled (Start=4).", r.evidence())
                : fail(ds, "The SMB1 client driver is enabled (Start=" + r.value() + ").", r.evidence());
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        Resolved r = resolve(ds);
        if (r.error()) {
            return List.of();
        }
        boolean disabled = r.value() == null || r.value() == 4;
        return List.of(new Claim(ClaimType.SMB1_CLIENT_DISABLED, ds.identity(), disabled,
                "SMB1 client " + (r.value() == null ? "not installed" : disabled ? "disabled" : "enabled (Start=" + r.value() + ")"),
                ClaimStrength.LOCAL, Reg.MRXSMB10 + "\\Start", id()));
    }
}
