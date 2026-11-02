package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-NETCFG-004. Implementation: {@code HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature}
 * (GPO: "Microsoft network client: Digitally sign communications (always)"). Default: required on
 * build 26100+ (Windows 11 24H2), not required before.
 */
public final class SmbClientSigningCheck extends AbstractCheck {

    public SmbClientSigningCheck() {
        super("HOST-NETCFG-004", "SMB client requires signing", Categories.NETWORK, Severity.MEDIUM,
                "A client that does not insist on signing can be served tampered files or scripts (e.g. Group Policy) by a man-in-the-middle.",
                "Read RequireSecuritySignature from LanmanWorkstation\\Parameters; absent means the build default.",
                "Set-SmbClientConfiguration -RequireSecuritySignature $true (GPO: 'Microsoft network client: Digitally sign communications (always)').",
                List.of("https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        int build = OsInfo.build(ds);
        Resolved r = RegistrySetting.of(build >= OsInfo.BUILD_24H2 ? 1L : 0L,
                RegistrySetting.local(Reg.LANMAN_WORKSTATION, "RequireSecuritySignature")).resolve(ds);
        if (r.error()) {
            return unknown(ds, r.errorReason(), r.evidence());
        }
        String origin = RegistryCheck.origin(r);
        return r.value() != null && r.value() != 0 ? pass(ds, "The SMB client requires signing " + origin + ".", r.evidence())
                : fail(ds, "The SMB client does not require signing " + origin + ".", r.evidence());
    }
}
