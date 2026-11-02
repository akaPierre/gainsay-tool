package dev.gainsay.host.checks;

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

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-NETCFG-009. Implementation: SCHANNEL (the Windows TLS library used by IIS, RDP, WinHTTP, .NET,
 * Edge's legacy paths, LDAPS…) reads, per protocol and per role,
 * {@code HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<SSL 3.0|TLS 1.0|TLS 1.1>\<Server|Client>}:
 * {@code Enabled} (0 = off) and {@code DisabledByDefault} (1 = only used when an app asks for it explicitly).
 * With no values, the build's default applies (TLS 1.0/1.1 still on in most Windows 10/11 builds).
 *
 * <p>Important lesson, encoded in the trial explanations: these keys only govern SCHANNEL. Chrome,
 * Firefox, Java, Python and OpenSSL-based servers ignore them. Trial claims:
 * {@link ClaimType#TLS_LEGACY_SERVER_DISABLED} and {@link ClaimType#TLS_LEGACY_CLIENT_DISABLED}.
 */
public final class SchannelLegacyCheck extends AbstractCheck {

    static final List<String> PROTOCOLS = List.of("SSL 3.0", "TLS 1.0", "TLS 1.1");

    public SchannelLegacyCheck() {
        super("HOST-NETCFG-009", "SSL 3.0, TLS 1.0 and TLS 1.1 are disabled in SCHANNEL", Categories.NETWORK, Severity.HIGH,
                "SSL 3.0 is broken (POODLE); TLS 1.0/1.1 lack modern AEAD ciphers and are deprecated (RFC 8996). If both ends support them, a "
                        + "downgrade or misconfiguration can leave traffic protected by obsolete cryptography.",
                "Read Enabled and DisabledByDefault for each legacy protocol under SCHANNEL\\Protocols, for both Server and Client roles.",
                "Create the Server and Client subkeys for SSL 3.0, TLS 1.0 and TLS 1.1 with Enabled=0 and DisabledByDefault=1 (e.g. with IIS Crypto "
                        + "or a GPO registry preference), then reboot. Test old clients first: see the trial's blast radius.",
                List.of("https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings", "https://www.rfc-editor.org/rfc/rfc8996"));
    }

    /** Effective state for one role. */
    record RoleState(boolean allDisabled, boolean anyExplicitlyEnabled, boolean anyDefault, boolean error, String errorReason,
                     List<Evidence> evidence, List<String> stillOn) {
    }

    RoleState role(HostDataSource ds, String role) {
        List<Evidence> ev = new ArrayList<>();
        List<String> stillOn = new ArrayList<>();
        boolean allDisabled = true, explicitOn = false, anyDefault = false;
        String error = null;
        for (String p : PROTOCOLS) {
            String key = Reg.SCHANNEL + "\\" + p + "\\" + role;
            Resolved enabled = RegistrySetting.of(null, RegistrySetting.local(key, "Enabled")).resolve(ds);
            Resolved dbd = RegistrySetting.of(null, RegistrySetting.local(key, "DisabledByDefault")).resolve(ds);
            ev.addAll(enabled.evidence());
            ev.addAll(dbd.evidence());
            if (enabled.error() || dbd.error()) {
                error = enabled.error() ? enabled.errorReason() : dbd.errorReason();
                continue;
            }
            boolean off = (enabled.value() != null && enabled.value() == 0) || (dbd.value() != null && dbd.value() == 1 && enabled.value() == null);
            if (off) {
                continue;
            }
            allDisabled = false;
            stillOn.add(p);
            if (enabled.value() != null) {
                explicitOn = true;
            } else {
                anyDefault = true;
            }
        }
        return new RoleState(allDisabled && error == null, explicitOn, anyDefault, error != null, error, ev, stillOn);
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        RoleState server = role(ds, "Server");
        RoleState client = role(ds, "Client");
        List<Evidence> ev = new ArrayList<>(server.evidence());
        ev.addAll(client.evidence());
        if (server.error() || client.error()) {
            return unknown(ds, server.error() ? server.errorReason() : client.errorReason(), ev);
        }
        if (server.allDisabled() && client.allDisabled()) {
            return pass(ds, "SSL 3.0, TLS 1.0 and TLS 1.1 are disabled for both server and client roles.", ev);
        }
        String detail = "server: " + (server.stillOn().isEmpty() ? "all disabled" : String.join(", ", server.stillOn()) + " on")
                + "; client: " + (client.stillOn().isEmpty() ? "all disabled" : String.join(", ", client.stillOn()) + " on");
        if (server.anyExplicitlyEnabled() || client.anyExplicitlyEnabled()) {
            return fail(ds, "Legacy protocols are explicitly enabled (" + detail + ").", ev);
        }
        return warn(ds, "Legacy protocols are not disabled and fall back to the build default, which usually leaves TLS 1.0/1.1 on (" + detail + ").", ev);
    }

    @Override
    public List<Claim> claims(HostDataSource ds) {
        List<Claim> out = new ArrayList<>();
        addClaim(out, ds, role(ds, "Server"), ClaimType.TLS_LEGACY_SERVER_DISABLED, "server");
        addClaim(out, ds, role(ds, "Client"), ClaimType.TLS_LEGACY_CLIENT_DISABLED, "client");
        return out;
    }

    private void addClaim(List<Claim> out, HostDataSource ds, RoleState s, ClaimType type, String role) {
        if (s.error()) {
            return;
        }
        ClaimStrength strength = s.anyDefault() && !s.anyExplicitlyEnabled() ? ClaimStrength.DEFAULT : ClaimStrength.LOCAL;
        String statement = s.allDisabled() ? "SSL 3.0/TLS 1.0/TLS 1.1 disabled for SCHANNEL " + role
                : String.join(", ", s.stillOn()) + " not disabled for SCHANNEL " + role;
        out.add(new Claim(type, ds.identity(), s.allDisabled(), statement, strength,
                Reg.SCHANNEL + "\\<protocol>\\" + (role.equals("server") ? "Server" : "Client"), id()));
    }
}
