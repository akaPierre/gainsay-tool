package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-CRED-003. Implementation: {@code HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential}
 * (1 = WDigest keeps a reversible copy of the logon password in LSASS memory). Absent = 0 on Windows 8.1 /
 * Server 2012 R2 and later (KB2871997). Attackers set it to 1 and wait for the next logon. No network
 * signature: this claim cannot be tested by the trial.
 */
public final class WDigestCheck extends RegistryCheck {

    public WDigestCheck() {
        super("HOST-CRED-003", "WDigest does not cache cleartext passwords", Categories.CREDENTIALS, Severity.HIGH,
                "With UseLogonCredential=1, the plaintext password of every interactive logon sits in LSASS memory, one memory dump away from an attacker.",
                "Read UseLogonCredential from the WDigest key; absent means the modern default (off).",
                "Set UseLogonCredential=0 (or delete it). Treat an unexpected value of 1 as a possible sign of compromise.",
                List.of("https://attack.mitre.org/techniques/T1112/"),
                RegistrySetting.of(0L, RegistrySetting.local(Reg.WDIGEST, "UseLogonCredential")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        return r.value() != null && r.value() == 1
                ? fail(ds, "WDigest caches cleartext passwords (UseLogonCredential=1).", r.evidence())
                : pass(ds, "WDigest does not cache cleartext passwords " + origin(r) + ".", r.evidence());
    }
}
