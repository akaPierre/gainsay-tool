package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-ACC-006. Implementation: the SAM domain policy {@code MinPasswordLength}, read with
 * {@code net accounts} ("Minimum password length"). The GPO path is Account Policies > Password Policy.
 */
public final class PasswordLengthCheck extends AbstractCheck {

    private final int minLength;

    public PasswordLengthCheck(HostPolicy policy) {
        super("HOST-ACC-006", "Local password policy requires long passwords", Categories.ACCOUNTS, Severity.MEDIUM,
                "Length is the single biggest factor in resisting offline cracking and guessing. Applies to local accounts only "
                        + "(Microsoft accounts and domain accounts follow their own policy).",
                "Parsed 'Minimum password length' from net accounts.",
                "Set Minimum password length to at least 14 (secpol.msc > Account Policies > Password Policy, or net accounts /minpwlen:14).",
                List.of("https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/minimum-password-length"));
        this.minLength = policy.minPasswordLength();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("net.accounts");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        Integer len = NetAccounts.number(NetAccounts.value(q, "Minimum password length", 3), null);
        if (len == null) {
            return unknown(ds, "could not parse 'Minimum password length' from net accounts", List.of());
        }
        Evidence ev = new Evidence("command", "net accounts", "Minimum password length: " + len, NetAccounts.REPRODUCE);
        if (len >= minLength) {
            return pass(ds, "Minimum password length is " + len + ".", List.of(ev));
        }
        if (len >= 8) {
            return warn(ds, "Minimum password length is " + len + " (recommended ≥ " + minLength + ").", List.of(ev));
        }
        return fail(ds, "Minimum password length is " + len + (len == 0 ? " (empty passwords allowed)" : "") + ".", List.of(ev));
    }
}
