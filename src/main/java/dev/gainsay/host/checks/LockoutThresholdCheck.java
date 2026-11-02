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
 * HOST-ACC-007. Implementation: SAM {@code LockoutThreshold}, read with {@code net accounts}
 * ("Lockout threshold"; "Never" = 0). Windows 11 22H2+ ships with a default of 10.
 */
public final class LockoutThresholdCheck extends AbstractCheck {

    private final int max;

    public LockoutThresholdCheck(HostPolicy policy) {
        super("HOST-ACC-007", "Account lockout is configured", Categories.ACCOUNTS, Severity.MEDIUM,
                "Without a lockout threshold, local accounts can be guessed online indefinitely (over SMB or RDP, for example).",
                "Parsed 'Lockout threshold' from net accounts.",
                "Set the lockout threshold to 10 or fewer attempts (net accounts /lockoutthreshold:10, or Account Lockout Policy in secpol.msc).",
                List.of("https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold"));
        this.max = policy.maxLockoutThreshold();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("net.accounts");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        String raw = NetAccounts.value(q, "Lockout threshold", 5);
        Integer t = NetAccounts.number(raw, 0);
        if (t == null) {
            return unknown(ds, "could not parse 'Lockout threshold' from net accounts", List.of());
        }
        Evidence ev = new Evidence("command", "net accounts", "Lockout threshold: " + raw, NetAccounts.REPRODUCE);
        if (t == 0) {
            return fail(ds, "Accounts never lock out after failed logons.", List.of(ev));
        }
        if (t <= max) {
            return pass(ds, "Accounts lock after " + t + " failed attempts.", List.of(ev));
        }
        return warn(ds, "Accounts lock only after " + t + " failed attempts (recommended ≤ " + max + ").", List.of(ev));
    }
}
