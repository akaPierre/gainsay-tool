package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-AUDIT-002. Implementation: Security log maximum size. Group Policy value
 * {@code HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize} is in <b>kilobytes</b>; the
 * service value {@code HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize} is in <b>bytes</b>.
 * Windows default: 20 MB (20480 KB).
 */
public final class EventLogSizeCheck extends AbstractCheck {

    private static final RegistrySetting POLICY_KB = RegistrySetting.of(null, RegistrySetting.policy(Reg.EVENTLOG_SECURITY_POLICY, "MaxSize"));
    private static final RegistrySetting LOCAL_BYTES = RegistrySetting.of(null, RegistrySetting.local(Reg.EVENTLOG_SECURITY, "MaxSize"));
    private final long minKb;

    public EventLogSizeCheck(HostPolicy policy) {
        super("HOST-AUDIT-002", "Security event log is large enough to retain history", Categories.AUDITING, Severity.LOW,
                "The default 20 MB Security log can roll over in hours on a busy machine, erasing the evidence an investigation needs.",
                "Read MaxSize from the EventLog policy key (KB) or the EventLog service key (bytes).",
                "Set the Security log maximum size to at least " + policy.minSecurityLogKb() / 1024 + " MB "
                        + "(GPO: Windows Components > Event Log Service > Security > Specify the maximum log file size), or forward events to a collector.",
                List.of("https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4719"));
        this.minKb = policy.minSecurityLogKb();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        Resolved pol = POLICY_KB.resolve(ds);
        Resolved loc = LOCAL_BYTES.resolve(ds);
        List<Evidence> ev = new ArrayList<>(pol.evidence());
        ev.addAll(loc.evidence());
        if (pol.error() || loc.error()) {
            return unknown(ds, pol.error() ? pol.errorReason() : loc.errorReason(), ev);
        }
        long kb;
        String from;
        if (pol.value() != null) {
            kb = pol.value();
            from = "Group Policy";
        } else if (loc.value() != null) {
            kb = loc.value() / 1024;
            from = "local setting";
        } else {
            kb = 20_480;
            from = "Windows default";
        }
        String summary = "Security log maximum size is " + kb / 1024 + " MB (" + from + ")";
        return kb >= minKb ? pass(ds, summary + ".", ev) : warn(ds, summary + "; recommended ≥ " + minKb / 1024 + " MB.", ev);
    }
}
