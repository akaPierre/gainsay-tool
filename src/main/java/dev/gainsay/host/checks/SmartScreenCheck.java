package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-EXEC-001. Implementation (SmartScreen for apps and files, i.e. Explorer):
 * Group Policy {@code HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen} (DWORD 0/1) wins;
 * otherwise the local {@code HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled}
 * (REG_SZ "Off", "Warn", "Prompt" or "RequireAdmin"). Neither present = on (Windows 10+ default).
 */
public final class SmartScreenCheck extends AbstractCheck {

    private static final RegistrySetting POLICY = RegistrySetting.of(null, RegistrySetting.policy(Reg.SYSTEM_POLICY, "EnableSmartScreen"));
    private static final RegistrySetting LOCAL = RegistrySetting.of(null, RegistrySetting.local(Reg.EXPLORER, "SmartScreenEnabled"));

    public SmartScreenCheck() {
        super("HOST-EXEC-001", "SmartScreen checks downloaded apps and files", Categories.EXECUTION, Severity.MEDIUM,
                "SmartScreen warns before running files that carry the Mark of the Web and have little reputation, which stops a large share of "
                        + "phishing payloads at the moment of double-click.",
                "Read the EnableSmartScreen policy value, then the local SmartScreenEnabled string.",
                "Group Policy: Windows Components > File Explorer > Configure Windows Defender SmartScreen = Enabled (Warn and prevent bypass).",
                List.of("https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        Resolved pol = POLICY.resolve(ds);
        Resolved loc = LOCAL.resolve(ds);
        List<Evidence> ev = new ArrayList<>(pol.evidence());
        ev.addAll(loc.evidence());
        if (pol.error() || loc.error()) {
            return unknown(ds, pol.error() ? pol.errorReason() : loc.errorReason(), ev);
        }
        if (pol.value() != null) {
            return pol.value() != 0 ? pass(ds, "SmartScreen is enforced by Group Policy.", ev)
                    : fail(ds, "SmartScreen is turned off by Group Policy.", ev);
        }
        if (loc.text() != null) {
            return "off".equalsIgnoreCase(loc.text().trim()) ? fail(ds, "SmartScreen is turned off (SmartScreenEnabled=Off).", ev)
                    : pass(ds, "SmartScreen is on (SmartScreenEnabled=" + loc.text() + ").", ev);
        }
        return pass(ds, "SmartScreen is not configured, so the Windows default (on) applies.", ev);
    }
}
