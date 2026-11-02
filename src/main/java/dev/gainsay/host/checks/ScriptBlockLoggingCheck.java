package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-EXEC-002. Implementation: {@code HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging}
 * (DWORD 1). Logged blocks go to Microsoft-Windows-PowerShell/Operational, event 4104, after deobfuscation.
 * Without the policy, PowerShell 5+ still logs blocks it considers suspicious, but not everything.
 */
public final class ScriptBlockLoggingCheck extends RegistryCheck {

    public ScriptBlockLoggingCheck() {
        super("HOST-EXEC-002", "PowerShell script block logging is on", Categories.EXECUTION, Severity.MEDIUM,
                "PowerShell is the most common post-exploitation tool on Windows. Script block logging records the code that actually ran, after "
                        + "decoding and deobfuscation, which is often the only trace an investigation finds.",
                "Read EnableScriptBlockLogging from the PowerShell policy key.",
                "Group Policy: Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled; forward event 4104 to your SIEM.",
                List.of("https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows"),
                RegistrySetting.of(0L, RegistrySetting.policy(Reg.PS_SCRIPTBLOCK_POLICY, "EnableScriptBlockLogging")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        return r.value() != null && r.value() == 1 ? pass(ds, "Script block logging is enabled by policy.", r.evidence())
                : fail(ds, "Script block logging is not enabled (only 'suspicious' blocks are logged).", r.evidence());
    }
}
