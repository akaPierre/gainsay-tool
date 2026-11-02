package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/**
 * HOST-EXEC-004. Implementation: {@code HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled}
 * (DWORD/REG_SZ, 0 = wscript.exe/cscript.exe refuse to run .vbs/.js/.wsf). Absent = enabled.
 */
public final class WshCheck extends RegistryCheck {

    public WshCheck() {
        super("HOST-EXEC-004", "Windows Script Host is disabled", Categories.EXECUTION, Severity.LOW,
                "Phishing attachments and drive-by downloads very often deliver .js/.vbs/.wsf scripts that run via Windows Script Host on double-click. "
                        + "Few users need WSH today.",
                "Read Enabled from the Windows Script Host\\Settings key; absent means enabled.",
                "Set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled = 0 after confirming no logon scripts depend on .vbs/.js.",
                List.of("https://attack.mitre.org/techniques/T1059/005/"),
                RegistrySetting.of(1L, RegistrySetting.local(Reg.WSH, "Enabled")));
    }

    @Override
    protected Finding judge(HostDataSource ds, Resolved r) {
        return r.value() != null && r.value() == 0 ? pass(ds, "Windows Script Host is disabled.", r.evidence())
                : warn(ds, "Windows Script Host is enabled " + origin(r) + ": .js/.vbs files run on double-click.", r.evidence());
    }
}
