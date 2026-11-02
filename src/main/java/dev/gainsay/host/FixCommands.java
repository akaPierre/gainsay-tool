package dev.gainsay.host;

import dev.gainsay.core.Fix;

import java.util.HashMap;
import java.util.Map;

/**
 * Copy-paste remediation per host check, for an <b>elevated</b> PowerShell prompt. Gainsay prints these
 * in the fix plan; it never executes them (the tool itself stays read-only). Checks whose fix lives in
 * firmware, a GUI or an uninstaller carry a note instead of a command.
 */
public final class FixCommands {

    private static final Map<String, Fix> FIXES = new HashMap<>();

    private static void cmd(String id, boolean reboot, String command, String note) {
        FIXES.put(id, new Fix(command, reboot, note));
    }

    private static void reg(String id, boolean reboot, String key, String name, Object value, String note) {
        String type = value instanceof String ? "String" : "DWord";
        String v = value instanceof String s ? "'" + s + "'" : value.toString();
        cmd(id, reboot, "$k = '" + key + "'; " + ENSURE_KEY + "Set-ItemProperty -Path $k -Name " + name + " -Value " + v + " -Type " + type, note);
    }

    /**
     * Creates every missing level of registry key $k, one at a time. Deliberately never uses New-Item -Force:
     * on an existing registry key that recreates the key and deletes all of its values.
     */
    static final String ENSURE_KEY = "$p = $null; foreach ($s in ($k -split '\\\\')) { $p = if ($p) { \"$p\\$s\" } else { $s }; "
            + "if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; ";

    static final String GPO_NOTE = "If this value is managed by Group Policy, change the GPO instead or it will be reverted.";

    static {
        cmd("HOST-AV-001", false, null, "Turn on Microsoft Defender (Windows Security > Virus & threat protection) or enable your AV product.");
        cmd("HOST-AV-002", false, "Set-MpPreference -DisableRealtimeMonitoring $false", GPO_NOTE);
        cmd("HOST-AV-003", false, "Update-MpSignature", "Then find out why automatic updates stopped.");
        cmd("HOST-AV-004", false, null, "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On (no command exists by design).");
        cmd("HOST-AV-005", false, "Set-MpPreference -MAPSReporting Advanced", GPO_NOTE);
        reg("HOST-ACC-001", true, "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", 1, GPO_NOTE);
        reg("HOST-ACC-002", false, "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin", 2, GPO_NOTE);
        reg("HOST-ACC-003", false, "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "PromptOnSecureDesktop", 1, GPO_NOTE);
        cmd("HOST-ACC-004", false, "Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser",
                "Make sure another administrator account exists first.");
        cmd("HOST-ACC-005", false, "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser", null);
        cmd("HOST-ACC-006", false, "net accounts /minpwlen:14", "Existing passwords are not affected until they are changed.");
        cmd("HOST-ACC-007", false, "net accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15", null);
        cmd("HOST-ACC-008", false, "net user 'ACCOUNT_NAME' /passwordreq:yes",
                "Set a strong password on the account first; replace ACCOUNT_NAME with the name in the finding.");
        cmd("HOST-ACC-009", false, "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value '0'; "
                + "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue",
                "Change the password of the auto-logon account afterwards: it was readable in clear text.");
        cmd("HOST-FW-001", false, "Set-NetFirewallProfile -Profile Domain -Enabled True", GPO_NOTE);
        cmd("HOST-FW-002", false, "Set-NetFirewallProfile -Profile Private -Enabled True", GPO_NOTE);
        cmd("HOST-FW-003", false, "Set-NetFirewallProfile -Profile Public -Enabled True", GPO_NOTE);
        cmd("HOST-FW-004", false, "Set-NetFirewallProfile -All -DefaultInboundAction Block",
                "Add explicit allow rules for services that must stay reachable before running this.");
        cmd("HOST-PATCH-001", true, null, "Upgrade to a supported Windows release (Settings > Windows Update > feature update) or enrol in ESU.");
        cmd("HOST-PATCH-002", false, "Start-Process ms-settings:windowsupdate", "Install the latest cumulative update.");
        cmd("HOST-PATCH-003", false, "Set-Service wuauserv -StartupType Manual", null);
        cmd("HOST-PATCH-004", false, "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue",
                GPO_NOTE);
        cmd("HOST-BOOT-001", true, "Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector; "
                + "Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -UsedSpaceOnly",
                "Save the recovery password shown by the first command somewhere safe (not on this disk) before rebooting.");
        cmd("HOST-BOOT-002", true, null, "Enable Secure Boot in the UEFI firmware setup (needs a GPT disk; convert with mbr2gpt first if needed).");
        cmd("HOST-BOOT-003", true, null, "Enable the TPM (often called PTT or fTPM) in the UEFI firmware setup.");
        cmd("HOST-NETCFG-001", true, "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; "
                + "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -NoRestart", null);
        cmd("HOST-NETCFG-002", true, "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart", null);
        cmd("HOST-NETCFG-003", false, "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force", GPO_NOTE);
        cmd("HOST-NETCFG-004", false, "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force", GPO_NOTE);
        reg("HOST-NETCFG-005", false, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "UserAuthentication", 1,
                "This requires NLA. If RDP is not needed at all, set fDenyTSConnections=1 under ...\\Control\\Terminal Server instead.");
        reg("HOST-NETCFG-006", false, "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast", 0,
                "In a domain, prefer the Group Policy 'Turn off multicast name resolution'.");
        cmd("HOST-NETCFG-007", false, "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | "
                + "ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 }", "New adapters (VPN, virtual switches) start at 0 again.");
        cmd("HOST-NETCFG-008", false, "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled",
                "Only if this machine is not managed remotely with PowerShell Remoting.");
        cmd("HOST-NETCFG-009", true, "foreach ($p in 'SSL 3.0','TLS 1.0','TLS 1.1') { foreach ($r in 'Server','Client') { "
                + "$k = \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$p\\$r\"; "
                + ENSURE_KEY.replace("$p", "$q") + "Set-ItemProperty -Path $k -Name Enabled -Value 0 -Type DWord; Set-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -Type DWord } }",
                "Old clients and devices that only speak TLS 1.0 will stop connecting; check the trial's blast radius first.");
        reg("HOST-CRED-001", true, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", 1,
                "Third-party LSA plug-ins (some smart-card or password-sync tools) must be signed.");
        cmd("HOST-CRED-002", true, null, "Enable Credential Guard via Group Policy (System > Device Guard) or Intune; it needs VBS, UEFI and Secure Boot.");
        reg("HOST-CRED-003", false, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", 0,
                "An unexpected value of 1 can be a sign of compromise: investigate who set it.");
        reg("HOST-CRED-004", false, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel", 5,
                "Very old devices (NAS, printers) that only speak NTLMv1 will stop authenticating.");
        cmd("HOST-EXEC-001", false, "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value 'Warn'",
                GPO_NOTE);
        reg("HOST-EXEC-002", false, "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging", 1,
                "Forward event 4104 to your log collector; also raise the PowerShell/Operational log size.");
        cmd("HOST-EXEC-003", false, "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine", "Not a security boundary; use WDAC/AppLocker for real control.");
        reg("HOST-EXEC-004", false, "HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings", "Enabled", 0,
                "Check that no logon script uses .vbs/.js first.");
        reg("HOST-EXEC-005", false, "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun", 255, null);
        StringBuilder audit = new StringBuilder();
        for (String guid : dev.gainsay.host.checks.AuditPolicyCheck.EXPECTED.keySet()) {
            var e = dev.gainsay.host.checks.AuditPolicyCheck.EXPECTED.get(guid);
            audit.append(audit.length() == 0 ? "" : "; ").append("auditpol /set /subcategory:\"").append(guid).append("\"")
                    .append(e.success() ? " /success:enable" : "").append(e.failure() ? " /failure:enable" : "");
        }
        cmd("HOST-AUDIT-001", false, audit.toString(), GPO_NOTE);
        cmd("HOST-AUDIT-002", false, "wevtutil sl Security /ms:201326592", GPO_NOTE);
        cmd("HOST-SW-001", false, null, "Uninstall or upgrade the listed programs (Settings > Apps > Installed apps).");
    }

    private FixCommands() {
    }

    /** The fix for a check id, or null. */
    public static Fix forCheck(String id) {
        return FIXES.get(id);
    }
}
