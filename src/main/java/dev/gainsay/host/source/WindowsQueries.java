package dev.gainsay.host.source;

import java.util.Map;
import java.util.TreeMap;

/**
 * The complete allow-list of commands Gainsay may run on a Windows host. Every entry is a
 * <b>read</b>: {@code Get-*} cmdlets, CIM/WMI class enumeration, {@code net accounts} and
 * {@code auditpol /get}. Nothing here writes to the registry, services, firewall or disk.
 * There is no way to run a command that is not in this map.
 *
 * <p>Each script's output is wrapped by {@link WindowsHostDataSource} into JSON
 * ({@code ConvertTo-Json}); errors are captured as data, never thrown.
 */
public final class WindowsQueries {

    private WindowsQueries() {
    }

    private static final Map<String, String> SCRIPTS = new TreeMap<>();

    static {
        // Security Center (root\SecurityCenter2) lists AV products registered with Windows. Absent on Server SKUs.
        SCRIPTS.put("av.products",
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState");
        // Microsoft Defender effective state (module Defender, read-only cmdlet).
        SCRIPTS.put("defender.status",
                "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, "
                        + "AntivirusSignatureAge, IsTamperProtected, AMRunningMode");
        SCRIPTS.put("defender.prefs",
                "Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent");
        // Local accounts; SID suffix -500 = built-in Administrator, -501 = Guest.
        SCRIPTS.put("local.users",
                "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, @{n='SID';e={$_.SID.Value}}");
        // Password/lockout policy as text lines (no WMI class exposes it without admin).
        SCRIPTS.put("net.accounts",
                "$o = net accounts; if ($LASTEXITCODE -ne 0) { throw \"net accounts exited $LASTEXITCODE\" }; $o | Where-Object { $_ -ne '' }");
        SCRIPTS.put("firewall.profiles",
                "Get-NetFirewallProfile | Select-Object Name, @{n='Enabled';e={$_.Enabled.ToString()}}, "
                        + "@{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}}");
        SCRIPTS.put("os.info",
                "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, ProductType");
        SCRIPTS.put("hotfixes",
                "Get-HotFix | Select-Object HotFixID, @{n='InstalledOn';e={ if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null } }}");
        SCRIPTS.put("service.state",
                "Get-CimInstance Win32_Service -Filter \"Name='wuauserv' OR Name='WinRM'\" | Select-Object Name, StartMode, State");
        // Needs elevation. ProtectionStatus: 0 off, 1 on, 2 unknown.
        SCRIPTS.put("bitlocker",
                "Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume "
                        + "-Filter (\"DriveLetter='\" + $env:SystemDrive + \"'\") | Select-Object DriveLetter, ProtectionStatus");
        // Needs elevation.
        SCRIPTS.put("tpm",
                "Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm | "
                        + "Select-Object IsActivated_InitialValue, IsEnabled_InitialValue, SpecVersion");
        // SecurityServicesRunning contains 1 when Credential Guard is running.
        SCRIPTS.put("deviceguard",
                "Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard | "
                        + "Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus");
        SCRIPTS.put("smb.server",
                "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EnableSecuritySignature");
        SCRIPTS.put("ps.execpolicy",
                "Get-ExecutionPolicy -List | Select-Object @{n='Scope';e={$_.Scope.ToString()}}, @{n='ExecutionPolicy';e={$_.ExecutionPolicy.ToString()}}");
        // NetbiosOptions per interface: 0 = use DHCP setting, 1 = enabled, 2 = disabled.
        SCRIPTS.put("netbt.interfaces",
                "Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | "
                        + "ForEach-Object { [pscustomobject]@{ Interface = $_.PSChildName; NetbiosOptions = $_.GetValue('NetbiosOptions') } }");
        // Needs elevation. /r = CSV report; subcategory GUIDs are locale-independent.
        SCRIPTS.put("auditpol",
                "$o = auditpol /get /category:* /r; if ($LASTEXITCODE -ne 0) { throw \"auditpol exited $LASTEXITCODE (needs elevation)\" }; "
                        + "$o | Where-Object { $_ -ne '' }");
        SCRIPTS.put("installed.software",
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                        + "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | "
                        + "Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher");
        // Reads value NAMES only for DefaultPassword: the password itself is never read.
        SCRIPTS.put("winlogon.autologon",
                "$k = Get-Item -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; "
                        + "[pscustomobject]@{ AutoAdminLogon = [string]$k.GetValue('AutoAdminLogon'); "
                        + "DefaultPasswordPresent = ($k.GetValueNames() -contains 'DefaultPassword') }");
        SCRIPTS.put("host.identity",
                "[pscustomobject]@{ Hostname = $env:COMPUTERNAME; "
                        + "IPs = @(Get-NetIPAddress | Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -ne '::1' } | ForEach-Object { $_.IPAddress }); "
                        + "MACs = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.MacAddress }) }");
        SCRIPTS.put("elevation",
                "[pscustomobject]@{ Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
                        + ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }");
    }

    /** Returns the script for an allow-listed id, or null if the id is not allowed. */
    public static String script(String id) {
        return SCRIPTS.get(id);
    }

    public static Map<String, String> all() {
        return Map.copyOf(SCRIPTS);
    }
}
