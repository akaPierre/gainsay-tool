# Check catalogue

_Generated from the check metadata in the code (`DocsGenerator`); the same text appears in every report._

Every check answers four questions: **what** it checks, **why** it matters, **how** Gainsay verified it, and **how to fix** it. Host checks are *testimony* (what the machine says it is configured to do); network checks are *evidence* (what was seen on the wire); trial claims connect the two.

- [Host checks](#host-checks) · [Network checks](#network-checks) · [Trial claims](#trial-claims) · [Scan](#scan)

## Host checks

### Malware protection

#### HOST-AV-001 — An antivirus product is registered and enabled

Severity: **HIGH**

- **Why:** Without an active anti-malware engine, commodity malware (droppers, ransomware loaders, info-stealers) runs unhindered. Security Center is what Windows itself uses to decide whether the machine is protected.
- **How verified:** Enumerated root\SecurityCenter2\AntiVirusProduct and decoded each productState: bit 0x1000 means real-time scanning is on.
- **How to fix:** Turn on Microsoft Defender Antivirus (Windows Security > Virus & threat protection) or install and enable a supported AV product.
- **Note:** Turn on Microsoft Defender (Windows Security > Virus & threat protection) or enable your AV product.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/system-security/windows-defender-security-center/windows-defender-security-center

#### HOST-AV-002 — Real-time protection is on

Severity: **HIGH**

- **Why:** On-demand scans find malware after the fact; real-time protection blocks it when a file is written or executed. Malware and careless admins both like to switch it off.
- **How verified:** Read RealTimeProtectionEnabled from Get-MpComputerStatus. If another AV is primary (Defender in passive mode), the check does not apply.
- **How to fix:** Windows Security > Virus & threat protection > Manage settings > Real-time protection: On. Remove any policy setting DisableRealtimeMonitoring=1.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-MpPreference -DisableRealtimeMonitoring $false`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus

#### HOST-AV-003 — Antivirus signatures are up to date

Severity: **MEDIUM**

- **Why:** Signature-based detection only knows threats published before its last update. A few days' lag is normal; weeks mean updates are broken.
- **How verified:** Read AntivirusSignatureAge from Get-MpComputerStatus (Defender) or the out-of-date bit of the third-party productState.
- **How to fix:** Run Update-MpSignature (or the vendor's update), then find out why automatic updates stopped (proxy, WSUS, disabled service).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Update-MpSignature`
- **Note:** Then find out why automatic updates stopped.
- **References:** https://learn.microsoft.com/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus

#### HOST-AV-004 — Defender Tamper Protection is on

Severity: **MEDIUM**

- **Why:** Ransomware operators routinely disable Defender with a registry write or Set-MpPreference before encrypting. Tamper Protection makes those changes fail even for local administrators.
- **How verified:** Read IsTamperProtected from Get-MpComputerStatus (Defender must be the active AV).
- **How to fix:** Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On (or enforce it from Intune/Defender for Endpoint).
- **Note:** Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On (no command exists by design).
- **References:** https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection

#### HOST-AV-005 — Cloud-delivered protection is on

Severity: **LOW**

- **Why:** Cloud lookups (MAPS) let Defender block never-seen-before files within seconds, instead of waiting for the next signature update.
- **How verified:** Read MAPSReporting from Get-MpPreference; 0 means cloud-delivered protection is off.
- **How to fix:** Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection: On.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-MpPreference -MAPSReporting Advanced`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/defender-endpoint/cloud-protection-microsoft-defender-antivirus

### Account control

#### HOST-ACC-001 — User Account Control is enabled

Severity: **HIGH**

- **Why:** With UAC off, any program an administrator starts (including a malicious attachment) silently gets full administrative rights. UAC also turns off file/registry virtualisation and protected-mode features when disabled.
- **How verified:** Read EnableLUA under the UAC policy key; absent means the default (enabled).
- **How to fix:** Set EnableLUA=1 (Group Policy: Security Options > 'User Account Control: Run all administrators in Admin Approval Mode' = Enabled) and reboot.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run; restart needed): `$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name EnableLUA -Value 1 -Type DWord`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration

#### HOST-ACC-002 — Administrators are prompted before elevation

Severity: **MEDIUM**

- **Why:** Value 0 ('elevate without prompting') keeps UAC technically on but removes the moment where a human can refuse an unexpected elevation.
- **How verified:** Read ConsentPromptBehaviorAdmin; absent means the default (5).
- **How to fix:** Set ConsentPromptBehaviorAdmin to 2 (consent on the secure desktop) or at least 5 (default). GPO: 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration

#### HOST-ACC-003 — UAC prompts appear on the secure desktop

Severity: **LOW**

- **Why:** On the normal desktop, other processes running as the user can screenshot, overlay or send clicks to the UAC prompt.
- **How verified:** Read PromptOnSecureDesktop; absent means the default (1).
- **How to fix:** Set PromptOnSecureDesktop=1 (GPO: 'User Account Control: Switch to the secure desktop when prompting for elevation').
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name PromptOnSecureDesktop -Value 1 -Type DWord`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration

#### HOST-ACC-004 — Built-in Administrator is disabled

Severity: **MEDIUM**

- **Why:** RID 500 is exempt from account lockout and, by default, from UAC remote restrictions, which makes it the favourite target for password guessing and pass-the-hash. Renaming it hides the name, not the SID.
- **How verified:** Found the local account with SID suffix -500 and read its Enabled flag.
- **How to fix:** Disable-LocalUser -SID (the -500 SID). Use named admin accounts, and Windows LAPS if a local admin password must exist.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser`
- **Note:** Make sure another administrator account exists first.
- **References:** https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-h--securing-local-administrator-accounts-and-groups

#### HOST-ACC-005 — Guest account is disabled

Severity: **MEDIUM**

- **Why:** An enabled Guest account gives anyone an unauthenticated foothold for local logon and, depending on share permissions, network access.
- **How verified:** Found the local account with SID suffix -501 and read its Enabled flag.
- **How to fix:** Disable-LocalUser -Name Guest (GPO: 'Accounts: Guest account status' = Disabled).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser`
- **References:** https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status

#### HOST-ACC-006 — Local password policy requires long passwords

Severity: **MEDIUM**

- **Why:** Length is the single biggest factor in resisting offline cracking and guessing. Applies to local accounts only (Microsoft accounts and domain accounts follow their own policy).
- **How verified:** Parsed 'Minimum password length' from net accounts.
- **How to fix:** Set Minimum password length to at least 14 (secpol.msc > Account Policies > Password Policy, or net accounts /minpwlen:14).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `net accounts /minpwlen:14`
- **Note:** Existing passwords are not affected until they are changed.
- **References:** https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/minimum-password-length

#### HOST-ACC-007 — Account lockout is configured

Severity: **MEDIUM**

- **Why:** Without a lockout threshold, local accounts can be guessed online indefinitely (over SMB or RDP, for example).
- **How verified:** Parsed 'Lockout threshold' from net accounts.
- **How to fix:** Set the lockout threshold to 10 or fewer attempts (net accounts /lockoutthreshold:10, or Account Lockout Policy in secpol.msc).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `net accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15`
- **References:** https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold

#### HOST-ACC-008 — No enabled account is allowed a blank password

Severity: **HIGH**

- **Why:** An account flagged 'password not required' can have an empty password; by default Windows blocks blank passwords over the network (LimitBlankPasswordUse), but anyone at the console can log on. Local accounts linked to a Microsoft account, or created during setup, often carry the flag although they do have a password, so confirm before acting.
- **How verified:** Listed enabled local accounts whose PasswordRequired flag is false. Credentials were not tested.
- **How to fix:** Set a strong password for the account and clear the flag: net user <name> /passwordreq:yes.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `net user 'ACCOUNT_NAME' /passwordreq:yes`
- **Note:** Set a strong password on the account first; replace ACCOUNT_NAME with the name in the finding.
- **References:** https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

#### HOST-ACC-009 — Automatic logon does not store a cleartext password

Severity: **CRITICAL**

- **Why:** Auto-logon with DefaultPassword keeps an account's password in clear text in the registry, and anyone who powers the machine on is logged in.
- **How verified:** Read AutoAdminLogon and checked whether a DefaultPassword value exists under the Winlogon key (presence only).
- **How to fix:** Set AutoAdminLogon to 0 and delete the DefaultPassword value. If a kiosk needs auto-logon, use Sysinternals Autologon (stores an LSA secret) or Assigned Access.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value '0'; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue`
- **Note:** Change the password of the auto-logon account afterwards: it was readable in clear text.
- **References:** https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon

### Firewall

#### HOST-FW-001 — Windows Firewall is on for the Domain profile

Severity: **HIGH**

- **Why:** The host firewall is the last filter between the network and every listening service. Windows picks the profile per network (Domain, Private or Public), so a profile that is off is a gap whenever that kind of network is joined.
- **How verified:** Read Enabled for the Domain profile from Get-NetFirewallProfile.
- **How to fix:** Set-NetFirewallProfile -Profile Domain -Enabled True (or via Group Policy: Windows Defender Firewall with Advanced Security).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-NetFirewallProfile -Profile Domain -Enabled True`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/

#### HOST-FW-002 — Windows Firewall is on for the Private profile

Severity: **HIGH**

- **Why:** The host firewall is the last filter between the network and every listening service. Windows picks the profile per network (Domain, Private or Public), so a profile that is off is a gap whenever that kind of network is joined.
- **How verified:** Read Enabled for the Private profile from Get-NetFirewallProfile.
- **How to fix:** Set-NetFirewallProfile -Profile Private -Enabled True (or via Group Policy: Windows Defender Firewall with Advanced Security).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-NetFirewallProfile -Profile Private -Enabled True`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/

#### HOST-FW-003 — Windows Firewall is on for the Public profile

Severity: **HIGH**

- **Why:** The host firewall is the last filter between the network and every listening service. Windows picks the profile per network (Domain, Private or Public), so a profile that is off is a gap whenever that kind of network is joined.
- **How verified:** Read Enabled for the Public profile from Get-NetFirewallProfile.
- **How to fix:** Set-NetFirewallProfile -Profile Public -Enabled True (or via Group Policy: Windows Defender Firewall with Advanced Security).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-NetFirewallProfile -Profile Public -Enabled True`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/

#### HOST-FW-004 — Firewall blocks unsolicited inbound traffic by default

Severity: **HIGH**

- **Why:** Default-allow inbound turns the firewall into a deny-list: every new service is exposed until someone writes a rule for it.
- **How verified:** Read DefaultInboundAction for every profile from Get-NetFirewallProfile.
- **How to fix:** Set-NetFirewallProfile -All -DefaultInboundAction Block, then add explicit allow rules for the services that must be reachable.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-NetFirewallProfile -All -DefaultInboundAction Block`
- **Note:** Add explicit allow rules for services that must stay reachable before running this.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure

### Patching

#### HOST-PATCH-001 — The Windows build still receives security updates

Severity: **HIGH**

- **Why:** Once a build leaves servicing, newly found vulnerabilities in it are never fixed, so every later patch Tuesday widens the gap.
- **How verified:** Read BuildNumber and Caption from Win32_OperatingSystem and looked up the end-of-servicing date in the local lifecycle table.
- **How to fix:** Upgrade to a supported feature update (Settings > Windows Update) or enrol in Extended Security Updates where available.
- **Note:** Upgrade to a supported Windows release (Settings > Windows Update > feature update) or enrol in ESU.
- **References:** https://learn.microsoft.com/lifecycle/products/

#### HOST-PATCH-002 — Security updates were installed recently

Severity: **HIGH**

- **Why:** Microsoft ships cumulative security updates monthly. A machine whose newest update is months old is missing fixes for vulnerabilities that are already public.
- **How verified:** Took the most recent InstalledOn date from Get-HotFix.
- **How to fix:** Run Windows Update and install the latest cumulative update; investigate why updates stalled (paused, WSUS, disk space).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Start-Process ms-settings:windowsupdate`
- **Note:** Install the latest cumulative update.
- **References:** https://learn.microsoft.com/windows/deployment/update/

#### HOST-PATCH-003 — Windows Update service is not disabled

Severity: **MEDIUM**

- **Why:** Disabling wuauserv is a common 'tweak' that silently stops all security patching.
- **How verified:** Read StartMode of the wuauserv service from Win32_Service.
- **How to fix:** Set-Service wuauserv -StartupType Manual (its default) and run Windows Update.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-Service wuauserv -StartupType Manual`
- **References:** https://learn.microsoft.com/windows/deployment/update/how-windows-update-works

#### HOST-PATCH-004 — Automatic updates are not turned off by policy

Severity: **MEDIUM**

- **Why:** Updates that wait for a person to click are installed late or never; most exploited Windows bugs were patched weeks before the attack.
- **How verified:** Read NoAutoUpdate and AUOptions from the Windows Update Group Policy key; absent means automatic updates.
- **How to fix:** Remove NoAutoUpdate=1 and set AUOptions to 4 (or manage updates through Windows Update for Business / Intune).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/deployment/update/waas-wu-settings

### Disk & boot

#### HOST-BOOT-001 — The OS volume is encrypted (BitLocker)

Severity: **HIGH**

- **Why:** Without full-disk encryption, a lost or stolen laptop hands over every file, cached credential and browser session to whoever boots it from a USB stick.
- **How verified:** Read ProtectionStatus of the system drive from Win32_EncryptableVolume (needs elevation).
- **How to fix:** Turn on BitLocker for the OS drive (manage-bde -on C: -RecoveryPassword) with TPM protection, and escrow the recovery key.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run; restart needed): `Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector; Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -UsedSpaceOnly`
- **Note:** Save the recovery password shown by the first command somewhere safe (not on this disk) before rebooting.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/

#### HOST-BOOT-002 — UEFI Secure Boot is on

Severity: **MEDIUM**

- **Why:** Secure Boot makes the firmware refuse unsigned boot loaders, which blocks bootkits that would otherwise load before Windows and its security software.
- **How verified:** Read UEFISecureBootEnabled from the SecureBoot\State key.
- **How to fix:** Enable Secure Boot in the UEFI firmware settings (the disk must be GPT and the machine in UEFI mode; use MBR2GPT if needed).
- **Note:** Enable Secure Boot in the UEFI firmware setup (needs a GPT disk; convert with mbr2gpt first if needed).
- **References:** https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot

#### HOST-BOOT-003 — A TPM is present and ready

Severity: **MEDIUM**

- **Why:** The TPM anchors BitLocker keys, Windows Hello, measured boot and Credential Guard. Without it those protections fall back to weaker modes or are unavailable.
- **How verified:** Read the Win32_Tpm instance (needs elevation).
- **How to fix:** Enable the TPM (often 'PTT' or 'fTPM') in the firmware settings; then initialise it from tpm.msc.
- **Note:** Enable the TPM (often called PTT or fTPM) in the UEFI firmware setup.
- **References:** https://learn.microsoft.com/windows/security/hardware-security/tpm/trusted-platform-module-overview

### Network-facing settings

#### HOST-NETCFG-001 — SMB1 server is disabled

Severity: **HIGH**

- **Why:** SMBv1 has no pre-authentication integrity, no encryption and was the vector for WannaCry/NotPetya (EternalBlue, MS17-010). Nothing modern needs it.
- **How verified:** Read EnableSMB1Protocol from Get-SmbServerConfiguration (falls back to LanmanServer\Parameters\SMB1).
- **How to fix:** Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server (or Set-SmbServerConfiguration -EnableSMB1Protocol $false), then reboot.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run; restart needed): `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -NoRestart`
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

#### HOST-NETCFG-002 — SMB1 client is disabled

Severity: **MEDIUM** · emits a trial claim

- **Why:** An SMB1-capable client can be downgraded to SMB1 by a rogue or legacy server, exposing credentials and data to SMB1's weaknesses.
- **How verified:** Read the Start value of the mrxsmb10 driver service; absent means the SMB1 client feature is not installed.
- **How to fix:** Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client (or sc.exe config mrxsmb10 start= disabled), then reboot.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run; restart needed): `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart`
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

#### HOST-NETCFG-003 — SMB server requires signing

Severity: **MEDIUM** · emits a trial claim

- **Why:** Without mandatory signing, an attacker on the path can relay NTLM authentication to this server (NTLM relay) or tamper with SMB traffic.
- **How verified:** Read RequireSecuritySignature from Get-SmbServerConfiguration (falls back to the LanmanServer registry value and the build default).
- **How to fix:** Set-SmbServerConfiguration -RequireSecuritySignature $true (GPO: 'Microsoft network server: Digitally sign communications (always)').
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview

#### HOST-NETCFG-004 — SMB client requires signing

Severity: **MEDIUM**

- **Why:** A client that does not insist on signing can be served tampered files or scripts (e.g. Group Policy) by a man-in-the-middle.
- **How verified:** Read RequireSecuritySignature from LanmanWorkstation\Parameters; absent means the build default.
- **How to fix:** Set-SmbClientConfiguration -RequireSecuritySignature $true (GPO: 'Microsoft network client: Digitally sign communications (always)').
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-SmbClientConfiguration -RequireSecuritySignature $true -Force`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview

#### HOST-NETCFG-005 — Remote Desktop is off, or requires Network Level Authentication

Severity: **HIGH** · emits a trial claim

- **Why:** Exposed RDP is one of the most common initial-access routes for ransomware. Without NLA, the server builds a full logon session (and shows the logon screen) before the user is authenticated, which exposes pre-auth bugs such as BlueKeep.
- **How verified:** Resolved fDenyTSConnections and UserAuthentication, policy key first, then the local key, then the Windows default.
- **How to fix:** If RDP is not needed: set fDenyTSConnections=1. If it is: require NLA (UserAuthentication=1), restrict it to a management network or VPN, and never expose 3389 to the internet.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name UserAuthentication -Value 1 -Type DWord`
- **Note:** This requires NLA. If RDP is not needed at all, set fDenyTSConnections=1 under ...\Control\Terminal Server instead.
- **References:** https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access

#### HOST-NETCFG-006 — LLMNR is disabled

Severity: **MEDIUM** · emits a trial claim

- **Why:** When DNS fails, Windows asks the whole local segment via LLMNR multicast. Anyone on the segment can answer and capture an NTLM hash in return (the classic Responder attack).
- **How verified:** Read EnableMulticast from the DNSClient policy key; absent means LLMNR is enabled.
- **How to fix:** Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name EnableMulticast -Value 0 -Type DWord`
- **Note:** In a domain, prefer the Group Policy 'Turn off multicast name resolution'.
- **References:** https://attack.mitre.org/techniques/T1557/001/

#### HOST-NETCFG-007 — NetBIOS over TCP/IP is disabled on every interface

Severity: **MEDIUM**

- **Why:** NBT-NS is the broadcast fallback after DNS and LLMNR; like LLMNR it lets any host on the segment answer a lookup and harvest NTLM hashes. It also exposes the host name, domain and logged-on user to anyone who asks over UDP/137.
- **How verified:** Enumerated NetbiosOptions under NetBT\Parameters\Interfaces for each adapter.
- **How to fix:** Set NetbiosOptions=2 on every interface (adapter > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP), or push DHCP option 001 = 0x2.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 }`
- **Note:** New adapters (VPN, virtual switches) start at 0 again.
- **References:** https://learn.microsoft.com/troubleshoot/windows-server/networking/netbios-over-tcpip-disabled

#### HOST-NETCFG-008 — WinRM is not running on a workstation

Severity: **MEDIUM**

- **Why:** WinRM (PowerShell Remoting) is a full remote-administration channel. On a workstation it is rarely needed and is a favourite lateral-movement path once any admin credential is stolen.
- **How verified:** Read StartMode and State of the WinRM service from Win32_Service.
- **How to fix:** If not needed: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled (and remove its firewall rules). If needed: restrict listeners and firewall scope to admin hosts and use HTTPS (5986).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Stop-Service WinRM; Set-Service WinRM -StartupType Disabled`
- **Note:** Only if this machine is not managed remotely with PowerShell Remoting.
- **References:** https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

#### HOST-NETCFG-009 — SSL 3.0, TLS 1.0 and TLS 1.1 are disabled in SCHANNEL

Severity: **HIGH** · emits a trial claim

- **Why:** SSL 3.0 is broken (POODLE); TLS 1.0/1.1 lack modern AEAD ciphers and are deprecated (RFC 8996). If both ends support them, a downgrade or misconfiguration can leave traffic protected by obsolete cryptography.
- **How verified:** Read Enabled and DisabledByDefault for each legacy protocol under SCHANNEL\Protocols, for both Server and Client roles.
- **How to fix:** Create the Server and Client subkeys for SSL 3.0, TLS 1.0 and TLS 1.1 with Enabled=0 and DisabledByDefault=1 (e.g. with IIS Crypto or a GPO registry preference), then reboot. Test old clients first: see the trial's blast radius.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run; restart needed): `foreach ($p in 'SSL 3.0','TLS 1.0','TLS 1.1') { foreach ($r in 'Server','Client') { $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\$r"; $q = $null; foreach ($s in ($k -split '\\')) { $q = if ($q) { "$q\$s" } else { $s }; if (-not (Test-Path $q)) { New-Item -Path $q | Out-Null } }; Set-ItemProperty -Path $k -Name Enabled -Value 0 -Type DWord; Set-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -Type DWord } }`
- **Note:** Old clients and devices that only speak TLS 1.0 will stop connecting; check the trial's blast radius first.
- **References:** https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings · https://www.rfc-editor.org/rfc/rfc8996

### Credential protection

#### HOST-CRED-001 — LSA protection (RunAsPPL) is on

Severity: **HIGH**

- **Why:** LSASS holds credential material for logged-on users. As a protected process, it refuses memory reads and code injection from non-protected processes, even administrators, which blocks Mimikatz-style dumping.
- **How verified:** Read RunAsPPL from the Lsa key.
- **How to fix:** Set RunAsPPL=1 (DWORD) under HKLM\SYSTEM\CurrentControlSet\Control\Lsa (or Windows Security > Device security > Core isolation > Local Security Authority protection) and reboot. Check that no LSA plug-ins are unsigned first.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run; restart needed): `$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name RunAsPPL -Value 1 -Type DWord`
- **Note:** Third-party LSA plug-ins (some smart-card or password-sync tools) must be signed.
- **References:** https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

#### HOST-CRED-002 — Credential Guard is running

Severity: **MEDIUM**

- **Why:** Credential Guard moves NTLM hashes and Kerberos TGTs into a virtualisation-isolated LSA (LSAIso), so even SYSTEM-level malware cannot dump them for pass-the-hash or pass-the-ticket.
- **How verified:** Checked whether SecurityServicesRunning in Win32_DeviceGuard contains 1.
- **How to fix:** Enable virtualization-based security and Credential Guard (Group Policy: Device Guard > Turn On Virtualization Based Security > Credential Guard Configuration), and reboot. Requires a 64-bit CPU with virtualization extensions, UEFI and Secure Boot.
- **Note:** Enable Credential Guard via Group Policy (System > Device Guard) or Intune; it needs VBS, UEFI and Secure Boot.
- **References:** https://learn.microsoft.com/windows/security/identity-protection/credential-guard/

#### HOST-CRED-003 — WDigest does not cache cleartext passwords

Severity: **HIGH**

- **Why:** With UseLogonCredential=1, the plaintext password of every interactive logon sits in LSASS memory, one memory dump away from an attacker.
- **How verified:** Read UseLogonCredential from the WDigest key; absent means the modern default (off).
- **How to fix:** Set UseLogonCredential=0 (or delete it). Treat an unexpected value of 1 as a possible sign of compromise.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name UseLogonCredential -Value 0 -Type DWord`
- **Note:** An unexpected value of 1 can be a sign of compromise: investigate who set it.
- **References:** https://attack.mitre.org/techniques/T1112/

#### HOST-CRED-004 — NTLMv1 and LM are not used (LmCompatibilityLevel ≥ 3)

Severity: **HIGH** · emits a trial claim

- **Why:** NTLMv1 responses can be cracked back to the NT hash quickly (DES-based; with a chosen challenge, rainbow tables make it trivial). Whoever captures one effectively has the account's password hash.
- **How verified:** Read LmCompatibilityLevel from the Lsa key; absent means the default (3).
- **How to fix:** Set LmCompatibilityLevel=5 (GPO: 'Network security: LAN Manager authentication level' = Send NTLMv2 response only. Refuse LM & NTLM).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name LmCompatibilityLevel -Value 5 -Type DWord`
- **Note:** Very old devices (NAS, printers) that only speak NTLMv1 will stop authenticating.
- **References:** https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level

### Execution & hardening

#### HOST-EXEC-001 — SmartScreen checks downloaded apps and files

Severity: **MEDIUM**

- **Why:** SmartScreen warns before running files that carry the Mark of the Web and have little reputation, which stops a large share of phishing payloads at the moment of double-click.
- **How verified:** Read the EnableSmartScreen policy value, then the local SmartScreenEnabled string.
- **How to fix:** Group Policy: Windows Components > File Explorer > Configure Windows Defender SmartScreen = Enabled (Warn and prevent bypass).
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value 'Warn'`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/

#### HOST-EXEC-002 — PowerShell script block logging is on

Severity: **MEDIUM**

- **Why:** PowerShell is the most common post-exploitation tool on Windows. Script block logging records the code that actually ran, after decoding and deobfuscation, which is often the only trace an investigation finds.
- **How verified:** Read EnableScriptBlockLogging from the PowerShell policy key.
- **How to fix:** Group Policy: Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled; forward event 4104 to your SIEM.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord`
- **Note:** Forward event 4104 to your log collector; also raise the PowerShell/Operational log size.
- **References:** https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows

#### HOST-EXEC-003 — PowerShell execution policy is not Bypass/Unrestricted

Severity: **LOW**

- **Why:** A restrictive execution policy stops users double-clicking downloaded .ps1 files by accident. It is not a security boundary: anyone can run powershell -ExecutionPolicy Bypass, so do not rely on it against an attacker.
- **How verified:** Took the effective policy from Get-ExecutionPolicy -List using PowerShell's scope precedence, ignoring the per-process scope (which only describes the query's own PowerShell session).
- **How to fix:** Set-ExecutionPolicy RemoteSigned -Scope LocalMachine (or via GPO 'Turn on Script Execution'). Use AppLocker/WDAC for real enforcement.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `Set-ExecutionPolicy RemoteSigned -Scope LocalMachine`
- **Note:** Not a security boundary; use WDAC/AppLocker for real control.
- **References:** https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies

#### HOST-EXEC-004 — Windows Script Host is disabled

Severity: **LOW**

- **Why:** Phishing attachments and drive-by downloads very often deliver .js/.vbs/.wsf scripts that run via Windows Script Host on double-click. Few users need WSH today.
- **How verified:** Read Enabled from the Windows Script Host\Settings key; absent means enabled.
- **How to fix:** Set HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0 after confirming no logon scripts depend on .vbs/.js.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name Enabled -Value 0 -Type DWord`
- **Note:** Check that no logon script uses .vbs/.js first.
- **References:** https://attack.mitre.org/techniques/T1059/005/

#### HOST-EXEC-005 — AutoRun/AutoPlay is disabled for removable media

Severity: **LOW**

- **Why:** AutoRun let malware (Conficker, Stuxnet's LNK variants) spread by USB. Modern Windows ignores autorun.inf on USB drives, but AutoPlay prompts and optical media still invite one-click execution.
- **How verified:** Read NoDriveTypeAutoRun and NoAutorun from the Explorer policy key.
- **How to fix:** Group Policy: Windows Components > AutoPlay Policies > Turn off AutoPlay = Enabled (All drives) and 'Set the default behavior for AutoRun' = Do not execute.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $p = $null; foreach ($s in ($k -split '\\')) { $p = if ($p) { "$p\$s" } else { $s }; if (-not (Test-Path $p)) { New-Item -Path $p | Out-Null } }; Set-ItemProperty -Path $k -Name NoDriveTypeAutoRun -Value 255 -Type DWord`
- **References:** https://learn.microsoft.com/windows/win32/shell/autoplay-reg

### Auditing

#### HOST-AUDIT-001 — Key audit policy subcategories are enabled

Severity: **MEDIUM**

- **Why:** Without logon, account-management and process-creation auditing, the Security log cannot answer 'who logged on, what changed, what ran' after an incident.
- **How verified:** Parsed auditpol /get /category:* /r and compared 10 subcategories (by GUID) with a baseline subset.
- **How to fix:** Configure Advanced Audit Policy via Group Policy (Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration), e.g. auditpol /set /subcategory:"Logon" /success:enable /failure:enable.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable; auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable; auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /failure:enable; auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable; auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable; auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable; auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable; auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable; auditpol /set /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable; auditpol /set /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /success:enable`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations

#### HOST-AUDIT-002 — Security event log is large enough to retain history

Severity: **LOW**

- **Why:** The default 20 MB Security log can roll over in hours on a busy machine, erasing the evidence an investigation needs.
- **How verified:** Read MaxSize from the EventLog policy key (KB) or the EventLog service key (bytes).
- **How to fix:** Set the Security log maximum size to at least 192 MB (GPO: Windows Components > Event Log Service > Security > Specify the maximum log file size), or forward events to a collector.
- **Fix command** (elevated PowerShell; printed by Gainsay, never run): `wevtutil sl Security /ms:201326592`
- **Note:** If this value is managed by Group Policy, change the GPO instead or it will be reverted.
- **References:** https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4719

### Software hygiene

#### HOST-SW-001 — No end-of-life or known-risky software is installed

Severity: **MEDIUM**

- **Why:** Software that no longer gets updates accumulates exploitable bugs; browsers and document readers are reached directly by attacker content.
- **How verified:** Compared installed programs (HKLM Uninstall keys, 64- and 32-bit) with the local end-of-life list.
- **How to fix:** Uninstall or upgrade the listed programs. Extend the list (--eol-list) with your organisation's own banned software.
- **Note:** Uninstall or upgrade the listed programs (Settings > Apps > Installed apps).
- **References:** https://learn.microsoft.com/lifecycle/

## Network checks

### Cleartext protocols

#### NET-HTTP-001 — HTTP is used without TLS

Severity: **MEDIUM**

- **Why:** Anything sent over plain HTTP can be read and modified by anyone on the path: pages, downloads, form data and session cookies.
- **How verified:** Detected HTTP/1.x request lines at the start of TCP client streams on any port (WinRM's 5985, which encrypts its payload, is excluded).
- **How to fix:** Serve the site over HTTPS only, redirect HTTP to HTTPS and enable HSTS.
- **References:** https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security

#### NET-HTTP-002 — Credentials are sent over cleartext HTTP

Severity: **HIGH**

- **Why:** Basic authentication, bearer tokens and password form fields over plain HTTP hand reusable secrets to any observer.
- **How verified:** Looked for Authorization headers (Basic/Bearer) and password-like parameter names in the query or form body of cleartext requests. Only the presence is recorded; values are masked.
- **How to fix:** Move the login and every authenticated page to HTTPS. Rotate any credential that was seen on the wire.
- **References:** https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

#### NET-HTTP-003 — Session cookies are set over cleartext HTTP

Severity: **MEDIUM**

- **Why:** A cookie set over HTTP travels in clear on every later request, so it can be stolen and replayed (session hijacking). Cookies on HTTPS pages are encrypted and cannot be checked passively.
- **How verified:** Read Set-Cookie headers in cleartext HTTP responses; cookie names are kept, values masked.
- **How to fix:** Set cookies only over HTTPS with the Secure and HttpOnly attributes, and redirect HTTP to HTTPS before any cookie is issued.
- **References:** https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies

#### NET-LEGACY-001 — Telnet is in use

Severity: **HIGH**

- **Why:** Telnet sends the whole session, including the password, in clear text.
- **How verified:** Detected TCP/23 sessions or Telnet option negotiation (IAC 0xFF followed by WILL/WONT/DO/DONT) at the start of a server stream.
- **How to fix:** Replace Telnet with SSH and disable the Telnet service on the device.
- **References:** https://www.rfc-editor.org/rfc/rfc854

#### NET-LEGACY-002 — FTP is used without TLS

Severity: **HIGH**

- **Why:** FTP sends USER/PASS and file contents in clear; the data channel is separate and equally exposed.
- **How verified:** Detected an FTP control session (banner 220 / USER command) without an AUTH TLS upgrade.
- **How to fix:** Use SFTP or FTPS (AUTH TLS with mandatory encryption) and disable plain FTP.
- **References:** https://www.rfc-editor.org/rfc/rfc4217

#### NET-LEGACY-003 — Mail protocols are used without TLS

Severity: **MEDIUM**

- **Why:** POP3, IMAP and SMTP submission without STARTTLS expose credentials and message contents; opportunistic STARTTLS can be stripped by an active attacker, so authentication before the upgrade is the worst case.
- **How verified:** Followed POP3/IMAP/SMTP control streams and checked whether STLS/STARTTLS was issued, and whether AUTH/LOGIN/USER came before it.
- **How to fix:** Require implicit TLS (IMAPS 993, POP3S 995, SMTPS 465) or mandatory STARTTLS, and refuse AUTH on unencrypted connections.
- **References:** https://www.rfc-editor.org/rfc/rfc8314

#### NET-LEGACY-004 — TFTP is in use

Severity: **MEDIUM**

- **Why:** TFTP has no authentication at all; anyone who can reach the server can read (and often write) files such as device configs.
- **How verified:** Detected TFTP read/write requests (UDP/69, opcodes 1 and 2).
- **How to fix:** Restrict TFTP to provisioning VLANs, make it read-only, or replace it with HTTPS/SCP for configuration transfer.
- **References:** https://www.rfc-editor.org/rfc/rfc1350

#### NET-LEGACY-005 — SNMP v1/v2c with community strings

Severity: **MEDIUM**

- **Why:** SNMP v1/v2c authenticate with a cleartext community string; anyone who sees one can query (or with a write community, reconfigure) the device.
- **How verified:** Parsed the SNMP message version (BER INTEGER) of UDP/161 and /162 traffic; the community string itself is masked.
- **How to fix:** Move to SNMPv3 with authPriv, or restrict v2c to a management network with ACLs and read-only communities.
- **References:** https://www.rfc-editor.org/rfc/rfc3414

#### NET-LEGACY-006 — rlogin/rsh/rexec are in use

Severity: **HIGH**

- **Why:** The Berkeley r-services trust source addresses and send everything in clear; they are trivially spoofed.
- **How verified:** Detected TCP sessions to ports 512, 513 or 514.
- **How to fix:** Disable the r-services and use SSH.
- **References:** https://www.rfc-editor.org/rfc/rfc1282

#### NET-LEGACY-007 — LDAP simple bind without TLS

Severity: **HIGH**

- **Why:** An LDAP simple bind carries the user's DN and password in clear; on Active Directory that is a domain credential.
- **How verified:** Parsed LDAP BindRequest messages on TCP/389 and flagged simple authentication with a non-empty password before any StartTLS. Neither the DN nor the password is recorded.
- **How to fix:** Use LDAPS (636) or StartTLS, prefer SASL/Kerberos binds, and on AD enforce LDAP signing and channel binding.
- **References:** https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server

### SMB & NTLM

#### NET-SMB-001 — SMB1 is negotiated or offered

Severity: **HIGH**

- **Why:** SMBv1 is the protocol behind EternalBlue/WannaCry; it lacks pre-authentication integrity and encryption. A client offering it can be downgraded.
- **How verified:** Parsed SMB NEGOTIATE exchanges: SMB1-format requests listing 'NT LM 0.12', and SMB1 responses that accept a dialect.
- **How to fix:** Remove SMB1 on servers and clients (see HOST-NETCFG-001/002) and replace devices that only speak SMB1.
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

#### NET-SMB-002 — SMB server does not require signing

Severity: **MEDIUM**

- **Why:** Without required signing an attacker in the middle can relay NTLM authentication to the server or alter SMB traffic.
- **How verified:** Read the SecurityMode field of the server's NEGOTIATE response (SMB2: bit 0x02 SIGNING_REQUIRED; SMB1: bit 0x08).
- **How to fix:** Require SMB signing on the server (HOST-NETCFG-003).
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview

#### NET-SMB-003 — NTLMv1 authentication is used

Severity: **HIGH**

- **Why:** An NTLMv1 response can be cracked back to the account's NT hash, which is as good as the password.
- **How verified:** Found NTLMSSP AUTHENTICATE messages (raw in SMB/SPNEGO, or base64 in HTTP headers) and checked the NT response length (24 bytes = NTLMv1).
- **How to fix:** Set LmCompatibilityLevel to 5 on clients and servers (HOST-CRED-004) and audit NTLM usage before blocking it.
- **References:** https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level

#### NET-SMB-004 — SMB crosses a network boundary

Severity: **MEDIUM**

- **Why:** SMB is meant for the local network. SMB between segments (or to/from public addresses) widens the reach of SMB worms and relay attacks.
- **How verified:** Mapped both ends of each SMB flow to a segment (from --segments or a /24 default) and flagged flows that cross segments or involve public IPs.
- **How to fix:** Filter TCP/445 and 139 at segment boundaries; allow it only to the file servers that need it.
- **References:** https://learn.microsoft.com/windows-server/storage/file-server/smb-secure-traffic

### TLS

#### NET-TLS-001 — Legacy SSL/TLS versions are negotiated or offered

Severity: **HIGH**

- **Why:** SSL 3.0, TLS 1.0 and TLS 1.1 are deprecated (RFC 8996) and lack modern protections; a server that still agrees to them keeps every client one downgrade away from weak crypto.
- **How verified:** Read the version selected in ServerHello (supported_versions extension if present) and the versions offered in ClientHello. Nothing is decrypted.
- **How to fix:** Disable SSL 3.0/TLS 1.0/1.1 on the server (HOST-NETCFG-009 for SCHANNEL; the app's own config otherwise) and upgrade old clients.
- **References:** https://www.rfc-editor.org/rfc/rfc8996

#### NET-TLS-002 — Weak TLS cipher suites are negotiated or offered

Severity: **HIGH**

- **Why:** NULL, EXPORT, anonymous, RC4, DES and 3DES suites give no or breakable protection (FREAK, Logjam, RC4 biases, Sweet32).
- **How verified:** Classified the suite selected in ServerHello and the suites offered in ClientHello against the IANA registry.
- **How to fix:** Remove the weak suites from the server's and client's TLS configuration; keep AEAD suites (AES-GCM, ChaCha20-Poly1305).
- **References:** https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

#### NET-TLS-003 — Expired or self-signed certificates are presented

Severity: **MEDIUM**

- **Why:** Users and devices that accept invalid certificates cannot tell a real server from an interception proxy.
- **How verified:** Parsed the first certificate of TLS ≤ 1.2 handshakes (TLS 1.3 encrypts certificates) and checked validity dates and issuer == subject.
- **How to fix:** Install certificates from a trusted (internal or public) CA and renew them before expiry.
- **References:** https://www.rfc-editor.org/rfc/rfc5280

#### NET-TLS-004 — TLS clients connect without SNI

Severity: **LOW**

- **Why:** Without Server Name Indication, multi-tenant servers cannot pick the right certificate and clients may be served (and accept) the wrong one; it is also typical of old or custom TLS stacks.
- **How verified:** Flagged ClientHello messages to port 443 without a server_name extension.
- **How to fix:** Update the client or library; connect by host name rather than IP address.
- **References:** https://www.rfc-editor.org/rfc/rfc6066#section-3

### Name resolution

#### NET-NAME-001 — LLMNR is used on the segment

Severity: **MEDIUM**

- **Why:** LLMNR lets any host on the segment answer name lookups, which is how Responder-style tools harvest NTLM hashes.
- **How verified:** Counted LLMNR queries (UDP/5355) per source host.
- **How to fix:** Disable LLMNR by Group Policy (HOST-NETCFG-006) and fix the DNS failures that trigger it.
- **References:** https://attack.mitre.org/techniques/T1557/001/

#### NET-NAME-002 — NetBIOS name service (NBT-NS) is used

Severity: **MEDIUM**

- **Why:** NBT-NS broadcast lookups can be answered by any host on the segment (NTLM hash capture), and leak host and domain names.
- **How verified:** Counted NetBIOS name queries (UDP/137) per source host.
- **How to fix:** Disable NetBIOS over TCP/IP on every interface (HOST-NETCFG-007) or via DHCP option 001.
- **References:** https://attack.mitre.org/techniques/T1557/001/

#### NET-NAME-003 — mDNS is used

Severity: **LOW**

- **Why:** mDNS advertises device names and services to the whole segment and, like LLMNR, accepts answers from anyone.
- **How verified:** Counted mDNS traffic (UDP/5353) per source host.
- **How to fix:** Disable mDNS where not needed (e.g. 'EnableMDNS'=0 under the DNS client parameters on Windows) or confine it to user VLANs.
- **References:** https://www.rfc-editor.org/rfc/rfc6762

#### NET-NAME-004 — Cleartext DNS goes to public resolvers

Severity: **LOW**

- **Why:** Queries that bypass the internal resolver escape filtering and logging, and travel unencrypted across the internet.
- **How verified:** Recorded DNS (UDP/53) resolvers per client and flagged public resolver addresses (or ones outside --expected-resolvers).
- **How to fix:** Point clients at the internal resolver, block outbound UDP/TCP 53 except from it, and use DoT/DoH from the resolver upstream.
- **References:** https://www.cisa.gov/resources-tools/resources/encrypted-dns-implementation-guidance

### Exposed services

#### NET-EXPOSE-001 — Risky services are reachable

Severity: **HIGH**

- **Why:** Remote administration, file sharing, databases and container/cluster APIs are prime targets; reachable from another segment they are an invitation for lateral movement.
- **How verified:** Inferred listening services passively from SYN-ACK replies (and UDP replies from well-known ports); nothing was probed.
- **How to fix:** Close the service if unused, otherwise restrict it with host and network firewalls to the hosts that need it.
- **References:** https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices

#### NET-EXPOSE-002 — RDP is served without Network Level Authentication

Severity: **HIGH**

- **Why:** Without NLA (CredSSP) the server starts a full session before authentication, exposing pre-auth vulnerabilities (BlueKeep) and the logon screen.
- **How verified:** Read the protocol the server selected in its X.224 Connection Confirm (RDP_NEG_RSP): 0 = RDP security, 1 = TLS only, 2/8 = CredSSP.
- **How to fix:** Require NLA on the server (HOST-NETCFG-005) and keep RDP off untrusted networks.
- **References:** https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access

### Network hygiene

#### NET-HYG-001 — Duplicate IP address (ARP conflict)

Severity: **MEDIUM**

- **Why:** Two MAC addresses answering for one IP cause intermittent outages and make spoofing easy to hide. This is a hygiene signal, not an attack verdict: failover pairs (VRRP/HSRP) and proxy ARP can look the same.
- **How verified:** Tracked ARP sender IP → MAC bindings and flagged IPs claimed by more than one MAC.
- **How to fix:** Find both devices (switch MAC tables), fix the static/DHCP overlap, and consider DHCP snooping + dynamic ARP inspection.
- **References:** https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sec/b_179_sec_9300_cg/configuring_dynamic_arp_inspection.html

#### NET-HYG-002 — More than one DHCP server answers

Severity: **MEDIUM**

- **Why:** Clients take whichever offer arrives first; a second (misconfigured or rogue) DHCP server can hand out a bad gateway or DNS server.
- **How verified:** Collected DHCP OFFER/ACK server identifiers.
- **How to fix:** Remove the unintended server and enable DHCP snooping on access switches.
- **References:** https://www.rfc-editor.org/rfc/rfc2131

#### NET-HYG-003 — Cleartext protocols cross a segment boundary

Severity: **HIGH**

- **Why:** Traffic that crosses the monitored boundary in clear exposes credentials and data to every network in between.
- **How verified:** Aggregated flows already flagged as cleartext by the protocol analyzers and kept those whose ends are in different segments.
- **How to fix:** Encrypt these flows (TLS/SSH/IPsec) or keep the protocol inside its segment.
- **References:** https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model

## Trial claims

A claim is produced by a host check whose setting has a network signature. The tribunal looks for evidence about the same host (matched by IP, then by MAC when the MAC is not a router's) and returns a verdict:

| | violating evidence | only conforming evidence | no relevant evidence |
|---|---|---|---|
| **claim secure** | CONTRADICTED (FAIL) | CORROBORATED (PASS) | UNTESTED |
| **claim insecure** | CORROBORATED (weakness confirmed live, INFO) | CONTRADICTED (WARN, low) | UNTESTED |

Violating evidence about an address that no audited host claims becomes **UNCLAIMED**. Settings with no network signature (WDigest, BitLocker, …) and the firewall default-inbound action (an allow rule makes any open port legitimate) are deliberately not claims.

### trial-smb1-srv

**TRIAL-SMB1-SRV — SMB1 server disabled** (severity HIGH)

- **Contradicted by:** server accepted an SMB1 dialect; server accepted an SMB1 dialect (port 139); server accepted an SMB1 dialect (port 3389); server accepted an SMB1 dialect (port 5985); server accepted an SMB1 dialect (port 5986)
- **Corroborated by:** server refused an SMB1-only negotiation; server refused an SMB1-only negotiation (port 139); server refused an SMB1-only negotiation (port 3389); server refused an SMB1-only negotiation (port 5985); server refused an SMB1-only negotiation (port 5986)
- **If contradicted, check whether:** the SMB1 feature was disabled but the machine has not rebooted since; another device (VM, NAS, second OS) answers on the same IP or MAC; the host snapshot and the capture were taken at different times.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-smb1-cli

**TRIAL-SMB1-CLI — SMB1 client disabled** (severity MEDIUM)

- **Contradicted by:** client offered the SMB1 dialect NT LM 0.12; client offered the SMB1 dialect NT LM 0.12 (port 139); client offered the SMB1 dialect NT LM 0.12 (port 3389); client offered the SMB1 dialect NT LM 0.12 (port 5985); client offered the SMB1 dialect NT LM 0.12 (port 5986)
- **Corroborated by:** client negotiated SMB2+ directly, without an SMB1 hello; client negotiated SMB2+ directly, without an SMB1 hello (port 139); client negotiated SMB2+ directly, without an SMB1 hello (port 3389); client negotiated SMB2+ directly, without an SMB1 hello (port 5985); client negotiated SMB2+ directly, without an SMB1 hello (port 5986)
- **If contradicted, check whether:** the mrxsmb10 driver start type was changed but the machine has not rebooted; a non-Windows SMB stack on the host (e.g. a bundled Samba client) offers SMB1; another device shares the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-smb-sign

**TRIAL-SMB-SIGN — SMB server requires signing** (severity MEDIUM)

- **Contradicted by:** server NEGOTIATE response did not set SIGNING_REQUIRED; server NEGOTIATE response did not set SIGNING_REQUIRED (port 139); server NEGOTIATE response did not set SIGNING_REQUIRED (port 3389); server NEGOTIATE response did not set SIGNING_REQUIRED (port 5985); server NEGOTIATE response did not set SIGNING_REQUIRED (port 5986)
- **Corroborated by:** server NEGOTIATE response set SIGNING_REQUIRED; server NEGOTIATE response set SIGNING_REQUIRED (port 139); server NEGOTIATE response set SIGNING_REQUIRED (port 3389); server NEGOTIATE response set SIGNING_REQUIRED (port 5985); server NEGOTIATE response set SIGNING_REQUIRED (port 5986)
- **If contradicted, check whether:** the LanmanServer service was not restarted after the change; a Group Policy refresh reverted a local change; another SMB server (e.g. a NAS) answers on the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-tls-srv

**TRIAL-TLS-SRV — Legacy TLS/SSL disabled for servers (SCHANNEL)** (severity HIGH)

- **Contradicted by:** server selected SSL 3.0 / TLS 1.0 / TLS 1.1 in ServerHello; server selected SSL 3.0 / TLS 1.0 / TLS 1.1 in ServerHello (port 139); server selected SSL 3.0 / TLS 1.0 / TLS 1.1 in ServerHello (port 3389); server selected SSL 3.0 / TLS 1.0 / TLS 1.1 in ServerHello (port 5985); server selected SSL 3.0 / TLS 1.0 / TLS 1.1 in ServerHello (port 5986)
- **Corroborated by:** server refused a legacy-only ClientHello; server refused a legacy-only ClientHello (port 139); server refused a legacy-only ClientHello (port 3389); server refused a legacy-only ClientHello (port 5985); server refused a legacy-only ClientHello (port 5986)
- **If contradicted, check whether:** the service uses its own TLS library (Java, OpenSSL, Node.js, nginx) rather than SCHANNEL; SCHANNEL changes need a reboot to take effect; a TLS-terminating proxy or another device answers on the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-tls-cli

**TRIAL-TLS-CLI — Legacy TLS/SSL disabled for clients (SCHANNEL)** (severity MEDIUM)

- **Contradicted by:** client offered SSL 3.0 / TLS 1.0 / TLS 1.1 in ClientHello; client offered SSL 3.0 / TLS 1.0 / TLS 1.1 in ClientHello (port 139); client offered SSL 3.0 / TLS 1.0 / TLS 1.1 in ClientHello (port 3389); client offered SSL 3.0 / TLS 1.0 / TLS 1.1 in ClientHello (port 5985); client offered SSL 3.0 / TLS 1.0 / TLS 1.1 in ClientHello (port 5986)
- **Corroborated by:** client offered only TLS 1.2+ (supported_versions); client offered only TLS 1.2+ (supported_versions) (port 139); client offered only TLS 1.2+ (supported_versions) (port 3389); client offered only TLS 1.2+ (supported_versions) (port 5985); client offered only TLS 1.2+ (supported_versions) (port 5986)
- **If contradicted, check whether:** the application uses its own TLS stack (Chrome/BoringSSL, Firefox/NSS, Java, Python) which ignores SCHANNEL settings; .NET Framework apps without SchUseStrongCrypto may still offer old versions; SCHANNEL changes need a reboot.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-llmnr

**TRIAL-LLMNR — LLMNR disabled** (severity MEDIUM)

- **Contradicted by:** host sent an LLMNR query (UDP 5355); host sent an LLMNR query (UDP 5355) (port 139); host sent an LLMNR query (UDP 5355) (port 3389); host sent an LLMNR query (UDP 5355) (port 5985); host sent an LLMNR query (UDP 5355) (port 5986)
- **Corroborated by:** host received NXDOMAIN with no multicast fallback seen; host received NXDOMAIN with no multicast fallback seen (port 139); host received NXDOMAIN with no multicast fallback seen (port 3389); host received NXDOMAIN with no multicast fallback seen (port 5985); host received NXDOMAIN with no multicast fallback seen (port 5986)
- **If contradicted, check whether:** the policy is set under the user hive or not yet applied (gpupdate pending); a non-Windows resolver on the host (e.g. a WSL distribution or systemd-resolved in a VM) sends LLMNR; another device shares the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-nbt

**TRIAL-NBT — NetBIOS over TCP/IP disabled** (severity MEDIUM)

- **Contradicted by:** host sent a NetBIOS name query (UDP 137); host sent a NetBIOS name query (UDP 137) (port 139); host sent a NetBIOS name query (UDP 137) (port 3389); host sent a NetBIOS name query (UDP 137) (port 5985); host sent a NetBIOS name query (UDP 137) (port 5986); host answered a TCP SYN with SYN-ACK (port 139)
- **Corroborated by:** host received NXDOMAIN with no multicast fallback seen; host received NXDOMAIN with no multicast fallback seen (port 139); host received NXDOMAIN with no multicast fallback seen (port 3389); host received NXDOMAIN with no multicast fallback seen (port 5985); host received NXDOMAIN with no multicast fallback seen (port 5986); host answered a TCP SYN with RST (port 139)
- **If contradicted, check whether:** NetbiosOptions is set per interface: one adapter (VPN, Wi-Fi, virtual switch) still has it enabled; DHCP option 001 re-enabled NetBIOS on an interface left at the default (0); another device shares the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-rdp

**TRIAL-RDP — Remote Desktop disabled** (severity HIGH)

- **Contradicted by:** host answered a TCP SYN with SYN-ACK (port 3389)
- **Corroborated by:** host answered a TCP SYN with RST (port 3389)
- **If contradicted, check whether:** a third-party remote tool or port-forward listens on 3389; the policy key overrides the local fDenyTSConnections value; another device (NAT, hypervisor) answers on the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-rdp-nla

**TRIAL-RDP-NLA — RDP requires Network Level Authentication** (severity HIGH)

- **Contradicted by:** RDP server selected a protocol without CredSSP (NLA); RDP server selected a protocol without CredSSP (NLA) (port 139); RDP server selected a protocol without CredSSP (NLA) (port 3389); RDP server selected a protocol without CredSSP (NLA) (port 5985); RDP server selected a protocol without CredSSP (NLA) (port 5986)
- **Corroborated by:** RDP server selected CredSSP/NLA or demanded it; RDP server selected CredSSP/NLA or demanded it (port 139); RDP server selected CredSSP/NLA or demanded it (port 3389); RDP server selected CredSSP/NLA or demanded it (port 5985); RDP server selected CredSSP/NLA or demanded it (port 5986)
- **If contradicted, check whether:** the setting was changed on a different RDP listener than the one in use; Group Policy overrides the local UserAuthentication value; an RDP gateway or other device answers on the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-winrm

**TRIAL-WINRM — WinRM not exposed** (severity MEDIUM)

- **Contradicted by:** host answered a TCP SYN with SYN-ACK (port 5985); host answered a TCP SYN with SYN-ACK (port 5986)
- **Corroborated by:** host answered a TCP SYN with RST (port 5985); host answered a TCP SYN with RST (port 5986)
- **If contradicted, check whether:** the WinRM service was started on demand (it is a trigger-start service on some builds); another management agent listens on 5985/5986; another device shares the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

### trial-ntlmv1

**TRIAL-NTLMV1 — NTLMv1 disabled (LmCompatibilityLevel ≥ 3)** (severity HIGH)

- **Contradicted by:** host sent an NTLM AUTHENTICATE with a 24-byte (NTLMv1) response; host sent an NTLM AUTHENTICATE with a 24-byte (NTLMv1) response (port 139); host sent an NTLM AUTHENTICATE with a 24-byte (NTLMv1) response (port 3389); host sent an NTLM AUTHENTICATE with a 24-byte (NTLMv1) response (port 5985); host sent an NTLM AUTHENTICATE with a 24-byte (NTLMv1) response (port 5986)
- **Corroborated by:** host sent an NTLM AUTHENTICATE with an NTLMv2 response; host sent an NTLM AUTHENTICATE with an NTLMv2 response (port 139); host sent an NTLM AUTHENTICATE with an NTLMv2 response (port 3389); host sent an NTLM AUTHENTICATE with an NTLMv2 response (port 5985); host sent an NTLM AUTHENTICATE with an NTLMv2 response (port 5986)
- **If contradicted, check whether:** an application implements NTLM itself instead of using the Windows SSPI; the policy value differs from the local one and has not applied yet; another device shares the address.
- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.

## Scan

#### SCAN-001 — Risky TCP services accept connections

Severity: **HIGH**. Optional active check (`gainsay scan`), off by default. A full TCP connect() per port, closed immediately, rate-limited; nothing is sent or read. Open Telnet/VNC/Redis/Elasticsearch/MongoDB = FAIL; other administrative or data services = WARN. Open/closed ports are also trial evidence (RDP, WinRM, NetBIOS).
