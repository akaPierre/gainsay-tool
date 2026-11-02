package dev.gainsay.host.checks;

/** Registry keys read by host checks (all under HKLM, all read-only). */
final class Reg {
    static final String UAC = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    static final String LSA = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa";
    static final String WDIGEST = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
    static final String SCHANNEL = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols";
    static final String LANMAN_SERVER = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
    static final String LANMAN_WORKSTATION = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters";
    static final String MRXSMB10 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10";
    static final String TS_POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";
    static final String TS = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    static final String TS_RDP_TCP = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
    static final String DNSCLIENT_POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
    static final String SECUREBOOT = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";
    static final String WU_AU_POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";
    static final String SYSTEM_POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System";
    static final String EXPLORER = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer";
    static final String EXPLORER_POLICY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    static final String PS_SCRIPTBLOCK_POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";
    static final String WSH = "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings";
    static final String EVENTLOG_SECURITY = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security";
    static final String EVENTLOG_SECURITY_POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security";

    private Reg() {
    }
}
