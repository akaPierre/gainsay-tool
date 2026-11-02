package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.ClaimStrength;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.Check;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.Snap;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** At least one passing and one failing (or unknown) case for every host check. */
class HostChecksTest {

    static final HostPolicy POLICY = HostPolicy.defaults();

    static Status status(Check c, Snap s) {
        return c.evaluate(s.ds()).status();
    }

    @Test
    void catalogIdsAreUniqueAndEveryCheckDocumentsItself() {
        Set<String> ids = new HashSet<>();
        for (Check c : CheckCatalog.all(POLICY)) {
            assertTrue(ids.add(c.id()), "duplicate id " + c.id());
            assertTrue(c.id().startsWith("HOST-"));
            assertFalse(c.rationale().isBlank(), c.id());
            assertFalse(c.howVerified().isBlank(), c.id());
            assertFalse(c.remediation().isBlank(), c.id());
        }
        assertTrue(ids.size() >= 45);
    }

    @Test
    void everyCheckSurvivesAnEmptySnapshotWithoutThrowing() {
        for (Check c : CheckCatalog.all(POLICY)) {
            Finding f = assertDoesNotThrow(() -> c.evaluate(new Snap().ds()), c.id());
            assertNotNull(f.status(), c.id());
        }
    }

    @Nested
    class Malware {
        @Test
        void avProductDecodesProductState() {
            assertEquals(Status.PASS, status(new AvProductCheck(), new Snap().query("av.products", "[{\"displayName\":\"Defender\",\"productState\":397568}]")));
            assertEquals(Status.FAIL, status(new AvProductCheck(), new Snap().query("av.products", "[{\"displayName\":\"Defender\",\"productState\":393472}]")));
            assertEquals(Status.FAIL, status(new AvProductCheck(), new Snap().query("av.products", "[]")));
            assertEquals(Status.NOT_APPLICABLE, status(new AvProductCheck(), new Snap().queryError("av.products", false)
                    .query("os.info", "[{\"ProductType\":3}]")));
        }

        @Test
        void productStateBits() {
            assertTrue(DefenderState.productEnabled(0x061100));
            assertFalse(DefenderState.productEnabled(0x060100));
            assertFalse(DefenderState.productUpToDate(0x061110));
        }

        @Test
        void realtimeProtection() {
            String on = "[{\"AntivirusEnabled\":true,\"RealTimeProtectionEnabled\":true,\"AMRunningMode\":\"Normal\"}]";
            String off = "[{\"AntivirusEnabled\":true,\"RealTimeProtectionEnabled\":false,\"AMRunningMode\":\"Normal\"}]";
            String passive = "[{\"AntivirusEnabled\":false,\"RealTimeProtectionEnabled\":false,\"AMRunningMode\":\"Passive Mode\"}]";
            assertEquals(Status.PASS, status(new DefenderRealtimeCheck(), new Snap().query("defender.status", on)));
            assertEquals(Status.FAIL, status(new DefenderRealtimeCheck(), new Snap().query("defender.status", off)));
            assertEquals(Status.NOT_APPLICABLE, status(new DefenderRealtimeCheck(), new Snap().query("defender.status", passive)
                    .query("av.products", "[{\"displayName\":\"Other AV\",\"productState\":266240}]")));
            assertEquals(Status.UNKNOWN, status(new DefenderRealtimeCheck(), new Snap().queryError("defender.status", true)));
        }

        @Test
        void signatureAge() {
            String fresh = "[{\"AntivirusEnabled\":true,\"AntivirusSignatureAge\":1,\"AMRunningMode\":\"Normal\"}]";
            String stale = "[{\"AntivirusEnabled\":true,\"AntivirusSignatureAge\":30,\"AMRunningMode\":\"Normal\"}]";
            assertEquals(Status.PASS, status(new SignatureAgeCheck(POLICY), new Snap().query("defender.status", fresh)));
            assertEquals(Status.FAIL, status(new SignatureAgeCheck(POLICY), new Snap().query("defender.status", stale)));
            assertEquals(Status.FAIL, status(new SignatureAgeCheck(POLICY), new Snap().queryError("defender.status", false)
                    .query("av.products", "[{\"displayName\":\"X\",\"productState\":266256}]")));
        }

        @Test
        void tamperAndCloud() {
            String active = "[{\"AntivirusEnabled\":true,\"IsTamperProtected\":%s,\"AMRunningMode\":\"Normal\"}]";
            assertEquals(Status.PASS, status(new TamperProtectionCheck(), new Snap().query("defender.status", active.formatted("true"))));
            assertEquals(Status.FAIL, status(new TamperProtectionCheck(), new Snap().query("defender.status", active.formatted("false"))));
            assertEquals(Status.PASS, status(new CloudProtectionCheck(), new Snap().query("defender.status", active.formatted("true"))
                    .query("defender.prefs", "[{\"MAPSReporting\":2}]")));
            assertEquals(Status.FAIL, status(new CloudProtectionCheck(), new Snap().query("defender.status", active.formatted("true"))
                    .query("defender.prefs", "[{\"MAPSReporting\":0}]")));
        }
    }

    @Nested
    class Accounts {
        @Test
        void uac() {
            assertEquals(Status.PASS, status(new UacEnabledCheck(), new Snap()));
            assertEquals(Status.FAIL, status(new UacEnabledCheck(), new Snap().dword(Reg.UAC, "EnableLUA", 0)));
            assertEquals(Status.UNKNOWN, status(new UacEnabledCheck(), new Snap().regError(Reg.UAC, "EnableLUA")));
            assertEquals(Status.FAIL, status(new UacAdminPromptCheck(), new Snap().dword(Reg.UAC, "ConsentPromptBehaviorAdmin", 0)));
            assertEquals(Status.PASS, status(new UacAdminPromptCheck(), new Snap()));
            assertEquals(Status.FAIL, status(new UacSecureDesktopCheck(), new Snap().dword(Reg.UAC, "PromptOnSecureDesktop", 0)));
            assertEquals(Status.PASS, status(new UacSecureDesktopCheck(), new Snap()));
        }

        static final String USERS = "[{\"Name\":\"%s\",\"Enabled\":%s,\"PasswordRequired\":%s,\"SID\":\"S-1-5-21-1-2-3-%d\"}]";

        @Test
        void builtinAdminByRidNotName() {
            assertEquals(Status.PASS, status(new BuiltinAdminCheck(), new Snap().query("local.users", USERS.formatted("Administrator", false, true, 500))));
            assertEquals(Status.FAIL, status(new BuiltinAdminCheck(), new Snap().query("local.users", USERS.formatted("Administrator", true, true, 500))));
            assertEquals(Status.WARN, status(new BuiltinAdminCheck(), new Snap().query("local.users", USERS.formatted("renamed", true, true, 500))));
        }

        @Test
        void guestAndBlankPasswords() {
            assertEquals(Status.FAIL, status(new GuestAccountCheck(), new Snap().query("local.users", USERS.formatted("Guest", true, false, 501))));
            assertEquals(Status.PASS, status(new GuestAccountCheck(), new Snap().query("local.users", USERS.formatted("Guest", false, false, 501))));
            assertEquals(Status.WARN, status(new PasswordNotRequiredCheck(), new Snap().query("local.users", USERS.formatted("kiosk", true, false, 1001))));
            assertEquals(Status.PASS, status(new PasswordNotRequiredCheck(), new Snap().query("local.users", USERS.formatted("kiosk", false, false, 1001))));
        }

        static String netAccounts(String minLen, String lockout) {
            return "[\"Force user logoff how long after time expires?: Never\",\"Minimum password age (days): 0\","
                    + "\"Maximum password age (days): 42\",\"Minimum password length: " + minLen + "\","
                    + "\"Length of password history maintained: None\",\"Lockout threshold: " + lockout + "\","
                    + "\"Lockout duration (minutes): 30\",\"Lockout observation window (minutes): 30\"]";
        }

        @Test
        void passwordPolicy() {
            assertEquals(Status.PASS, status(new PasswordLengthCheck(POLICY), new Snap().query("net.accounts", netAccounts("14", "5"))));
            assertEquals(Status.WARN, status(new PasswordLengthCheck(POLICY), new Snap().query("net.accounts", netAccounts("8", "5"))));
            assertEquals(Status.FAIL, status(new PasswordLengthCheck(POLICY), new Snap().query("net.accounts", netAccounts("0", "5"))));
            assertEquals(Status.FAIL, status(new LockoutThresholdCheck(POLICY), new Snap().query("net.accounts", netAccounts("14", "Never"))));
            assertEquals(Status.PASS, status(new LockoutThresholdCheck(POLICY), new Snap().query("net.accounts", netAccounts("14", "5"))));
            assertEquals(Status.WARN, status(new LockoutThresholdCheck(POLICY), new Snap().query("net.accounts", netAccounts("14", "50"))));
        }

        @Test
        void localisedNetAccountsFallsBackToLinePosition() {
            String pt = "[\"Forçar logoff: Nunca\",\"Tempo mínimo: 0\",\"Tempo máximo: 42\",\"Comprimento mínimo da senha: 12\","
                    + "\"Histórico: Nenhum\",\"Limite de bloqueio: Nunca\",\"Duração: 30\",\"Janela: 30\"]";
            assertEquals(Status.WARN, status(new PasswordLengthCheck(POLICY), new Snap().query("net.accounts", pt)));
            assertEquals(Status.FAIL, status(new LockoutThresholdCheck(POLICY), new Snap().query("net.accounts", pt)));
        }

        @Test
        void autoLogonNeverReadsThePassword() {
            Finding f = new AutoLogonCheck().evaluate(new Snap().query("winlogon.autologon", "[{\"AutoAdminLogon\":\"1\",\"DefaultPasswordPresent\":true}]").ds());
            assertEquals(Status.FAIL, f.status());
            assertTrue(f.evidence().get(0).detail().contains("value not read"));
            assertEquals(Status.PASS, status(new AutoLogonCheck(), new Snap().query("winlogon.autologon", "[{\"AutoAdminLogon\":\"0\",\"DefaultPasswordPresent\":false}]")));
            assertEquals(Status.WARN, status(new AutoLogonCheck(), new Snap().query("winlogon.autologon", "[{\"AutoAdminLogon\":\"0\",\"DefaultPasswordPresent\":true}]")));
        }
    }

    @Nested
    class FirewallAndPatching {
        static final String FW = "[{\"Name\":\"Domain\",\"Enabled\":\"True\",\"DefaultInboundAction\":\"Block\"},"
                + "{\"Name\":\"Private\",\"Enabled\":\"True\",\"DefaultInboundAction\":\"NotConfigured\"},"
                + "{\"Name\":\"Public\",\"Enabled\":\"False\",\"DefaultInboundAction\":\"Allow\"}]";

        @Test
        void firewallProfiles() {
            assertEquals(Status.PASS, status(new FirewallProfileCheck("HOST-FW-001", "Domain"), new Snap().query("firewall.profiles", FW)));
            assertEquals(Status.FAIL, status(new FirewallProfileCheck("HOST-FW-003", "Public"), new Snap().query("firewall.profiles", FW)));
            assertEquals(Status.FAIL, status(new FirewallDefaultInboundCheck(), new Snap().query("firewall.profiles", FW)));
            assertEquals(Status.PASS, status(new FirewallDefaultInboundCheck(), new Snap().query("firewall.profiles",
                    "[{\"Name\":\"Domain\",\"DefaultInboundAction\":\"NotConfigured\"}]")));
        }

        @Test
        void supportedBuildIsEditionAware() {
            assertEquals(Status.FAIL, status(new SupportedBuildCheck(POLICY), new Snap().build(19044, "Microsoft Windows 10 Pro")));
            assertEquals(Status.PASS, status(new SupportedBuildCheck(POLICY), new Snap().build(19044, "Microsoft Windows 10 IoT Enterprise LTSC")));
            assertEquals(Status.UNKNOWN, status(new SupportedBuildCheck(POLICY), new Snap().build(12345, "Windows Future")));
        }

        @Test
        void hotfixAge() {
            assertEquals(Status.PASS, status(new HotfixAgeCheck(POLICY), new Snap().query("hotfixes", "[{\"HotFixID\":\"KB1\",\"InstalledOn\":\"2026-10-14\"}]")));
            assertEquals(Status.WARN, status(new HotfixAgeCheck(POLICY), new Snap().query("hotfixes", "[{\"HotFixID\":\"KB1\",\"InstalledOn\":\"2026-08-20\"}]")));
            assertEquals(Status.FAIL, status(new HotfixAgeCheck(POLICY), new Snap().query("hotfixes", "[{\"HotFixID\":\"KB1\",\"InstalledOn\":\"2025-01-01\"},{\"HotFixID\":\"KB2\",\"InstalledOn\":null}]")));
        }

        @Test
        void updateServiceAndPolicy() {
            assertEquals(Status.FAIL, status(new UpdateServiceCheck(), new Snap().query("service.state", "[{\"Name\":\"wuauserv\",\"StartMode\":\"Disabled\"}]")));
            assertEquals(Status.PASS, status(new UpdateServiceCheck(), new Snap().query("service.state", "[{\"Name\":\"wuauserv\",\"StartMode\":\"Manual\"}]")));
            assertEquals(Status.FAIL, status(new AutoUpdatePolicyCheck(), new Snap().dword(Reg.WU_AU_POLICY, "NoAutoUpdate", 1)));
            assertEquals(Status.WARN, status(new AutoUpdatePolicyCheck(), new Snap().dword(Reg.WU_AU_POLICY, "AUOptions", 2)));
            assertEquals(Status.PASS, status(new AutoUpdatePolicyCheck(), new Snap()));
        }
    }

    @Nested
    class Boot {
        @Test
        void bitlockerSecureBootTpm() {
            assertEquals(Status.PASS, status(new BitLockerCheck(), new Snap().query("bitlocker", "[{\"DriveLetter\":\"C:\",\"ProtectionStatus\":1}]")));
            assertEquals(Status.FAIL, status(new BitLockerCheck(), new Snap().query("bitlocker", "[{\"DriveLetter\":\"C:\",\"ProtectionStatus\":0}]")));
            Finding denied = new BitLockerCheck().evaluate(new Snap().queryError("bitlocker", true).ds());
            assertEquals(Status.UNKNOWN, denied.status());
            assertTrue(denied.summary().contains("elevated"));
            assertEquals(Status.PASS, status(new SecureBootCheck(), new Snap().dword(Reg.SECUREBOOT, "UEFISecureBootEnabled", 1)));
            assertEquals(Status.FAIL, status(new SecureBootCheck(), new Snap().dword(Reg.SECUREBOOT, "UEFISecureBootEnabled", 0)));
            assertEquals(Status.WARN, status(new SecureBootCheck(), new Snap()));
            assertEquals(Status.PASS, status(new TpmCheck(), new Snap().query("tpm", "[{\"IsEnabled_InitialValue\":true,\"IsActivated_InitialValue\":true}]")));
            assertEquals(Status.FAIL, status(new TpmCheck(), new Snap().query("tpm", "[]")));
        }
    }

    @Nested
    class NetworkFacing {
        @Test
        void smb1ServerPrefersCmdletAndEmitsClaim() {
            Snap s = new Snap().query("smb.server", "[{\"EnableSMB1Protocol\":false}]").dword(Reg.LANMAN_SERVER, "SMB1", 1);
            assertEquals(Status.PASS, status(new Smb1ServerCheck(), s));
            Claim c = new Smb1ServerCheck().claims(s.ds()).get(0);
            assertEquals(ClaimType.SMB1_SERVER_DISABLED, c.type());
            assertTrue(c.secure());
            assertEquals(ClaimStrength.MEASURED, c.strength());
            assertEquals(Status.FAIL, status(new Smb1ServerCheck(), new Snap().queryError("smb.server", false).dword(Reg.LANMAN_SERVER, "SMB1", 1)));
            assertEquals(Status.UNKNOWN, status(new Smb1ServerCheck(), new Snap().queryError("smb.server", false)));
        }

        @Test
        void smb1Client() {
            assertEquals(Status.PASS, status(new Smb1ClientCheck(), new Snap()));
            assertEquals(Status.PASS, status(new Smb1ClientCheck(), new Snap().dword(Reg.MRXSMB10, "Start", 4)));
            Snap on = new Snap().dword(Reg.MRXSMB10, "Start", 2);
            assertEquals(Status.FAIL, status(new Smb1ClientCheck(), on));
            assertFalse(new Smb1ClientCheck().claims(on.ds()).get(0).secure());
        }

        @Test
        void smbSigningDefaultDependsOnBuild() {
            assertEquals(Status.PASS, status(new SmbClientSigningCheck(), new Snap().build(26100, "Windows 11 Pro")));
            assertEquals(Status.FAIL, status(new SmbClientSigningCheck(), new Snap().build(19045, "Windows 10 Pro")));
            assertEquals(Status.FAIL, status(new SmbServerSigningCheck(), new Snap().query("smb.server", "[{\"RequireSecuritySignature\":false}]")));
            assertEquals(Status.PASS, status(new SmbServerSigningCheck(), new Snap().build(19045, "x").dword(Reg.LANMAN_SERVER, "RequireSecuritySignature", 1)));
        }

        @Test
        void rdpPolicyWinsOverLocalAndClaimsFollow() {
            Snap s = new Snap().dword(Reg.TS_POLICY, "fDenyTSConnections", 1).dword(Reg.TS, "fDenyTSConnections", 0);
            assertEquals(Status.PASS, status(new RdpCheck(), s));
            List<Claim> claims = new RdpCheck().claims(s.ds());
            assertEquals(1, claims.size(), "no NLA claim when RDP is off");
            assertEquals(ClaimStrength.POLICY, claims.get(0).strength());

            Snap noNla = new Snap().dword(Reg.TS, "fDenyTSConnections", 0).dword(Reg.TS_RDP_TCP, "UserAuthentication", 0);
            assertEquals(Status.FAIL, status(new RdpCheck(), noNla));
            assertEquals(2, new RdpCheck().claims(noNla.ds()).size());
            assertEquals(Status.WARN, status(new RdpCheck(), new Snap().dword(Reg.TS, "fDenyTSConnections", 0)));
        }

        @Test
        void llmnrAndNetbios() {
            assertEquals(Status.FAIL, status(new LlmnrCheck(), new Snap()));
            assertEquals(ClaimStrength.DEFAULT, new LlmnrCheck().claims(new Snap().ds()).get(0).strength());
            assertEquals(Status.PASS, status(new LlmnrCheck(), new Snap().dword(Reg.DNSCLIENT_POLICY, "EnableMulticast", 0)));
            assertEquals(Status.PASS, status(new NetbiosCheck(), new Snap().query("netbt.interfaces", "[{\"Interface\":\"a\",\"NetbiosOptions\":2}]")));
            assertEquals(Status.FAIL, status(new NetbiosCheck(), new Snap().query("netbt.interfaces",
                    "[{\"Interface\":\"a\",\"NetbiosOptions\":2},{\"Interface\":\"vpn\",\"NetbiosOptions\":0}]")));
        }

        @Test
        void winrm() {
            String running = "[{\"Name\":\"WinRM\",\"StartMode\":\"Auto\",\"State\":\"Running\"}]";
            assertEquals(Status.FAIL, status(new WinRmCheck(), new Snap().query("service.state", running).query("os.info", "[{\"ProductType\":1}]")));
            assertEquals(Status.WARN, status(new WinRmCheck(), new Snap().query("service.state", running).query("os.info", "[{\"ProductType\":3}]")));
            assertEquals(Status.PASS, status(new WinRmCheck(), new Snap().query("service.state", "[{\"Name\":\"WinRM\",\"State\":\"Stopped\"}]")));
        }

        @Test
        void schannel() {
            Snap all = new Snap();
            for (String p : SchannelLegacyCheck.PROTOCOLS) {
                for (String role : List.of("Server", "Client")) {
                    all.dword(Reg.SCHANNEL + "\\" + p + "\\" + role, "Enabled", 0);
                }
            }
            assertEquals(Status.PASS, status(new SchannelLegacyCheck(), all));
            assertTrue(new SchannelLegacyCheck().claims(all.ds()).stream().allMatch(Claim::secure));
            assertEquals(Status.WARN, status(new SchannelLegacyCheck(), new Snap()));
            assertEquals(ClaimStrength.DEFAULT, new SchannelLegacyCheck().claims(new Snap().ds()).get(0).strength());
            assertEquals(Status.FAIL, status(new SchannelLegacyCheck(), new Snap().dword(Reg.SCHANNEL + "\\TLS 1.0\\Server", "Enabled", 1)));
        }
    }

    @Nested
    class Credentials {
        @Test
        void lsaCredentialGuardWdigestNtlm() {
            assertEquals(Status.PASS, status(new LsaProtectionCheck(), new Snap().dword(Reg.LSA, "RunAsPPL", 1)));
            assertEquals(Status.FAIL, status(new LsaProtectionCheck(), new Snap().dword(Reg.LSA, "RunAsPPL", 0)));
            assertEquals(Status.WARN, status(new LsaProtectionCheck(), new Snap()));
            assertEquals(Status.PASS, status(new CredentialGuardCheck(), new Snap().query("deviceguard", "[{\"SecurityServicesRunning\":[1,2]}]")));
            assertEquals(Status.FAIL, status(new CredentialGuardCheck(), new Snap().query("deviceguard", "[{\"SecurityServicesRunning\":[2]}]")));
            assertEquals(Status.FAIL, status(new WDigestCheck(), new Snap().dword(Reg.WDIGEST, "UseLogonCredential", 1)));
            assertEquals(Status.PASS, status(new WDigestCheck(), new Snap()));
            assertEquals(Status.PASS, status(new NtlmV1Check(), new Snap()));
            Snap v1 = new Snap().dword(Reg.LSA, "LmCompatibilityLevel", 1);
            assertEquals(Status.FAIL, status(new NtlmV1Check(), v1));
            assertFalse(new NtlmV1Check().claims(v1.ds()).get(0).secure());
        }
    }

    @Nested
    class Execution {
        @Test
        void smartScreen() {
            assertEquals(Status.PASS, status(new SmartScreenCheck(), new Snap()));
            assertEquals(Status.FAIL, status(new SmartScreenCheck(), new Snap().string(Reg.EXPLORER, "SmartScreenEnabled", "Off")));
            assertEquals(Status.PASS, status(new SmartScreenCheck(), new Snap().dword(Reg.SYSTEM_POLICY, "EnableSmartScreen", 1)
                    .string(Reg.EXPLORER, "SmartScreenEnabled", "Off")), "policy wins");
        }

        @Test
        void scriptLoggingPolicyWshAutorun() {
            assertEquals(Status.PASS, status(new ScriptBlockLoggingCheck(), new Snap().dword(Reg.PS_SCRIPTBLOCK_POLICY, "EnableScriptBlockLogging", 1)));
            assertEquals(Status.FAIL, status(new ScriptBlockLoggingCheck(), new Snap()));
            assertEquals(Status.WARN, status(new ExecutionPolicyCheck(), new Snap().query("ps.execpolicy",
                    "[{\"Scope\":\"MachinePolicy\",\"ExecutionPolicy\":\"Undefined\"},{\"Scope\":\"LocalMachine\",\"ExecutionPolicy\":\"Bypass\"}]")));
            assertEquals(Status.PASS, status(new ExecutionPolicyCheck(), new Snap().query("ps.execpolicy",
                    "[{\"Scope\":\"MachinePolicy\",\"ExecutionPolicy\":\"AllSigned\"},{\"Scope\":\"LocalMachine\",\"ExecutionPolicy\":\"Bypass\"}]")));
            assertEquals(Status.PASS, status(new ExecutionPolicyCheck(), new Snap().query("ps.execpolicy",
                    "[{\"Scope\":\"Process\",\"ExecutionPolicy\":\"Bypass\"},{\"Scope\":\"LocalMachine\",\"ExecutionPolicy\":\"RemoteSigned\"}]")),
                    "the query's own process scope says nothing about the machine");
            assertEquals(Status.WARN, status(new WshCheck(), new Snap()));
            assertEquals(Status.PASS, status(new WshCheck(), new Snap().dword(Reg.WSH, "Enabled", 0)));
            assertEquals(Status.WARN, status(new AutoRunCheck(), new Snap()));
            assertEquals(Status.PASS, status(new AutoRunCheck(), new Snap().dword(Reg.EXPLORER_POLICY, "NoDriveTypeAutoRun", 0xFF)));
        }
    }

    @Nested
    class Auditing {
        static final String HEADER = "\"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\"";

        static String rows(String setting) {
            StringBuilder b = new StringBuilder("[" + HEADER);
            for (String guid : AuditPolicyCheck.EXPECTED.keySet()) {
                b.append(",\"PC,System,x,").append(guid).append(',').append(setting).append(",\"");
            }
            return b.append(']').toString();
        }

        @Test
        void auditPolicy() {
            assertEquals(Status.PASS, status(new AuditPolicyCheck(), new Snap().query("auditpol", rows("Success and Failure"))));
            assertEquals(Status.FAIL, status(new AuditPolicyCheck(), new Snap().query("auditpol", rows("No Auditing"))));
            assertEquals(Status.UNKNOWN, status(new AuditPolicyCheck(), new Snap().query("auditpol", rows("Sem auditoria"))));
            assertEquals(Status.UNKNOWN, status(new AuditPolicyCheck(), new Snap().queryError("auditpol", true)));
        }

        @Test
        void eventLogSizeUnitsDiffer() {
            assertEquals(Status.PASS, status(new EventLogSizeCheck(POLICY), new Snap().dword(Reg.EVENTLOG_SECURITY_POLICY, "MaxSize", 196608)));
            assertEquals(Status.PASS, status(new EventLogSizeCheck(POLICY), new Snap().dword(Reg.EVENTLOG_SECURITY, "MaxSize", 201_326_592L)));
            assertEquals(Status.WARN, status(new EventLogSizeCheck(POLICY), new Snap()));
        }
    }

    @Nested
    class Software {
        @Test
        void eolList() {
            assertEquals(Status.FAIL, status(new EolSoftwareCheck(POLICY), new Snap().query("installed.software",
                    "[{\"DisplayName\":\"Adobe Flash Player 32 NPAPI\",\"DisplayVersion\":\"32.0\"}]")));
            assertEquals(Status.PASS, status(new EolSoftwareCheck(POLICY), new Snap().query("installed.software",
                    "[{\"DisplayName\":\"PuTTY release 0.83\",\"DisplayVersion\":\"0.83.0.0\"}]")));
            assertEquals(Status.FAIL, status(new EolSoftwareCheck(POLICY), new Snap().query("installed.software",
                    "[{\"DisplayName\":\"PuTTY release 0.76\",\"DisplayVersion\":\"0.76.0.0\"}]")));
        }
    }
}
