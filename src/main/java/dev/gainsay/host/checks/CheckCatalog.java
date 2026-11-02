package dev.gainsay.host.checks;

import dev.gainsay.host.Check;
import dev.gainsay.host.HostPolicy;

import java.util.List;

/** All host checks, in report order. */
public final class CheckCatalog {

    private CheckCatalog() {
    }

    public static List<Check> all(HostPolicy policy) {
        return List.of(
                new AvProductCheck(),
                new DefenderRealtimeCheck(),
                new SignatureAgeCheck(policy),
                new TamperProtectionCheck(),
                new CloudProtectionCheck(),
                new UacEnabledCheck(),
                new UacAdminPromptCheck(),
                new UacSecureDesktopCheck(),
                new BuiltinAdminCheck(),
                new GuestAccountCheck(),
                new PasswordLengthCheck(policy),
                new LockoutThresholdCheck(policy),
                new PasswordNotRequiredCheck(),
                new AutoLogonCheck(),
                new FirewallProfileCheck("HOST-FW-001", "Domain"),
                new FirewallProfileCheck("HOST-FW-002", "Private"),
                new FirewallProfileCheck("HOST-FW-003", "Public"),
                new FirewallDefaultInboundCheck(),
                new SupportedBuildCheck(policy),
                new HotfixAgeCheck(policy),
                new UpdateServiceCheck(),
                new AutoUpdatePolicyCheck(),
                new BitLockerCheck(),
                new SecureBootCheck(),
                new TpmCheck(),
                new Smb1ServerCheck(),
                new Smb1ClientCheck(),
                new SmbServerSigningCheck(),
                new SmbClientSigningCheck(),
                new RdpCheck(),
                new LlmnrCheck(),
                new NetbiosCheck(),
                new WinRmCheck(),
                new SchannelLegacyCheck(),
                new LsaProtectionCheck(),
                new CredentialGuardCheck(),
                new WDigestCheck(),
                new NtlmV1Check(),
                new SmartScreenCheck(),
                new ScriptBlockLoggingCheck(),
                new ExecutionPolicyCheck(),
                new WshCheck(),
                new AutoRunCheck(),
                new AuditPolicyCheck(),
                new EventLogSizeCheck(policy),
                new EolSoftwareCheck(policy));
    }
}
