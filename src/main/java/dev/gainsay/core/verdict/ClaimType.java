package dev.gainsay.core.verdict;

import dev.gainsay.core.Severity;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import static dev.gainsay.core.verdict.ObservationType.*;

/**
 * The catalogue of network-testable claims. For each claim type this encodes the core teaching of
 * the trial: <em>which observable behaviour would prove the setting false (violating), which would
 * support it (conforming), and which peers depend on the weak behaviour (dependants)</em>.
 *
 * <p>Host settings without any network signature (e.g. WDigest caching, BitLocker) are deliberately
 * absent: Gainsay will not pretend traffic can test them. The firewall default-inbound action is
 * also absent: an allow rule makes any listening port legitimate, so traffic alone cannot falsify it.
 */
public enum ClaimType {

    SMB1_SERVER_DISABLED("TRIAL-SMB1-SRV", "SMB1 server disabled", Severity.HIGH,
            o -> o.type() == SMB1_ACCEPTED_BY_SERVER,
            o -> o.type() == SMB1_REFUSED_BY_SERVER,
            EnumSet.of(SMB1_ONLY_CLIENT_OFFER),
            List.of("the SMB1 feature was disabled but the machine has not rebooted since",
                    "another device (VM, NAS, second OS) answers on the same IP or MAC",
                    "the host snapshot and the capture were taken at different times")),

    SMB1_CLIENT_DISABLED("TRIAL-SMB1-CLI", "SMB1 client disabled", Severity.MEDIUM,
            o -> o.type() == SMB1_OFFERED_BY_CLIENT,
            o -> o.type() == SMB2_DIRECT_NEGOTIATE_BY_CLIENT,
            EnumSet.noneOf(ObservationType.class),
            List.of("the mrxsmb10 driver start type was changed but the machine has not rebooted",
                    "a non-Windows SMB stack on the host (e.g. a bundled Samba client) offers SMB1",
                    "another device shares the address")),

    SMB_SERVER_SIGNING_REQUIRED("TRIAL-SMB-SIGN", "SMB server requires signing", Severity.MEDIUM,
            o -> o.type() == SMB_SIGNING_NOT_REQUIRED_BY_SERVER,
            o -> o.type() == SMB_SIGNING_REQUIRED_BY_SERVER,
            EnumSet.noneOf(ObservationType.class),
            List.of("the LanmanServer service was not restarted after the change",
                    "a Group Policy refresh reverted a local change",
                    "another SMB server (e.g. a NAS) answers on the address")),

    TLS_LEGACY_SERVER_DISABLED("TRIAL-TLS-SRV", "Legacy TLS/SSL disabled for servers (SCHANNEL)", Severity.HIGH,
            o -> o.type() == TLS_LEGACY_NEGOTIATED_BY_SERVER,
            o -> o.type() == TLS_LEGACY_REFUSED_BY_SERVER,
            EnumSet.of(TLS_LEGACY_ONLY_CLIENT_OFFER),
            List.of("the service uses its own TLS library (Java, OpenSSL, Node.js, nginx) rather than SCHANNEL",
                    "SCHANNEL changes need a reboot to take effect",
                    "a TLS-terminating proxy or another device answers on the address")),

    TLS_LEGACY_CLIENT_DISABLED("TRIAL-TLS-CLI", "Legacy TLS/SSL disabled for clients (SCHANNEL)", Severity.MEDIUM,
            o -> o.type() == TLS_LEGACY_OFFERED_BY_CLIENT,
            o -> o.type() == TLS_MODERN_ONLY_OFFERED_BY_CLIENT,
            EnumSet.noneOf(ObservationType.class),
            List.of("the application uses its own TLS stack (Chrome/BoringSSL, Firefox/NSS, Java, Python) which ignores SCHANNEL settings",
                    ".NET Framework apps without SchUseStrongCrypto may still offer old versions",
                    "SCHANNEL changes need a reboot")),

    LLMNR_DISABLED("TRIAL-LLMNR", "LLMNR disabled", Severity.MEDIUM,
            o -> o.type() == LLMNR_QUERY_SENT,
            o -> o.type() == DNS_NXDOMAIN_RECEIVED,
            EnumSet.noneOf(ObservationType.class),
            List.of("the policy is set under the user hive or not yet applied (gpupdate pending)",
                    "a non-Windows resolver on the host (e.g. a WSL distribution or systemd-resolved in a VM) sends LLMNR",
                    "another device shares the address")),

    NETBIOS_DISABLED("TRIAL-NBT", "NetBIOS over TCP/IP disabled", Severity.MEDIUM,
            o -> o.type() == NBNS_QUERY_SENT || (o.type() == SERVICE_LISTENING && o.port() == 139),
            o -> o.type() == DNS_NXDOMAIN_RECEIVED || (o.type() == PORT_CLOSED && o.port() == 139),
            EnumSet.noneOf(ObservationType.class),
            List.of("NetbiosOptions is set per interface: one adapter (VPN, Wi-Fi, virtual switch) still has it enabled",
                    "DHCP option 001 re-enabled NetBIOS on an interface left at the default (0)",
                    "another device shares the address")),

    RDP_DISABLED("TRIAL-RDP", "Remote Desktop disabled", Severity.HIGH,
            o -> o.type() == SERVICE_LISTENING && o.port() == 3389,
            o -> o.type() == PORT_CLOSED && o.port() == 3389,
            EnumSet.noneOf(ObservationType.class),
            List.of("a third-party remote tool or port-forward listens on 3389",
                    "the policy key overrides the local fDenyTSConnections value",
                    "another device (NAT, hypervisor) answers on the address")),

    RDP_NLA_REQUIRED("TRIAL-RDP-NLA", "RDP requires Network Level Authentication", Severity.HIGH,
            o -> o.type() == RDP_NLA_NOT_ENFORCED,
            o -> o.type() == RDP_NLA_ENFORCED,
            EnumSet.of(RDP_NON_NLA_CLIENT_REQUEST),
            List.of("the setting was changed on a different RDP listener than the one in use",
                    "Group Policy overrides the local UserAuthentication value",
                    "an RDP gateway or other device answers on the address")),

    WINRM_NOT_EXPOSED("TRIAL-WINRM", "WinRM not exposed", Severity.MEDIUM,
            o -> o.type() == SERVICE_LISTENING && (o.port() == 5985 || o.port() == 5986),
            o -> o.type() == PORT_CLOSED && (o.port() == 5985 || o.port() == 5986),
            EnumSet.noneOf(ObservationType.class),
            List.of("the WinRM service was started on demand (it is a trigger-start service on some builds)",
                    "another management agent listens on 5985/5986",
                    "another device shares the address")),

    NTLMV1_DISABLED("TRIAL-NTLMV1", "NTLMv1 disabled (LmCompatibilityLevel ≥ 3)", Severity.HIGH,
            o -> o.type() == NTLMV1_SENT,
            o -> o.type() == NTLMV2_SENT,
            EnumSet.noneOf(ObservationType.class),
            List.of("an application implements NTLM itself instead of using the Windows SSPI",
                    "the policy value differs from the local one and has not applied yet",
                    "another device shares the address"));

    private final String trialId;
    private final String title;
    private final Severity severity;
    private final Predicate<Observation> violating;
    private final Predicate<Observation> conforming;
    private final Set<ObservationType> dependants;
    private final List<String> explanations;

    ClaimType(String trialId, String title, Severity severity, Predicate<Observation> violating,
              Predicate<Observation> conforming, Set<ObservationType> dependants, List<String> explanations) {
        this.trialId = trialId;
        this.title = title;
        this.severity = severity;
        this.violating = violating;
        this.conforming = conforming;
        this.dependants = dependants;
        this.explanations = explanations;
    }

    public String trialId() { return trialId; }
    public String title() { return title; }
    public Severity severity() { return severity; }
    public boolean violatedBy(Observation o) { return violating.test(o); }
    public boolean conformedBy(Observation o) { return conforming.test(o); }
    public boolean isDependant(Observation o) { return dependants.contains(o.type()); }
    /** Plausible innocent and not-so-innocent reasons for a contradiction; shown in the report to guide investigation. */
    public List<String> explanations() { return explanations; }
}
