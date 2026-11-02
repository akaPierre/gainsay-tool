package dev.gainsay.net;

import dev.gainsay.core.Severity;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Static teaching metadata for every network check id. Analyzers emit findings by id; the text
 * (why / how verified / how to fix) lives here so it is identical in every report and in docs/CHECKS.md.
 */
public final class NetChecks {

    public record Info(String id, String category, Severity severity, String title, String rationale, String howVerified,
                       String remediation, List<String> references) {
    }

    public static final String CLEARTEXT = "Cleartext protocols";
    public static final String SMB = "SMB & NTLM";
    public static final String TLS = "TLS";
    public static final String NAMES = "Name resolution";
    public static final String EXPOSURE = "Exposed services";
    public static final String HYGIENE = "Network hygiene";

    private static final Map<String, Info> ALL = new LinkedHashMap<>();

    private static void add(String id, String cat, Severity sev, String title, String why, String how, String fix, String... refs) {
        ALL.put(id, new Info(id, cat, sev, title, why, how, fix, List.of(refs)));
    }

    static {
        add("NET-HTTP-001", CLEARTEXT, Severity.MEDIUM, "HTTP is used without TLS",
                "Anything sent over plain HTTP can be read and modified by anyone on the path: pages, downloads, form data and session cookies.",
                "Detected HTTP/1.x request lines at the start of TCP client streams on any port (WinRM's 5985, which encrypts its payload, is excluded).",
                "Serve the site over HTTPS only, redirect HTTP to HTTPS and enable HSTS.",
                "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security");
        add("NET-HTTP-002", CLEARTEXT, Severity.HIGH, "Credentials are sent over cleartext HTTP",
                "Basic authentication, bearer tokens and password form fields over plain HTTP hand reusable secrets to any observer.",
                "Looked for Authorization headers (Basic/Bearer) and password-like parameter names in the query or form body of cleartext requests. "
                        + "Only the presence is recorded; values are masked.",
                "Move the login and every authenticated page to HTTPS. Rotate any credential that was seen on the wire.",
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure");
        add("NET-HTTP-003", CLEARTEXT, Severity.MEDIUM, "Session cookies are set over cleartext HTTP",
                "A cookie set over HTTP travels in clear on every later request, so it can be stolen and replayed (session hijacking). "
                        + "Cookies on HTTPS pages are encrypted and cannot be checked passively.",
                "Read Set-Cookie headers in cleartext HTTP responses; cookie names are kept, values masked.",
                "Set cookies only over HTTPS with the Secure and HttpOnly attributes, and redirect HTTP to HTTPS before any cookie is issued.",
                "https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies");
        add("NET-LEGACY-001", CLEARTEXT, Severity.HIGH, "Telnet is in use",
                "Telnet sends the whole session, including the password, in clear text.",
                "Detected TCP/23 sessions or Telnet option negotiation (IAC 0xFF followed by WILL/WONT/DO/DONT) at the start of a server stream.",
                "Replace Telnet with SSH and disable the Telnet service on the device.",
                "https://www.rfc-editor.org/rfc/rfc854");
        add("NET-LEGACY-002", CLEARTEXT, Severity.HIGH, "FTP is used without TLS",
                "FTP sends USER/PASS and file contents in clear; the data channel is separate and equally exposed.",
                "Detected an FTP control session (banner 220 / USER command) without an AUTH TLS upgrade.",
                "Use SFTP or FTPS (AUTH TLS with mandatory encryption) and disable plain FTP.",
                "https://www.rfc-editor.org/rfc/rfc4217");
        add("NET-LEGACY-003", CLEARTEXT, Severity.MEDIUM, "Mail protocols are used without TLS",
                "POP3, IMAP and SMTP submission without STARTTLS expose credentials and message contents; opportunistic STARTTLS can be stripped by an "
                        + "active attacker, so authentication before the upgrade is the worst case.",
                "Followed POP3/IMAP/SMTP control streams and checked whether STLS/STARTTLS was issued, and whether AUTH/LOGIN/USER came before it.",
                "Require implicit TLS (IMAPS 993, POP3S 995, SMTPS 465) or mandatory STARTTLS, and refuse AUTH on unencrypted connections.",
                "https://www.rfc-editor.org/rfc/rfc8314");
        add("NET-LEGACY-004", CLEARTEXT, Severity.MEDIUM, "TFTP is in use",
                "TFTP has no authentication at all; anyone who can reach the server can read (and often write) files such as device configs.",
                "Detected TFTP read/write requests (UDP/69, opcodes 1 and 2).",
                "Restrict TFTP to provisioning VLANs, make it read-only, or replace it with HTTPS/SCP for configuration transfer.",
                "https://www.rfc-editor.org/rfc/rfc1350");
        add("NET-LEGACY-005", CLEARTEXT, Severity.MEDIUM, "SNMP v1/v2c with community strings",
                "SNMP v1/v2c authenticate with a cleartext community string; anyone who sees one can query (or with a write community, reconfigure) the device.",
                "Parsed the SNMP message version (BER INTEGER) of UDP/161 and /162 traffic; the community string itself is masked.",
                "Move to SNMPv3 with authPriv, or restrict v2c to a management network with ACLs and read-only communities.",
                "https://www.rfc-editor.org/rfc/rfc3414");
        add("NET-LEGACY-006", CLEARTEXT, Severity.HIGH, "rlogin/rsh/rexec are in use",
                "The Berkeley r-services trust source addresses and send everything in clear; they are trivially spoofed.",
                "Detected TCP sessions to ports 512, 513 or 514.",
                "Disable the r-services and use SSH.",
                "https://www.rfc-editor.org/rfc/rfc1282");
        add("NET-LEGACY-007", CLEARTEXT, Severity.HIGH, "LDAP simple bind without TLS",
                "An LDAP simple bind carries the user's DN and password in clear; on Active Directory that is a domain credential.",
                "Parsed LDAP BindRequest messages on TCP/389 and flagged simple authentication with a non-empty password before any StartTLS. "
                        + "Neither the DN nor the password is recorded.",
                "Use LDAPS (636) or StartTLS, prefer SASL/Kerberos binds, and on AD enforce LDAP signing and channel binding.",
                "https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server");
        add("NET-SMB-001", SMB, Severity.HIGH, "SMB1 is negotiated or offered",
                "SMBv1 is the protocol behind EternalBlue/WannaCry; it lacks pre-authentication integrity and encryption. A client offering it can be downgraded.",
                "Parsed SMB NEGOTIATE exchanges: SMB1-format requests listing 'NT LM 0.12', and SMB1 responses that accept a dialect.",
                "Remove SMB1 on servers and clients (see HOST-NETCFG-001/002) and replace devices that only speak SMB1.",
                "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3");
        add("NET-SMB-002", SMB, Severity.MEDIUM, "SMB server does not require signing",
                "Without required signing an attacker in the middle can relay NTLM authentication to the server or alter SMB traffic.",
                "Read the SecurityMode field of the server's NEGOTIATE response (SMB2: bit 0x02 SIGNING_REQUIRED; SMB1: bit 0x08).",
                "Require SMB signing on the server (HOST-NETCFG-003).",
                "https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview");
        add("NET-SMB-003", SMB, Severity.HIGH, "NTLMv1 authentication is used",
                "An NTLMv1 response can be cracked back to the account's NT hash, which is as good as the password.",
                "Found NTLMSSP AUTHENTICATE messages (raw in SMB/SPNEGO, or base64 in HTTP headers) and checked the NT response length (24 bytes = NTLMv1).",
                "Set LmCompatibilityLevel to 5 on clients and servers (HOST-CRED-004) and audit NTLM usage before blocking it.",
                "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level");
        add("NET-SMB-004", SMB, Severity.MEDIUM, "SMB crosses a network boundary",
                "SMB is meant for the local network. SMB between segments (or to/from public addresses) widens the reach of SMB worms and relay attacks.",
                "Mapped both ends of each SMB flow to a segment (from --segments or a /24 default) and flagged flows that cross segments or involve public IPs.",
                "Filter TCP/445 and 139 at segment boundaries; allow it only to the file servers that need it.",
                "https://learn.microsoft.com/windows-server/storage/file-server/smb-secure-traffic");
        add("NET-TLS-001", TLS, Severity.HIGH, "Legacy SSL/TLS versions are negotiated or offered",
                "SSL 3.0, TLS 1.0 and TLS 1.1 are deprecated (RFC 8996) and lack modern protections; a server that still agrees to them keeps every "
                        + "client one downgrade away from weak crypto.",
                "Read the version selected in ServerHello (supported_versions extension if present) and the versions offered in ClientHello. Nothing is decrypted.",
                "Disable SSL 3.0/TLS 1.0/1.1 on the server (HOST-NETCFG-009 for SCHANNEL; the app's own config otherwise) and upgrade old clients.",
                "https://www.rfc-editor.org/rfc/rfc8996");
        add("NET-TLS-002", TLS, Severity.HIGH, "Weak TLS cipher suites are negotiated or offered",
                "NULL, EXPORT, anonymous, RC4, DES and 3DES suites give no or breakable protection (FREAK, Logjam, RC4 biases, Sweet32).",
                "Classified the suite selected in ServerHello and the suites offered in ClientHello against the IANA registry.",
                "Remove the weak suites from the server's and client's TLS configuration; keep AEAD suites (AES-GCM, ChaCha20-Poly1305).",
                "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4");
        add("NET-TLS-003", TLS, Severity.MEDIUM, "Expired or self-signed certificates are presented",
                "Users and devices that accept invalid certificates cannot tell a real server from an interception proxy.",
                "Parsed the first certificate of TLS ≤ 1.2 handshakes (TLS 1.3 encrypts certificates) and checked validity dates and issuer == subject.",
                "Install certificates from a trusted (internal or public) CA and renew them before expiry.",
                "https://www.rfc-editor.org/rfc/rfc5280");
        add("NET-TLS-004", TLS, Severity.LOW, "TLS clients connect without SNI",
                "Without Server Name Indication, multi-tenant servers cannot pick the right certificate and clients may be served (and accept) the wrong one; "
                        + "it is also typical of old or custom TLS stacks.",
                "Flagged ClientHello messages to port 443 without a server_name extension.",
                "Update the client or library; connect by host name rather than IP address.",
                "https://www.rfc-editor.org/rfc/rfc6066#section-3");
        add("NET-NAME-001", NAMES, Severity.MEDIUM, "LLMNR is used on the segment",
                "LLMNR lets any host on the segment answer name lookups, which is how Responder-style tools harvest NTLM hashes.",
                "Counted LLMNR queries (UDP/5355) per source host.",
                "Disable LLMNR by Group Policy (HOST-NETCFG-006) and fix the DNS failures that trigger it.",
                "https://attack.mitre.org/techniques/T1557/001/");
        add("NET-NAME-002", NAMES, Severity.MEDIUM, "NetBIOS name service (NBT-NS) is used",
                "NBT-NS broadcast lookups can be answered by any host on the segment (NTLM hash capture), and leak host and domain names.",
                "Counted NetBIOS name queries (UDP/137) per source host.",
                "Disable NetBIOS over TCP/IP on every interface (HOST-NETCFG-007) or via DHCP option 001.",
                "https://attack.mitre.org/techniques/T1557/001/");
        add("NET-NAME-003", NAMES, Severity.LOW, "mDNS is used",
                "mDNS advertises device names and services to the whole segment and, like LLMNR, accepts answers from anyone.",
                "Counted mDNS traffic (UDP/5353) per source host.",
                "Disable mDNS where not needed (e.g. 'EnableMDNS'=0 under the DNS client parameters on Windows) or confine it to user VLANs.",
                "https://www.rfc-editor.org/rfc/rfc6762");
        add("NET-NAME-004", NAMES, Severity.LOW, "Cleartext DNS goes to public resolvers",
                "Queries that bypass the internal resolver escape filtering and logging, and travel unencrypted across the internet.",
                "Recorded DNS (UDP/53) resolvers per client and flagged public resolver addresses (or ones outside --expected-resolvers).",
                "Point clients at the internal resolver, block outbound UDP/TCP 53 except from it, and use DoT/DoH from the resolver upstream.",
                "https://www.cisa.gov/resources-tools/resources/encrypted-dns-implementation-guidance");
        add("NET-EXPOSE-001", EXPOSURE, Severity.HIGH, "Risky services are reachable",
                "Remote administration, file sharing, databases and container/cluster APIs are prime targets; reachable from another segment they are "
                        + "an invitation for lateral movement.",
                "Inferred listening services passively from SYN-ACK replies (and UDP replies from well-known ports); nothing was probed.",
                "Close the service if unused, otherwise restrict it with host and network firewalls to the hosts that need it.",
                "https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices");
        add("NET-EXPOSE-002", EXPOSURE, Severity.HIGH, "RDP is served without Network Level Authentication",
                "Without NLA (CredSSP) the server starts a full session before authentication, exposing pre-auth vulnerabilities (BlueKeep) and the logon screen.",
                "Read the protocol the server selected in its X.224 Connection Confirm (RDP_NEG_RSP): 0 = RDP security, 1 = TLS only, 2/8 = CredSSP.",
                "Require NLA on the server (HOST-NETCFG-005) and keep RDP off untrusted networks.",
                "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access");
        add("NET-HYG-001", HYGIENE, Severity.MEDIUM, "Duplicate IP address (ARP conflict)",
                "Two MAC addresses answering for one IP cause intermittent outages and make spoofing easy to hide. This is a hygiene signal, not an attack "
                        + "verdict: failover pairs (VRRP/HSRP) and proxy ARP can look the same.",
                "Tracked ARP sender IP → MAC bindings and flagged IPs claimed by more than one MAC.",
                "Find both devices (switch MAC tables), fix the static/DHCP overlap, and consider DHCP snooping + dynamic ARP inspection.",
                "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sec/b_179_sec_9300_cg/configuring_dynamic_arp_inspection.html");
        add("NET-HYG-002", HYGIENE, Severity.MEDIUM, "More than one DHCP server answers",
                "Clients take whichever offer arrives first; a second (misconfigured or rogue) DHCP server can hand out a bad gateway or DNS server.",
                "Collected DHCP OFFER/ACK server identifiers.",
                "Remove the unintended server and enable DHCP snooping on access switches.",
                "https://www.rfc-editor.org/rfc/rfc2131");
        add("NET-HYG-003", HYGIENE, Severity.HIGH, "Cleartext protocols cross a segment boundary",
                "Traffic that crosses the monitored boundary in clear exposes credentials and data to every network in between.",
                "Aggregated flows already flagged as cleartext by the protocol analyzers and kept those whose ends are in different segments.",
                "Encrypt these flows (TLS/SSH/IPsec) or keep the protocol inside its segment.",
                "https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model");
    }

    private NetChecks() {
    }

    public static Info get(String id) {
        Info i = ALL.get(id);
        if (i == null) {
            throw new IllegalArgumentException("unknown network check " + id);
        }
        return i;
    }

    public static Iterable<Info> all() {
        return ALL.values();
    }
}
