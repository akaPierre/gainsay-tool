package dev.gainsay.core.verdict;

/**
 * Protocol facts the network module can attest to, always attributed to one address ({@code ip}) and
 * sometimes to a peer. Observations carry no payload; they are the "evidence" side of the trial.
 *
 * <p>{@link #confidence()} expresses how directly the fact reflects the host's own configuration:
 * 1.0 = the host itself put the decisive bytes on the wire; lower values = indirect inference.
 */
public enum ObservationType {
    /** Server answered an SMB1 NEGOTIATE with an SMB1 response choosing a dialect. */
    SMB1_ACCEPTED_BY_SERVER(1.0, "server accepted an SMB1 dialect"),
    /** Client offered only SMB1 dialects and the server refused (dialect index 0xFFFF or reset). */
    SMB1_REFUSED_BY_SERVER(0.9, "server refused an SMB1-only negotiation"),
    /** Client sent an SMB1-format NEGOTIATE that lists "NT LM 0.12". */
    SMB1_OFFERED_BY_CLIENT(1.0, "client offered the SMB1 dialect NT LM 0.12"),
    /** Client started with an SMB2 NEGOTIATE directly (what Windows does when the SMB1 client is removed). */
    SMB2_DIRECT_NEGOTIATE_BY_CLIENT(0.7, "client negotiated SMB2+ directly, without an SMB1 hello"),
    /** Client offered ONLY SMB1 dialects; a dependant of the peer's SMB1 server support. */
    SMB1_ONLY_CLIENT_OFFER(1.0, "client can only speak SMB1"),
    SMB_SIGNING_NOT_REQUIRED_BY_SERVER(1.0, "server NEGOTIATE response did not set SIGNING_REQUIRED"),
    SMB_SIGNING_REQUIRED_BY_SERVER(1.0, "server NEGOTIATE response set SIGNING_REQUIRED"),
    TLS_LEGACY_NEGOTIATED_BY_SERVER(1.0, "server selected SSL 3.0 / TLS 1.0 / TLS 1.1 in ServerHello"),
    /** Client offered only legacy versions and the server answered with an alert or reset. */
    TLS_LEGACY_REFUSED_BY_SERVER(0.8, "server refused a legacy-only ClientHello"),
    TLS_LEGACY_OFFERED_BY_CLIENT(0.8, "client offered SSL 3.0 / TLS 1.0 / TLS 1.1 in ClientHello"),
    TLS_MODERN_ONLY_OFFERED_BY_CLIENT(0.6, "client offered only TLS 1.2+ (supported_versions)"),
    /** Client's highest offered version is TLS 1.1 or lower; a dependant of the peer's legacy TLS support. */
    TLS_LEGACY_ONLY_CLIENT_OFFER(1.0, "client cannot do better than TLS 1.1"),
    LLMNR_QUERY_SENT(1.0, "host sent an LLMNR query (UDP 5355)"),
    NBNS_QUERY_SENT(1.0, "host sent a NetBIOS name query (UDP 137)"),
    /** DNS failure seen; with LLMNR/NBT-NS enabled, Windows would normally fall back to multicast. */
    DNS_NXDOMAIN_RECEIVED(0.5, "host received NXDOMAIN with no multicast fallback seen"),
    SERVICE_LISTENING(1.0, "host answered a TCP SYN with SYN-ACK"),
    PORT_CLOSED(0.8, "host answered a TCP SYN with RST"),
    RDP_NLA_NOT_ENFORCED(1.0, "RDP server selected a protocol without CredSSP (NLA)"),
    RDP_NLA_ENFORCED(0.8, "RDP server selected CredSSP/NLA or demanded it"),
    RDP_NON_NLA_CLIENT_REQUEST(1.0, "RDP client did not request CredSSP/NLA"),
    NTLMV1_SENT(1.0, "host sent an NTLM AUTHENTICATE with a 24-byte (NTLMv1) response"),
    NTLMV2_SENT(0.8, "host sent an NTLM AUTHENTICATE with an NTLMv2 response");

    private final double confidence;
    private final String meaning;

    ObservationType(double confidence, String meaning) {
        this.confidence = confidence;
        this.meaning = meaning;
    }

    public double confidence() {
        return confidence;
    }

    public String meaning() {
        return meaning;
    }
}
