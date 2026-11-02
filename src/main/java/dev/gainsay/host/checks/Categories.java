package dev.gainsay.host.checks;

/** Category names used in reports. */
final class Categories {
    static final String MALWARE = "Malware protection";
    static final String ACCOUNTS = "Account control";
    static final String FIREWALL = "Firewall";
    static final String PATCHING = "Patching";
    static final String BOOT = "Disk & boot";
    static final String NETWORK = "Network-facing settings";
    static final String CREDENTIALS = "Credential protection";
    static final String EXECUTION = "Execution & hardening";
    static final String AUDITING = "Auditing";
    static final String SOFTWARE = "Software hygiene";

    private Categories() {
    }
}
