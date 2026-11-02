package dev.gainsay.docs;

import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.host.Check;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.net.NetChecks;
import dev.gainsay.net.synth.Scenarios;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Regenerates docs/CHECKS.md from the metadata the reports use, and writes the sample capture.
 * Run: {@code java -cp target/classes;target/test-classes dev.gainsay.docs.DocsGenerator} (":" on Linux/macOS).
 */
public final class DocsGenerator {

    public static void main(String[] args) throws Exception {
        Files.writeString(Path.of("docs", "CHECKS.md"), checks(), StandardCharsets.UTF_8);
        Scenarios.demo().write(Path.of("samples", "demo.pcap"));
        System.out.println("wrote docs/CHECKS.md and samples/demo.pcap");
    }

    static String checks() {
        StringBuilder b = new StringBuilder();
        b.append("# Check catalogue\n\n")
                .append("_Generated from the check metadata in the code (`DocsGenerator`); the same text appears in every report._\n\n")
                .append("Every check answers four questions: **what** it checks, **why** it matters, **how** Gainsay verified it, ")
                .append("and **how to fix** it. Host checks are *testimony* (what the machine says it is configured to do); network ")
                .append("checks are *evidence* (what was seen on the wire); trial claims connect the two.\n\n")
                .append("- [Host checks](#host-checks) · [Network checks](#network-checks) · [Trial claims](#trial-claims) · [Scan](#scan)\n\n");

        b.append("## Host checks\n\n");
        Map<String, List<Check>> byCat = new LinkedHashMap<>();
        for (Check c : CheckCatalog.all(HostPolicy.defaults())) {
            byCat.computeIfAbsent(c.category(), k -> new ArrayList<>()).add(c);
        }
        for (var e : byCat.entrySet()) {
            b.append("### ").append(e.getKey()).append("\n\n");
            for (Check c : e.getValue()) {
                b.append("#### ").append(c.id()).append(" — ").append(c.title()).append("\n\n")
                        .append("Severity: **").append(c.severity()).append("**")
                        .append(c.claims(new dev.gainsay.host.Snap().ds()).isEmpty() ? "" : " · emits a trial claim").append("\n\n")
                        .append("- **Why:** ").append(c.rationale()).append('\n')
                        .append("- **How verified:** ").append(c.howVerified()).append('\n')
                        .append("- **How to fix:** ").append(c.remediation()).append('\n');
                var fix = dev.gainsay.host.FixCommands.forCheck(c.id());
                if (fix != null && fix.command() != null) {
                    b.append("- **Fix command** (elevated PowerShell; printed by Gainsay, never run")
                            .append(fix.reboot() ? "; restart needed" : "").append("): `").append(fix.command()).append("`\n");
                }
                if (fix != null && fix.note() != null) {
                    b.append("- **Note:** ").append(fix.note()).append('\n');
                }
                if (!c.references().isEmpty()) {
                    b.append("- **References:** ").append(String.join(" · ", c.references())).append('\n');
                }
                b.append('\n');
            }
        }

        b.append("## Network checks\n\n");
        String cat = "";
        for (NetChecks.Info i : NetChecks.all()) {
            if (!i.category().equals(cat)) {
                cat = i.category();
                b.append("### ").append(cat).append("\n\n");
            }
            b.append("#### ").append(i.id()).append(" — ").append(i.title()).append("\n\n")
                    .append("Severity: **").append(i.severity()).append("**\n\n")
                    .append("- **Why:** ").append(i.rationale()).append('\n')
                    .append("- **How verified:** ").append(i.howVerified()).append('\n')
                    .append("- **How to fix:** ").append(i.remediation()).append('\n');
            if (!i.references().isEmpty()) {
                b.append("- **References:** ").append(String.join(" · ", i.references())).append('\n');
            }
            b.append('\n');
        }

        b.append("## Trial claims\n\n")
                .append("A claim is produced by a host check whose setting has a network signature. The tribunal looks for evidence ")
                .append("about the same host (matched by IP, then by MAC when the MAC is not a router's) and returns a verdict:\n\n")
                .append("| | violating evidence | only conforming evidence | no relevant evidence |\n|---|---|---|---|\n")
                .append("| **claim secure** | CONTRADICTED (FAIL) | CORROBORATED (PASS) | UNTESTED |\n")
                .append("| **claim insecure** | CORROBORATED (weakness confirmed live, INFO) | CONTRADICTED (WARN, low) | UNTESTED |\n\n")
                .append("Violating evidence about an address that no audited host claims becomes **UNCLAIMED**. ")
                .append("Settings with no network signature (WDigest, BitLocker, …) and the firewall default-inbound action ")
                .append("(an allow rule makes any open port legitimate) are deliberately not claims.\n\n");
        for (ClaimType t : ClaimType.values()) {
            b.append("### ").append(t.trialId().toLowerCase()).append("\n\n")
                    .append("**").append(t.trialId()).append(" — ").append(t.title()).append("** (severity ").append(t.severity()).append(")\n\n")
                    .append("- **Contradicted by:** ").append(describe(t, true)).append('\n')
                    .append("- **Corroborated by:** ").append(describe(t, false)).append('\n')
                    .append("- **If contradicted, check whether:** ").append(String.join("; ", t.explanations())).append(".\n")
                    .append("- **To put it on trial:** capture traffic that exercises it (see the evidence above) while the host is on the monitored path.\n\n");
        }

        b.append("## Scan\n\n#### SCAN-001 — Risky TCP services accept connections\n\n")
                .append("Severity: **HIGH**. Optional active check (`gainsay scan`), off by default. A full TCP connect() per port, closed ")
                .append("immediately, rate-limited; nothing is sent or read. Open Telnet/VNC/Redis/Elasticsearch/MongoDB = FAIL; other ")
                .append("administrative or data services = WARN. Open/closed ports are also trial evidence (RDP, WinRM, NetBIOS).\n");
        return b.toString();
    }

    /** Human description of the observation types that violate or conform to a claim type. */
    static String describe(ClaimType t, boolean violating) {
        List<String> out = new ArrayList<>();
        for (ObservationType o : ObservationType.values()) {
            for (int port : new int[]{0, 139, 3389, 5985, 5986}) {
                var obs = new dev.gainsay.core.verdict.Observation(o, "x", null, null, port, null, null, 1, null);
                if (violating ? t.violatedBy(obs) : t.conformedBy(obs)) {
                    out.add(o.meaning() + (port == 0 ? "" : " (port " + port + ")"));
                }
            }
        }
        return out.isEmpty() ? "—" : String.join("; ", out.stream().distinct().toList());
    }
}
