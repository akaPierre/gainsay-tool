package dev.gainsay.cli;

import dev.gainsay.core.Fix;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.Check;
import dev.gainsay.host.FixCommands;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.net.NetChecks;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;

@Command(name = "explain", description = "Explain one check: what it checks, why it matters, how it is verified and how to fix it.")
public final class ExplainCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(paramLabel = "ID", description = "A check id, e.g. HOST-CRED-003, NET-SMB-001 or TRIAL-SMB1-SRV (case-insensitive).")
    String id;

    @Override
    public Integer call() {
        PrintWriter out = spec.commandLine().getOut();
        String want = id.trim().toUpperCase(Locale.ROOT);
        List<String> known = new ArrayList<>();
        for (Check c : CheckCatalog.all(HostPolicy.defaults())) {
            known.add(c.id());
            if (c.id().equals(want)) {
                print(out, c.id(), c.title(), c.category() + " · host check · severity " + c.severity(), c.rationale(), c.howVerified(),
                        c.remediation(), FixCommands.forCheck(c.id()), c.references());
                return 0;
            }
        }
        for (NetChecks.Info i : NetChecks.all()) {
            known.add(i.id());
            if (i.id().equals(want)) {
                print(out, i.id(), i.title(), i.category() + " · network check (passive) · severity " + i.severity(), i.rationale(),
                        i.howVerified(), i.remediation(), null, i.references());
                return 0;
            }
        }
        for (ClaimType t : ClaimType.values()) {
            known.add(t.trialId());
            if (t.trialId().equals(want)) {
                print(out, t.trialId(), "Claim on trial: " + t.title(), "trial claim · severity " + t.severity(),
                        "A host says this is configured; traffic can prove it wrong. A contradiction usually means the setting is not in effect.",
                        "The host check's reading is compared with protocol facts recorded for the host's addresses (see docs/CHECKS.md#"
                                + t.trialId().toLowerCase(Locale.ROOT) + ").",
                        "If contradicted, check whether: " + String.join("; ", t.explanations()) + ".", null, List.of());
                return 0;
            }
        }
        out.println("Unknown check id '" + id + "'.");
        List<String> close = known.stream().filter(k -> k.startsWith(want) || k.contains(want)).limit(10).toList();
        out.println(close.isEmpty() ? "Run 'gainsay list-checks' to see all ids." : "Did you mean: " + String.join(", ", close));
        return 2;
    }

    private static void print(PrintWriter out, String id, String title, String kind, String why, String how, String fix, Fix cmd, List<String> refs) {
        out.println(Terminal.style("bold", id + " — " + title));
        out.println(Terminal.style("faint", kind));
        out.println();
        section(out, "Why it matters", why);
        section(out, "How Gainsay verifies it", how);
        section(out, "How to fix", fix);
        if (cmd != null && cmd.command() != null) {
            out.println(Terminal.style("bold", "Fix command") + Terminal.style("faint", " (elevated PowerShell; Gainsay never runs it"
                    + (cmd.reboot() ? "; restart needed" : "") + ")"));
            out.println("  " + Terminal.style("cyan", cmd.command()));
            out.println();
        }
        if (cmd != null && cmd.note() != null) {
            section(out, "Note", cmd.note());
        }
        if (!refs.isEmpty()) {
            section(out, "References", String.join("\n", refs));
        }
        out.flush();
    }

    private static void section(PrintWriter out, String head, String body) {
        out.println(Terminal.style("bold", head));
        for (String line : wrap(body, 96)) {
            out.println("  " + line);
        }
        out.println();
    }

    static List<String> wrap(String text, int width) {
        List<String> lines = new ArrayList<>();
        for (String para : text.split("\n")) {
            StringBuilder cur = new StringBuilder();
            for (String w : para.split(" ")) {
                if (cur.length() > 0 && cur.length() + 1 + w.length() > width) {
                    lines.add(cur.toString());
                    cur.setLength(0);
                }
                if (cur.length() > 0) {
                    cur.append(' ');
                }
                cur.append(w);
            }
            lines.add(cur.toString());
        }
        return lines;
    }
}
