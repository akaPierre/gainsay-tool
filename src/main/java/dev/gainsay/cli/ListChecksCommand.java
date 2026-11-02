package dev.gainsay.cli;

import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.Check;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.net.NetChecks;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.io.PrintWriter;

@Command(name = "list-checks", description = "List every host check, network analyzer check and trial claim.")
public final class ListChecksCommand implements Runnable {

    @Spec
    CommandSpec spec;

    @Override
    public void run() {
        PrintWriter out = spec.commandLine().getOut();
        out.println("Host checks (testimony):");
        for (Check c : CheckCatalog.all(HostPolicy.defaults())) {
            out.printf("  %-16s %-9s %-26s %s%n", c.id(), c.severity(), c.category(), c.title());
        }
        out.println();
        out.println("Network checks (evidence):");
        for (NetChecks.Info i : NetChecks.all()) {
            out.printf("  %-16s %-9s %-26s %s%n", i.id(), i.severity(), i.category(), i.title());
        }
        out.println();
        out.println("Trial claims (testimony that traffic can contradict):");
        for (ClaimType t : ClaimType.values()) {
            out.printf("  %-16s %-9s %s%n", t.trialId(), t.severity(), t.title());
        }
    }
}
