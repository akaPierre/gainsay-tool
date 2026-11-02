package dev.gainsay.cli;

import dev.gainsay.core.Report;
import dev.gainsay.report.ReportWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "trial", description = "Cross-examine host testimony (host report.json) against network evidence (net/scan report.json).")
public final class TrialCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Mixin
    OutputOptions output;

    @Option(names = "--host", paramLabel = "host.json", split = ",", required = true, description = "One or more host reports (testimony).")
    List<Path> hosts;

    @Option(names = "--net", paramLabel = "net.json", split = ",", required = true, description = "One or more net/scan reports (evidence).")
    List<Path> nets;

    @Override
    public Integer call() throws Exception {
        List<Report> reports = new ArrayList<>();
        for (Path p : hosts) {
            Report r = ReportWriter.read(p);
            if (r.claims.isEmpty()) {
                spec.commandLine().getErr().println("warning: " + p + " contains no claims (is it a host report?)");
            }
            reports.add(r);
        }
        for (Path p : nets) {
            Report r = ReportWriter.read(p);
            if (r.observations.isEmpty()) {
                spec.commandLine().getErr().println("warning: " + p + " contains no network observations");
            }
            reports.add(r);
        }
        return output.finish(reports, spec.commandLine().getOut());
    }
}
