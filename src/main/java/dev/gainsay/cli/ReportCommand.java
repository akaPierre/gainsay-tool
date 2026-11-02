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

@Command(name = "report", description = "Merge report.json files (host, net, scan). If testimony and evidence are both present, the claims are put on trial.")
public final class ReportCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Mixin
    OutputOptions output;

    @Option(names = "--inputs", paramLabel = "a.json,b.json", split = ",", required = true, description = "Reports to merge.")
    List<Path> inputs;

    @Override
    public Integer call() throws Exception {
        List<Report> reports = new ArrayList<>();
        for (Path p : inputs) {
            reports.add(ReportWriter.read(p));
        }
        return output.finish(reports, spec.commandLine().getOut());
    }
}
