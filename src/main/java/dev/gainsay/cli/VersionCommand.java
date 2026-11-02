package dev.gainsay.cli;

import dev.gainsay.core.Report;
import dev.gainsay.core.Version;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

@Command(name = "version", description = "Print the version.")
public final class VersionCommand implements Runnable {

    @Spec
    CommandSpec spec;

    @Override
    public void run() {
        spec.commandLine().getOut().println("gainsay " + Version.VERSION + " (report schema " + Report.SCHEMA + ")");
    }
}
