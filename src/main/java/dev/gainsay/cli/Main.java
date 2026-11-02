package dev.gainsay.cli;

import dev.gainsay.core.Version;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

/**
 * Entry point. Exit codes: 0 ok, 1 findings at/above {@code --fail-on}, 2 usage error, 3 runtime error.
 */
@Command(name = "gainsay", mixinStandardHelpOptions = true, version = "gainsay " + Version.VERSION,
        description = {"Cross-examines a machine's security settings (testimony) against what its traffic shows (evidence).",
                "Defensive and read-only: it never changes the host and is passive on the network unless 'scan' is used with explicit authorization."},
        subcommands = {AuditCommand.class, ExplainCommand.class, InitCommand.class, ScheduleCommand.class, HostCommand.class, NetCommand.class, TrialCommand.class, ScanCommand.class, ReportCommand.class,
                ListChecksCommand.class, ListIfacesCommand.class, VersionCommand.class})
public final class Main implements Runnable {

    public static final int EXIT_RUNTIME = 3;

    @Spec
    CommandSpec spec;

    @Override
    public void run() {
        spec.commandLine().usage(spec.commandLine().getOut());
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(String... args) {
        return commandLine().execute(args);
    }

    public static CommandLine commandLine() {
        CommandLine cl = new CommandLine(new Main());
        cl.setCaseInsensitiveEnumValuesAllowed(true);
        cl.setExecutionExceptionHandler((ex, cmd, parseResult) -> {
            String msg = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            cmd.getErr().println("error: " + msg);
            return EXIT_RUNTIME;
        });
        return cl;
    }
}
