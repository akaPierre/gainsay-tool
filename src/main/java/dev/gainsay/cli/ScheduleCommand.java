package dev.gainsay.cli;

import dev.gainsay.core.Severity;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DayOfWeek;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

/**
 * Prints the PowerShell commands that register {@code gainsay audit} as a Windows scheduled task.
 * Gainsay never creates the task itself: that would change the host. The task runs as SYSTEM so the
 * elevation-only reads and pktmon capture work, writes each run under the chosen folder, and its exit
 * code (1 when a FAIL at {@code --fail-on} or above exists) shows in Task Scheduler's "Last Run Result".
 */
@Command(name = "schedule", description = {"Print the PowerShell commands to run 'gainsay audit' regularly as a Windows scheduled task.",
        "Gainsay never creates the task: review the commands and run them yourself in an elevated PowerShell."})
public final class ScheduleCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    static final class When {
        @Option(names = "--daily", description = "Every day.")
        boolean daily;

        @Option(names = "--weekly", paramLabel = "DAY", description = "Once a week on this day (default: weekly on MONDAY).")
        DayOfWeek weekly;
    }

    @ArgGroup(exclusive = true)
    When when;

    @Option(names = "--at", paramLabel = "HH:MM", description = "Time of day (default ${DEFAULT-VALUE}).", defaultValue = "09:00")
    String at;

    @Option(names = "--folder", paramLabel = "DIR", description = "Working folder for the runs and gainsay.json (default: the current folder).")
    Path folder;

    @Option(names = "--name", paramLabel = "NAME", description = "Task name (default ${DEFAULT-VALUE}).", defaultValue = "Gainsay audit")
    String name;

    @Option(names = "--seconds", paramLabel = "N", description = "Capture duration for each run (default: captureSeconds in gainsay.json, else 60).")
    Integer seconds;

    @Option(names = "--fail-on", paramLabel = "SEVERITY", description = "Make the run's exit code 1 when a FAIL of at least this severity exists (default ${DEFAULT-VALUE}).", defaultValue = "HIGH")
    Severity failOn;

    @Option(names = "--keep-runs", paramLabel = "N", description = "Keep only the newest N runs (default ${DEFAULT-VALUE}; 0 keeps all).", defaultValue = "26")
    int keepRuns;

    @Option(names = "--exe", paramLabel = "PATH", description = "Path of gainsay.exe (default: the one running now).")
    Path exe;

    /** Task names are shown in Task Scheduler and pasted into a command: keep them plain. */
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}");

    /** Test hook: the program that is running now and the jar it was started from. */
    Optional<String> currentCommand = ProcessHandle.current().info().command();

    @Override
    public Integer call() throws Exception {
        PrintWriter o = spec.commandLine().getOut();
        if (!SAFE_NAME.matcher(name).matches()) {
            throw new ParameterException(spec.commandLine(), "--name may use letters, digits, spaces, '.', '_' and '-' (at most 64 characters)");
        }
        LocalTime time;
        try {
            time = LocalTime.parse(at);
        } catch (DateTimeParseException e) {
            throw new ParameterException(spec.commandLine(), "--at must be a time like 09:00 or 18:30");
        }
        if (seconds != null && (seconds < 5 || seconds > 3600)) {
            throw new ParameterException(spec.commandLine(), "--seconds must be between 5 and 3600");
        }
        if (keepRuns < 0) {
            throw new ParameterException(spec.commandLine(), "--keep-runs must be 0 or more");
        }
        Path dir = (folder != null ? folder : Path.of("")).toAbsolutePath().normalize();
        String[] program = program();

        List<String> args = new ArrayList<>();
        if (program[1] != null) {
            args.add("-jar");
            args.add(quoteArg(program[1]));
        }
        args.addAll(List.of("audit", "--no-open", "--fail-on", failOn.name()));
        if (seconds != null) {
            args.add("--seconds");
            args.add(seconds.toString());
        }
        if (keepRuns > 0) {
            args.add("--keep-runs");
            args.add(Integer.toString(keepRuns));
        }

        String trigger = when != null && when.daily
                ? "New-ScheduledTaskTrigger -Daily -At " + time
                : "New-ScheduledTaskTrigger -Weekly -DaysOfWeek " + dayName(when == null || when.weekly == null ? DayOfWeek.MONDAY : when.weekly) + " -At " + time;
        String schedule = when != null && when.daily ? "every day at " + time : "every " + dayName(when == null || when.weekly == null ? DayOfWeek.MONDAY : when.weekly) + " at " + time;

        o.println("# Gainsay does not create scheduled tasks. Review these commands, then run them in an elevated PowerShell.");
        o.println("# The task runs 'gainsay audit' " + schedule + " as SYSTEM (needed for full reads and pktmon capture).");
        o.println("# Runs are written to " + dir + (keepRuns > 0 ? "; only the newest " + keepRuns + " are kept." : "."));
        o.println("# Task Scheduler's 'Last Run Result' is 0x1 when a FAIL of " + failOn + " or above was found.");
        o.println();
        if (!Files.isDirectory(dir)) {
            o.println("New-Item -ItemType Directory -Path " + ps(dir.toString()) + " | Out-Null");
        }
        o.println(script(program[0], String.join(" ", args), dir.toString(), trigger));
        o.println();
        o.println("# Run it once now:   Start-ScheduledTask -TaskName " + ps(name));
        o.println("# Remove it:         Unregister-ScheduledTask -TaskName " + ps(name) + " -Confirm:$false");
        if (!Files.exists(dir.resolve(GainsayConfig.DEFAULT_FILE))) {
            o.println("# Tip: run 'gainsay init' in " + dir + " to name your segments and DNS servers for every run.");
        }
        if (program[0].equals(PLACEHOLDER_EXE)) {
            o.println("# Replace " + PLACEHOLDER_EXE + " with the full path of gainsay.exe, or pass --exe.");
        }
        return 0;
    }

    static final String PLACEHOLDER_EXE = "C:\\path\\to\\gainsay.exe";

    /** The four PowerShell lines that register the task. */
    String script(String execute, String argument, String workDir, String trigger) {
        return "$action = New-ScheduledTaskAction -Execute " + ps(execute) + " -Argument " + ps(argument) + " -WorkingDirectory " + ps(workDir) + "\n"
                + "$trigger = " + trigger + "\n"
                + "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n"
                + "$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -StartWhenAvailable\n"
                + "Register-ScheduledTask -TaskName " + ps(name) + " -Action $action -Trigger $trigger -Principal $principal -Settings $settings "
                + "-Description 'Read-only Gainsay posture audit (prints fixes, never applies them).'";
    }

    /** {executable, jar or null}: the standalone exe, java plus the jar, or a placeholder. */
    String[] program() {
        if (exe != null) {
            return new String[]{exe.toAbsolutePath().normalize().toString(), null};
        }
        String cmd = currentCommand.orElse("");
        String file = Path.of(cmd.isEmpty() ? "." : cmd).getFileName().toString().toLowerCase(Locale.ROOT);
        if (file.equals("gainsay.exe")) {
            return new String[]{cmd, null};
        }
        if (file.equals("java.exe") || file.equals("javaw.exe") || file.equals("java")) {
            try {
                Path jar = Path.of(ScheduleCommand.class.getProtectionDomain().getCodeSource().getLocation().toURI());
                if (jar.toString().endsWith(".jar")) {
                    return new String[]{cmd, jar.toAbsolutePath().toString()};
                }
            } catch (URISyntaxException | SecurityException | NullPointerException ignored) {
                // fall through to the placeholder
            }
        }
        return new String[]{PLACEHOLDER_EXE, null};
    }

    private static String dayName(DayOfWeek d) {
        String s = d.name().toLowerCase(Locale.ROOT);
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    /** A PowerShell single-quoted string literal: nothing inside is expanded; ' is doubled. */
    static String ps(String s) {
        return "'" + s.replace("'", "''") + "'";
    }

    /** A Windows command-line argument, quoted when it contains spaces (paths never contain '"'). */
    static String quoteArg(String s) {
        if (s.indexOf('"') >= 0) {
            throw new IllegalArgumentException("unsupported character '\"' in " + s);
        }
        return s.indexOf(' ') >= 0 || s.indexOf('\t') >= 0 ? "\"" + s + "\"" : s;
    }
}
