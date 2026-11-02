package dev.gainsay.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ScheduleCommandTest {

    static AuditCommandTest.Run run(Optional<String> command, String... args) {
        CommandLine cl = Main.commandLine();
        ScheduleCommand sc = cl.getSubcommands().get("schedule").getCommand();
        sc.currentCommand = command;
        StringWriter sw = new StringWriter();
        cl.setOut(new PrintWriter(sw));
        cl.setErr(new PrintWriter(sw));
        return new AuditCommandTest.Run(cl.execute(args), sw.toString());
    }

    @Test
    void printsAWeeklySystemTaskForTheRunningExeAndNeverRegistersIt(@TempDir Path dir) {
        var r = run(Optional.of("C:\\Tools\\gainsay\\gainsay.exe"), "schedule", "--folder", dir.toString());
        assertEquals(0, r.code(), r.out());
        String out = r.out();
        assertTrue(out.contains("-Execute 'C:\\Tools\\gainsay\\gainsay.exe'"), out);
        assertTrue(out.contains("-Argument 'audit --no-open --fail-on HIGH --keep-runs 26'"), out);
        assertTrue(out.contains("-WorkingDirectory '" + dir.toAbsolutePath().normalize() + "'"), out);
        assertTrue(out.contains("New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 09:00"));
        assertTrue(out.contains("-UserId 'SYSTEM'"));
        assertTrue(out.contains("Register-ScheduledTask -TaskName 'Gainsay audit'"));
        assertTrue(out.contains("Unregister-ScheduledTask"));
        assertTrue(out.contains("does not create scheduled tasks"));
        assertTrue(out.contains("gainsay init"), "suggests a config when there is none");
    }

    @Test
    void dailyAndCustomOptions(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("gainsay.json"), "{}");
        var r = run(Optional.empty(), "schedule", "--daily", "--at", "18:30", "--seconds", "300", "--fail-on", "medium",
                "--keep-runs", "0", "--name", "Nightly posture", "--folder", dir.toString(), "--exe", "D:\\My Tools\\gainsay.exe");
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains("New-ScheduledTaskTrigger -Daily -At 18:30"));
        assertTrue(r.out().contains("-Argument 'audit --no-open --fail-on MEDIUM --seconds 300'"), r.out());
        assertTrue(r.out().contains("-Execute 'D:\\My Tools\\gainsay.exe'"));
        assertTrue(r.out().contains("-TaskName 'Nightly posture'"));
        assertFalse(r.out().contains("gainsay init"));
    }

    @Test
    void javaPlusJarAndPlaceholder() {
        // Running from the test classes, not a jar: the placeholder is printed with a hint.
        var r = run(Optional.of("C:\\jdk\\bin\\java.exe"), "schedule", "--weekly", "friday");
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains(ScheduleCommand.PLACEHOLDER_EXE));
        assertTrue(r.out().contains("-DaysOfWeek Friday"));
        assertTrue(r.out().contains("pass --exe"));
    }

    @Test
    void createsAMissingFolderFirst(@TempDir Path dir) {
        Path missing = dir.resolve("runs");
        var r = run(Optional.of("C:\\gainsay.exe"), "schedule", "--folder", missing.toString());
        assertTrue(r.out().contains("New-Item -ItemType Directory -Path '" + missing.toAbsolutePath().normalize() + "' | Out-Null"), r.out());
        assertFalse(r.out().contains("-Force"), "never -Force, even on folders");
        assertFalse(java.nio.file.Files.exists(missing), "printed, not created");
    }

    @Test
    void quotingCannotBreakOutOfTheCommand(@TempDir Path dir) throws Exception {
        Path odd = Files.createDirectories(dir.resolve("it's here"));
        var r = run(Optional.of("C:\\gainsay.exe"), "schedule", "--folder", odd.toString());
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains("it''s here"), "single quotes are doubled inside PowerShell literals");
        assertEquals("\"C:\\a b\\g.jar\"", ScheduleCommand.quoteArg("C:\\a b\\g.jar"));
        assertEquals("plain", ScheduleCommand.quoteArg("plain"));
    }

    @Test
    void badOptionsAreUsageErrors() {
        Optional<String> exe = Optional.of("C:\\gainsay.exe");
        assertEquals(2, run(exe, "schedule", "--at", "25:00").code());
        assertEquals(2, run(exe, "schedule", "--name", "x'; Remove-Item C:\\ -Recurse; '").code());
        assertEquals(2, run(exe, "schedule", "--daily", "--weekly", "monday").code());
        assertEquals(2, run(exe, "schedule", "--seconds", "2").code());
        assertEquals(2, run(exe, "schedule", "--weekly", "someday").code());
    }
}
