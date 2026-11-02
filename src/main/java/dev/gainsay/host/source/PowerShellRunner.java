package dev.gainsay.host.source;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Runs a PowerShell script in a child process with a timeout and a bounded output buffer.
 * The script is passed with {@code -EncodedCommand} (Base64 UTF-16LE), so no shell quoting is
 * involved and no file is written. {@code -NoProfile} prevents user profile scripts from running.
 */
final class PowerShellRunner {

    static final int MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

    record Result(int exitCode, String stdout, String stderr, boolean timedOut) {
    }

    private PowerShellRunner() {
    }

    static Result run(String script, Duration timeout) throws IOException {
        String prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
                + "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;";
        String encoded = Base64.getEncoder().encodeToString((prefix + script).getBytes(StandardCharsets.UTF_16LE));
        ProcessBuilder pb = new ProcessBuilder(List.of("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded));
        Process p = pb.start();
        p.getOutputStream().close();
        CompletableFuture<byte[]> out = CompletableFuture.supplyAsync(() -> readBounded(p.getInputStream()));
        CompletableFuture<byte[]> err = CompletableFuture.supplyAsync(() -> readBounded(p.getErrorStream()));
        boolean finished;
        try {
            finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            finished = false;
        }
        if (!finished) {
            p.destroyForcibly();
            return new Result(-1, "", "timed out after " + timeout.toSeconds() + "s", true);
        }
        String stdout = new String(out.join(), StandardCharsets.UTF_8);
        String stderr = new String(err.join(), StandardCharsets.UTF_8);
        return new Result(p.exitValue(), stdout, stderr, false);
    }

    private static byte[] readBounded(InputStream in) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        try (in) {
            int n;
            while ((n = in.read(chunk)) > 0) {
                if (buf.size() < MAX_OUTPUT_BYTES) {
                    buf.write(chunk, 0, Math.min(n, MAX_OUTPUT_BYTES - buf.size()));
                } // else keep draining so the child never blocks on a full pipe
            }
        } catch (IOException ignored) {
            // the process was killed or closed its pipe; return what we have
        }
        return buf.toByteArray();
    }
}
