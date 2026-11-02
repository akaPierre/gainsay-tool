package dev.gainsay.net.capture;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs an external program (no shell) with a timeout and bounded output. Injectable for tests. */
public interface CommandRunner {

    record Result(int exitCode, String output) {
    }

    Result run(List<String> command, Duration timeout) throws IOException;

    CommandRunner SYSTEM = (command, timeout) -> {
        Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
        p.getOutputStream().close();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            byte[] chunk = new byte[4096];
            try (InputStream in = p.getInputStream()) {
                int n;
                while ((n = in.read(chunk)) > 0) {
                    if (buf.size() < 256 * 1024) {
                        buf.write(chunk, 0, n);
                    }
                }
            } catch (IOException ignored) {
                // process ended
            }
        });
        reader.setDaemon(true);
        reader.start();
        try {
            if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                return new Result(-1, "timed out after " + timeout.toSeconds() + " s");
            }
            reader.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            throw new IOException("interrupted", e);
        }
        return new Result(p.exitValue(), buf.toString(Charset.defaultCharset()));
    };
}
