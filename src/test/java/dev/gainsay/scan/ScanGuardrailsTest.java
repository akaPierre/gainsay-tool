package dev.gainsay.scan;

import dev.gainsay.cli.Main;
import dev.gainsay.core.Cidr;
import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class ScanGuardrailsTest {

    static final TargetPolicy NO_ALLOWLIST = new TargetPolicy(List.of());

    @Test
    void refusesWithoutAuthorizationFlag(@TempDir Path dir) {
        int code = Main.commandLine().execute("scan", "--targets", "127.0.0.1", "--ports", "1", "--out", dir.toString());
        assertEquals(2, code);
        assertFalse(Files.exists(dir.resolve("report.json")), "nothing ran, nothing written");
    }

    @Test
    void refusesPublicAddressesUnlessAllowlisted() throws Exception {
        TargetPolicy.Refused e = assertThrows(TargetPolicy.Refused.class, () -> NO_ALLOWLIST.authorise(List.of("10.0.0.1", "8.8.8.8")));
        assertTrue(e.getMessage().contains("8.8.8.8"));
        TargetPolicy allow = new TargetPolicy(List.of(Cidr.parse("203.0.113.0/29")));
        assertEquals(6, allow.authorise(List.of("203.0.113.0/29")).size(), "allowlisted range (network/broadcast skipped)");
        assertThrows(TargetPolicy.Refused.class, () -> allow.authorise(List.of("203.0.113.8")));
    }

    @Test
    void refusesPublicTargetsFromTheCli(@TempDir Path dir) {
        int code = Main.commandLine().execute("scan", "--targets", "1.1.1.1", "--i-am-authorized", "--allowlist",
                dir.resolve("none.txt").toString(), "--out", dir.toString());
        assertEquals(2, code);
    }

    @Test
    void acceptsPrivateLinkLocalAndLoopback() throws Exception {
        assertEquals(4, NO_ALLOWLIST.authorise(List.of("192.168.1.10", "172.16.0.1", "169.254.1.1", "127.0.0.1")).size());
        assertEquals(1, NO_ALLOWLIST.authorise(List.of("fd00::1")).size());
    }

    @Test
    void refusesHostNamesAndHugeRanges() {
        assertThrows(TargetPolicy.Refused.class, () -> NO_ALLOWLIST.authorise(List.of("intranet.corp.test")));
        assertThrows(TargetPolicy.Refused.class, () -> NO_ALLOWLIST.authorise(List.of("10.0.0.0/8")));
        assertThrows(TargetPolicy.Refused.class, () -> NO_ALLOWLIST.authorise(List.of()));
    }

    @Test
    void refusesExcessiveRate(@TempDir Path dir) {
        assertEquals(2, Main.commandLine().execute("scan", "--targets", "127.0.0.1", "--i-am-authorized", "--rate", "1000",
                "--out", dir.toString()));
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(RateLimiter.MAX_RATE + 1, RateLimiter.Clock.SYSTEM));
    }

    /** Fake clock: time only moves when the limiter sleeps. */
    static final class FakeClock implements RateLimiter.Clock {
        long now;
        long slept;

        @Override
        public long nanoTime() {
            return now;
        }

        @Override
        public void sleepNanos(long nanos) {
            slept += nanos;
            now += nanos;
        }
    }

    @Test
    void honoursRateLimit() throws Exception {
        FakeClock clock = new FakeClock();
        List<Long> attemptTimes = new ArrayList<>();
        ConnectScanner.Connector fake = (a, p, t) -> {
            attemptTimes.add(clock.now);
            return ConnectScanner.Result.CLOSED;
        };
        new ConnectScanner(fake, new RateLimiter(5, clock), 1000).scan(NO_ALLOWLIST.authorise(List.of("10.0.0.1", "10.0.0.2")), List.of(1, 2, 3, 4, 5));
        assertEquals(10, attemptTimes.size());
        for (int i = 1; i < attemptTimes.size(); i++) {
            assertTrue(attemptTimes.get(i) - attemptTimes.get(i - 1) >= 200_000_000L, "≥ 200 ms between attempts at 5/s");
        }
        assertEquals(9 * 200_000_000L, clock.slept);
    }

    @Test
    void connectOnlyAgainstLocalListenerAndTrialEvidence() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            int openPort = server.getLocalPort();
            CompletableFuture<Integer> received = CompletableFuture.supplyAsync(() -> {
                try (Socket s = server.accept(); InputStream in = s.getInputStream()) {
                    s.setSoTimeout(3000);
                    return in.read(); // -1 means the scanner closed without sending anything
                } catch (Exception e) {
                    return -2;
                }
            });
            int closedPort;
            try (ServerSocket tmp = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                closedPort = tmp.getLocalPort();
            }
            Report r = new ConnectScanner(ConnectScanner.Connector.TCP, new RateLimiter(50, RateLimiter.Clock.SYSTEM), 1000)
                    .scan(NO_ALLOWLIST.authorise(List.of("127.0.0.1")), List.of(openPort, closedPort));
            assertEquals(-1, received.get(5, TimeUnit.SECONDS), "no byte was sent by the scanner");
            assertTrue(r.observations.stream().anyMatch(o -> o.type() == ObservationType.SERVICE_LISTENING && o.port() == openPort));
            assertTrue(r.observations.stream().anyMatch(o -> o.type() == ObservationType.PORT_CLOSED && o.port() == closedPort));
            assertEquals(Status.PASS, r.findings.get(0).status(), "unlisted ports are recorded as evidence but not graded");
        }
    }

    @Test
    void riskyOpenPortsAreGraded() throws Exception {
        ConnectScanner.Connector allOpen = (a, p, t) -> ConnectScanner.Result.OPEN;
        Report r = new ConnectScanner(allOpen, new RateLimiter(50, new FakeClock()), 1000)
                .scan(NO_ALLOWLIST.authorise(List.of("10.0.0.5")), List.of(23, 3389, 443));
        assertEquals(Status.FAIL, r.findings.stream().filter(f -> f.subject().contains(":23/")).findFirst().orElseThrow().status());
        assertEquals(Status.WARN, r.findings.stream().filter(f -> f.subject().contains(":3389/")).findFirst().orElseThrow().status());
        assertTrue(r.findings.stream().noneMatch(f -> f.subject().contains(":443/")));
    }

    @Test
    void capsPortsAndAttempts() {
        ConnectScanner s = new ConnectScanner((a, p, t) -> ConnectScanner.Result.CLOSED, new RateLimiter(50, new FakeClock()), 1000);
        List<Integer> tooMany = new ArrayList<>();
        for (int i = 1; i <= ConnectScanner.MAX_PORTS + 1; i++) {
            tooMany.add(i);
        }
        assertThrows(IllegalArgumentException.class, () -> s.scan(List.of(new byte[]{10, 0, 0, 1}), tooMany));
    }
}
