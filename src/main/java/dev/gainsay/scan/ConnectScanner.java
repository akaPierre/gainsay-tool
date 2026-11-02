package dev.gainsay.scan;

import dev.gainsay.core.Addresses;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Plane;
import dev.gainsay.core.Report;
import dev.gainsay.core.Severity;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.Observation;
import dev.gainsay.core.verdict.ObservationType;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Map.entry;

/**
 * Optional active check: a low-rate, full TCP connect() to a short list of ports, then an immediate
 * close. No SYN scanning, no payload is sent, nothing is read (no banner grabbing), no retries.
 * Results become findings and trial evidence (listening/closed ports), merged into the same report.
 */
public final class ConnectScanner {

    public static final List<Integer> DEFAULT_PORTS = List.of(21, 22, 23, 25, 80, 110, 135, 139, 143, 389, 443, 445, 1433, 3306, 3389,
            5432, 5900, 5985, 5986, 6379, 9200, 27017);
    public static final int MAX_PORTS = 64;
    public static final int MAX_ATTEMPTS = 10_000;

    static final Map<Integer, String> NAMES = Map.ofEntries(entry(21, "FTP"), entry(22, "SSH"), entry(23, "Telnet"), entry(25, "SMTP"),
            entry(80, "HTTP"), entry(110, "POP3"), entry(135, "MS-RPC"), entry(139, "NetBIOS session"), entry(143, "IMAP"),
            entry(389, "LDAP"), entry(443, "HTTPS"), entry(445, "SMB"), entry(1433, "MS SQL"), entry(3306, "MySQL"), entry(3389, "RDP"),
            entry(5432, "PostgreSQL"), entry(5900, "VNC"), entry(5985, "WinRM HTTP"), entry(5986, "WinRM HTTPS"), entry(6379, "Redis"),
            entry(9200, "Elasticsearch"), entry(27017, "MongoDB"));
    /** Open = FAIL: cleartext remote shells and services that are unauthenticated by default. */
    static final Set<Integer> HIGH_RISK = Set.of(23, 5900, 6379, 9200, 27017);
    /** Open = WARN: worth knowing, may be legitimate. */
    static final Set<Integer> NOTEWORTHY = Set.of(21, 25, 110, 135, 139, 143, 389, 445, 1433, 3306, 3389, 5432, 5985, 5986);

    public enum Result { OPEN, CLOSED, FILTERED }

    /** The one network operation: connect, then close. Injectable for tests. */
    public interface Connector {
        Result connect(byte[] address, int port, int timeoutMs);

        Connector TCP = (address, port, timeoutMs) -> {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(InetAddress.getByAddress(address), port), timeoutMs);
                return Result.OPEN; // closed immediately by try-with-resources; nothing written or read
            } catch (ConnectException e) {
                return Result.CLOSED;
            } catch (SocketTimeoutException e) {
                return Result.FILTERED;
            } catch (IOException e) {
                return Result.FILTERED;
            }
        };
    }

    private final Connector connector;
    private final RateLimiter limiter;
    private final int timeoutMs;

    public ConnectScanner(Connector connector, RateLimiter limiter, int timeoutMs) {
        this.connector = connector;
        this.limiter = limiter;
        this.timeoutMs = timeoutMs;
    }

    public Report scan(List<byte[]> targets, List<Integer> ports) throws InterruptedException {
        if (ports.isEmpty() || ports.size() > MAX_PORTS) {
            throw new IllegalArgumentException("between 1 and " + MAX_PORTS + " ports are allowed");
        }
        if ((long) targets.size() * ports.size() > MAX_ATTEMPTS) {
            throw new IllegalArgumentException("targets × ports exceeds " + MAX_ATTEMPTS + " connection attempts");
        }
        Report r = new Report();
        r.kinds.add("scan");
        Instant start = Instant.now();
        int open = 0, attempts = 0;
        for (byte[] t : targets) {
            String ip = Addresses.format(t, 0, t.length);
            for (int port : ports) {
                limiter.acquire();
                attempts++;
                Result res = connector.connect(t, port, timeoutMs);
                Instant now = Instant.now();
                String reproduce = "Test-NetConnection -ComputerName " + ip + " -Port " + port + "   # or: nc -zv " + ip + " " + port;
                if (res == Result.OPEN) {
                    open++;
                    r.observations.add(new Observation(ObservationType.SERVICE_LISTENING, ip, null, null, port, now, now, 1,
                            new Evidence("scan", ip + ":" + port, "TCP connect succeeded", reproduce)));
                    String name = NAMES.getOrDefault(port, "tcp/" + port);
                    if (HIGH_RISK.contains(port) || NOTEWORTHY.contains(port)) {
                        r.findings.add(finding(ip, port, name, HIGH_RISK.contains(port) ? Status.FAIL : Status.WARN, reproduce, now));
                    }
                } else if (res == Result.CLOSED) {
                    r.observations.add(new Observation(ObservationType.PORT_CLOSED, ip, null, null, port, now, now, 1,
                            new Evidence("scan", ip + ":" + port, "TCP connect refused (RST)", reproduce)));
                }
            }
        }
        if (r.findings.isEmpty()) {
            r.findings.add(base().status(Status.PASS).summary("No risky service answered on " + targets.size() + " target(s) × " + ports.size() + " port(s).")
                    .seen(start, Instant.now()).build());
        }
        r.notes.add("Active connect check: " + attempts + " connection attempt(s), " + open + " open, rate-limited to "
                + (1_000_000_000L / limiter.intervalNanos()) + "/s; connect-only, no data sent or read.");
        return r;
    }

    private Finding finding(String ip, int port, String name, Status st, String reproduce, Instant now) {
        return base().status(st).subject(ip + ":" + port + "/tcp").summary(name + " accepts TCP connections on " + ip + ":" + port + ".")
                .evidence(new Evidence("scan", ip + ":" + port, "TCP connect succeeded", reproduce)).seen(now, now).build();
    }

    private static Finding.Builder base() {
        return Finding.builder("SCAN-001", Plane.SCAN).category("Exposed services").title("Risky TCP services accept connections")
                .severity(Severity.HIGH)
                .rationale("A service that accepts connections is attack surface. Remote shells in clear text and databases or caches without "
                        + "authentication by default are high risk wherever they are reachable.")
                .howVerified("Full TCP connect() to each listed port, closed immediately; rate-limited, no data sent or read.")
                .remediation("Disable services that are not needed; restrict the rest with host and network firewalls to the hosts that need them.")
                .references(List.of("https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices"));
    }
}
