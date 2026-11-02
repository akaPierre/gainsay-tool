package dev.gainsay.scan;

/**
 * Spaces connection attempts at least {@code 1/rate} seconds apart. The clock is injectable so the
 * guardrail is testable without real sleeping.
 */
public final class RateLimiter {

    /** Hard ceiling regardless of what the user asks for. */
    public static final int MAX_RATE = 50;
    public static final int DEFAULT_RATE = 5;

    /** Time source and sleeper. */
    public interface Clock {
        long nanoTime();

        void sleepNanos(long nanos) throws InterruptedException;

        Clock SYSTEM = new Clock() {
            @Override
            public long nanoTime() {
                return System.nanoTime();
            }

            @Override
            public void sleepNanos(long nanos) throws InterruptedException {
                Thread.sleep(nanos / 1_000_000, (int) (nanos % 1_000_000));
            }
        };
    }

    private final long intervalNanos;
    private final Clock clock;
    private long next = Long.MIN_VALUE;

    public RateLimiter(int perSecond, Clock clock) {
        if (perSecond < 1 || perSecond > MAX_RATE) {
            throw new IllegalArgumentException("rate must be between 1 and " + MAX_RATE + " connections per second");
        }
        this.intervalNanos = 1_000_000_000L / perSecond;
        this.clock = clock;
    }

    /** Blocks until the next attempt is allowed. */
    public void acquire() throws InterruptedException {
        long now = clock.nanoTime();
        if (next != Long.MIN_VALUE && now < next) {
            clock.sleepNanos(next - now);
            now = next;
        }
        next = now + intervalNanos;
    }

    public long intervalNanos() {
        return intervalNanos;
    }
}
