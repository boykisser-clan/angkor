/*
 * Copyright (C) 2026 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Rate limiter that uses a token bucket algorithm to limit packets per second per IP.
 * Whitelisted private IPs are skipped.
 */
public class PacketRateLimiter {

    private static final Logger logger = Logger.getLogger("Angkor-Packet");

    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupScheduler = Executors.newSingleThreadScheduledExecutor();

    private int threshold = 500;
    private boolean enabled = true;

    /**
     * Creates a new PacketRateLimiter with automatic cleanup every 60 seconds.
     */
    public PacketRateLimiter() {
        cleanupScheduler.scheduleAtFixedRate(this::cleanupIdleBuckets, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * Checks if an IP is rate limited.
     * Whitelisted IPs (127.x, 10.x, 192.168.x) are never limited.
     *
     * @param ip the IP address to check
     * @return true if the IP is rate limited (should be blocked), false otherwise
     */
    public boolean isRateLimited(String ip) {
        if (!enabled) {
            return false;
        }

        // Skip whitelisted IPs
        if (isPrivateIP(ip)) {
            return false;
        }

        TokenBucket bucket = buckets.computeIfAbsent(ip, k -> new TokenBucket(threshold));
        bucket.refill();

        if (!bucket.consume()) {
            logger.info("[Angkor-Packet] Rate limit hit for " + ip);
            return true;
        }
        return false;
    }

    /**
     * Sets the packet threshold (tokens per second).
     *
     * @param packetsPerSecond the new threshold
     */
    public void setThreshold(int packetsPerSecond) {
        this.threshold = packetsPerSecond;
        // Update existing buckets
        for (TokenBucket bucket : buckets.values()) {
            bucket.setCapacity(packetsPerSecond);
        }
    }

    /**
     * Sets whether the rate limiter is enabled.
     *
     * @param enabled true to enable, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Shuts down the cleanup scheduler.
     */
    public void shutdown() {
        cleanupScheduler.shutdown();
    }

    private void cleanupIdleBuckets() {
        buckets.entrySet().removeIf(entry -> {
            TokenBucket bucket = entry.getValue();
            bucket.refill(); // Ensure accurate state
            return bucket.isFull();
        });
    }

    private boolean isPrivateIP(String ip) {
        return ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.");
    }

    /**
     * Token bucket for rate limiting using token bucket algorithm.
     */
    private static class TokenBucket {
        private final AtomicInteger tokens;
        private final AtomicLong lastRefill;
        private volatile int capacity;

        TokenBucket(int capacity) {
            this.capacity = capacity;
            this.tokens = new AtomicInteger(capacity);
            this.lastRefill = new AtomicLong(System.currentTimeMillis());
        }

        void refill() {
            long now = System.currentTimeMillis();
            long last = lastRefill.get();
            if (now - last >= 1000) {
                if (lastRefill.compareAndSet(last, now)) {
                    tokens.set(capacity);
                }
            }
        }

        boolean consume() {
            while (true) {
                int current = tokens.get();
                if (current <= 0) {
                    return false;
                }
                if (tokens.compareAndSet(current, current - 1)) {
                    return true;
                }
            }
        }

        boolean isFull() {
            return tokens.get() >= capacity;
        }

        void setCapacity(int newCapacity) {
            this.capacity = newCapacity;
        }
    }
}
