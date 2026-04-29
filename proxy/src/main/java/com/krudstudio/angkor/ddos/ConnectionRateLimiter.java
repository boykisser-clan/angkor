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

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * Rate limiter for connections using a sliding window per IP.
 * Temp-bans IPs that exceed violation thresholds.
 */
public class ConnectionRateLimiter {

    private static final Logger logger = Logger.getLogger("Angkor-DDoS");

    private final ConcurrentHashMap<String, Deque<Long>> connectionTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> violationCount = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> tempBans = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupScheduler = Executors.newSingleThreadScheduledExecutor();

    private final IptablesManager iptables;

    private int maxConnectionsPerSecond = 10;
    private int violationsBeforeBan = 5;
    private int banDurationSeconds = 300;
    private boolean enabled = true;

    /**
     * Creates a new ConnectionRateLimiter.
     *
     * @param iptables the IptablesManager instance to use for banning
     */
    public ConnectionRateLimiter(IptablesManager iptables) {
        this.iptables = iptables;
        cleanupScheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * Checks if a connection from the given IP should be allowed.
     * Uses a sliding window of 1 second to count connections.
     *
     * @param ip the IP address to check
     * @return true if the connection is allowed, false if blocked
     */
    public boolean checkConnection(String ip) {
        if (!enabled) {
            return true;
        }

        // Check temp ban
        Long banExpiry = tempBans.get(ip);
        if (banExpiry != null) {
            if (System.currentTimeMillis() < banExpiry) {
                return false; // Still banned
            }
            tempBans.remove(ip); // Expired
        }

        // Whitelist check
        if (isPrivateIP(ip)) {
            return true;
        }

        // Add current timestamp
        Deque<Long> times = connectionTimes.computeIfAbsent(ip, k -> new ArrayDeque<>());
        long now = System.currentTimeMillis();
        times.addLast(now);

        // Remove timestamps older than 1000ms
        while (!times.isEmpty() && (now - times.peekFirst()) > 1000) {
            times.pollFirst();
        }

        // Check if over limit
        if (times.size() > maxConnectionsPerSecond) {
            AtomicInteger violations = violationCount.computeIfAbsent(ip, k -> new AtomicInteger(0));
            int violationCountValue = violations.incrementAndGet();

            logger.info("[Angkor-DDoS] Connection flood " + ip + " - "
                + times.size() + "/sec violation #" + violationCountValue);

            if (violationCountValue >= violationsBeforeBan) {
                long expiry = System.currentTimeMillis() + (banDurationSeconds * 1000L);
                tempBans.put(ip, expiry);
                violationCount.remove(ip);
                connectionTimes.remove(ip);

                logger.info("[Angkor-DDoS] Temp banned " + ip + " for " + banDurationSeconds + "s");

                if (iptables != null) {
                    iptables.blockIP(ip, banDurationSeconds);
                }
            }

            return false;
        }

        return true;
    }

    /**
     * Sets the maximum connections per second before flagging a violation.
     *
     * @param max the maximum connections per second
     */
    public void setMaxConnections(int max) {
        this.maxConnectionsPerSecond = max;
    }

    /**
     * Sets the number of violations before a temp ban is issued.
     *
     * @param violations the number of violations
     */
    public void setViolationsBeforeBan(int violations) {
        this.violationsBeforeBan = violations;
    }

    /**
     * Sets the ban duration in seconds.
     *
     * @param seconds the duration
     */
    public void setBanDurationSeconds(int seconds) {
        this.banDurationSeconds = seconds;
    }

    /**
     * Sets whether the limiter is enabled.
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

    private void cleanupExpiredEntries() {
        long now = System.currentTimeMillis();

        tempBans.entrySet().removeIf(entry -> now > entry.getValue());

        violationCount.entrySet().removeIf(entry -> {
            Deque<Long> times = connectionTimes.get(entry.getKey());
            return times == null || times.isEmpty();
        });

        connectionTimes.entrySet().removeIf(entry -> {
            Deque<Long> times = entry.getValue();
            return times == null || times.isEmpty();
        });
    }

    private boolean isPrivateIP(String ip) {
        if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")) {
            return true;
        }
        return false;
    }
}
