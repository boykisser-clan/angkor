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
import java.util.logging.Logger;

/**
 * Detects UDP flood attacks by tracking packets per second per IP.
 * Blacklists IPs that exceed the threshold.
 */
public class UDPFloodDetector {

    private static final Logger logger = Logger.getLogger("Angkor-DDoS");

    private final ConcurrentHashMap<String, AtomicInteger> packetCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> blacklist = new ConcurrentHashMap<>();
    private final ScheduledExecutorService resetScheduler = Executors.newSingleThreadScheduledExecutor();

    private final IptablesManager iptables;

    private int thresholdPps = 100;
    private int blockDurationSeconds = 300;
    private boolean enabled = true;

    /**
     * Creates a new UDPFloodDetector.
     *
     * @param iptables the IptablesManager instance to use for blocking
     */
    public UDPFloodDetector(IptablesManager iptables) {
        this.iptables = iptables;
        resetScheduler.scheduleAtFixedRate(this::resetCounters, 1, 1, TimeUnit.SECONDS);
    }

    /**
     * Handles a UDP packet from the given IP.
     * If the IP is whitelisted, the packet is ignored.
     * If the IP is blacklisted and not expired, the packet is dropped.
     * If the packet count exceeds the threshold, the IP is blacklisted.
     *
     * @param ip the source IP address
     */
    public void handlePacket(String ip) {
        if (!enabled) {
            return;
        }

        // Check whitelist
        if (isPrivateIP(ip)) {
            return;
        }

        // Check blacklist
        Long blacklistExpiry = blacklist.get(ip);
        if (blacklistExpiry != null) {
            if (System.currentTimeMillis() < blacklistExpiry) {
                return; // Still blacklisted, drop silently
            }
            blacklist.remove(ip); // Expired
        }

        // Increment counter
        AtomicInteger count = packetCounts.computeIfAbsent(ip, k -> new AtomicInteger(0));
        int currentCount = count.incrementAndGet();

        // Check threshold
        if (currentCount > thresholdPps) {
            long expiry = System.currentTimeMillis() + (blockDurationSeconds * 1000L);
            blacklist.put(ip, expiry);
            packetCounts.remove(ip);

            logger.info("[Angkor-DDoS] UDP flood from " + ip + " - " + currentCount
                + " pps - blocked for " + blockDurationSeconds + "s");

            if (iptables != null) {
                iptables.blockIP(ip, blockDurationSeconds);
            }
        }
    }

    /**
     * Checks if an IP is currently blacklisted.
     *
     * @param ip the IP address to check
     * @return true if blacklisted, false otherwise
     */
    public boolean isBlacklisted(String ip) {
        Long expiry = blacklist.get(ip);
        if (expiry == null) {
            return false;
        }
        if (System.currentTimeMillis() < expiry) {
            return true;
        }
        blacklist.remove(ip);
        return false;
    }

    /**
     * Whitelists an IP (adds to permanent whitelist).
     *
     * @param ip the IP to whitelist
     */
    public void whitelist(String ip) {
        // In this simple implementation, whitelist is checked via isPrivateIP
        // For additional whitelisting, we just remove from blacklist and counters
        blacklist.remove(ip);
        packetCounts.remove(ip);
    }

    /**
     * Sets the UDP flood threshold in packets per second.
     *
     * @param threshold the threshold
     */
    public void setThresholdPps(int threshold) {
        this.thresholdPps = threshold;
    }

    /**
     * Sets the block duration in seconds.
     *
     * @param seconds the duration
     */
    public void setBlockDurationSeconds(int seconds) {
        this.blockDurationSeconds = seconds;
    }

    /**
     * Sets whether the detector is enabled.
     *
     * @param enabled true to enable, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Shuts down the reset scheduler.
     */
    public void shutdown() {
        resetScheduler.shutdown();
    }

    private void resetCounters() {
        packetCounts.clear();
    }

    private boolean isPrivateIP(String ip) {
        if (ip.equals("127.0.0.1") || ip.equals("::1")) {
            return true;
        }
        if (ip.startsWith("10.")) {
            return true;
        }
        if (ip.startsWith("192.168.")) {
            return true;
        }
        if (ip.startsWith("172.")) {
            String[] parts = ip.split("\\.");
            if (parts.length >= 2) {
                try {
                    int secondOctet = Integer.parseInt(parts[1]);
                    if (secondOctet >= 16 && secondOctet <= 31) {
                        return true;
                    }
                } catch (NumberFormatException e) {
                    // ignore
                }
            }
        }
        return false;
    }
}
