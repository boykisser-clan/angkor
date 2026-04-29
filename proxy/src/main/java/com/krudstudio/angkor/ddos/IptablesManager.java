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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Manages iptables rules for blocking/unblocking IPs.
 * Requires root privileges for iptables commands.
 */
public class IptablesManager {

    private static final Logger logger = Logger.getLogger("Angkor-Iptables");
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final ConcurrentHashMap<String, ScheduledFuture<?>> blockedIPs = new ConcurrentHashMap<>();

    /**
     * Checks if the current process has root privileges.
     *
     * @return true if root is available, false otherwise
     */
    public boolean isRootAvailable() {
        try {
            String output = runCommand("id -u");
            return "0".equals(output.trim());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Blocks an IP using iptables and schedules automatic unblock.
     *
     * @param ip the IP to block
     * @param durationSeconds how long to block the IP
     */
    public void blockIP(String ip, int durationSeconds) {
        if (!isValidIP(ip)) {
            logger.warning("[Angkor-Iptables] Invalid IP format: " + ip);
            return;
        }

        if (!isRootAvailable()) {
            logger.info("[Angkor-Iptables] No root - software block only");
            return;
        }

        try {
            runCommand("iptables -I INPUT -s " + ip + " -j DROP");

            // Schedule unblock
            ScheduledFuture<?> future = scheduler.schedule(() -> unblockIP(ip),
                durationSeconds, TimeUnit.SECONDS);
            blockedIPs.put(ip, future);

            logger.info("[Angkor-Iptables] Blocked " + ip + " for " + durationSeconds + "s");
        } catch (Exception e) {
            logger.warning("[Angkor-Iptables] Failed to block IP " + ip + ": " + e.getMessage());
        }
    }

    /**
     * Unblocks an IP by removing the iptables rule.
     *
     * @param ip the IP to unblock
     */
    public void unblockIP(String ip) {
        if (!isValidIP(ip)) {
            return;
        }

        try {
            runCommand("iptables -D INPUT -s " + ip + " -j DROP");
        } catch (Exception e) {
            // ignore - rule might not exist
        }

        ScheduledFuture<?> future = blockedIPs.remove(ip);
        if (future != null) {
            future.cancel(false);
        }

        logger.info("[Angkor-Iptables] Unblocked " + ip);
    }

    /**
     * Blocks a UDP port using iptables.
     *
     * @param port the port to block
     */
    public void blockUDPPort(int port) {
        if (!isRootAvailable()) {
            logger.info("[Angkor-Iptables] No root - cannot block UDP port");
            return;
        }

        try {
            runCommand("iptables -A INPUT -p udp --dport " + port + " -j DROP");
            logger.info("[Angkor-Iptables] Blocked UDP port " + port);
        } catch (Exception e) {
            logger.warning("[Angkor-Iptables] Failed to block UDP port " + port + ": " + e.getMessage());
        }
    }

    /**
     * Unblocks all currently blocked IPs. Used on proxy shutdown.
     */
    public void unblockAll() {
        for (String ip : blockedIPs.keySet()) {
            unblockIP(ip);
        }
        scheduler.shutdown();
    }

    /**
     * Shuts down the scheduler.
     */
    public void shutdown() {
        scheduler.shutdown();
    }

    private boolean isValidIP(String ip) {
        return IP_PATTERN.matcher(ip).matches();
    }

    /**
     * Runs a system command and returns the output.
     *
     * @param cmd the command to run
     * @return the command output, or empty string on error
     */
    private String runCommand(String cmd) {
        try {
            Process process = Runtime.getRuntime().exec(cmd.split(" "));
            process.waitFor(5000, TimeUnit.MILLISECONDS);

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            return output.toString();
        } catch (Exception e) {
            logger.warning("[Angkor-Iptables] Command error: " + e.getMessage());
            return "";
        }
    }
}
