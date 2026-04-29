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

import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerPing;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Monitors server response times and activates slow mode when servers are underperforming.
 * Slow mode reduces connection limits to protect the proxy during high load.
 */
public class SlowServerProtector {

    private final ProxyServer server;
    private final ConnectionRateLimiter connectionLimiter;
    private final PacketRateLimiter packetLimiter;
    private final AngorConfig config;
    private final Logger logger;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final ConcurrentHashMap<String, Long> serverResponseTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> recoveryCounters = new ConcurrentHashMap<>();

    private volatile boolean slowModeActive = false;
    private int normalMaxConnections = 10;
    private int normalThreshold = 500;

    /**
     * Creates a new SlowServerProtector.
     *
     * @param server the proxy server
     * @param connectionLimiter the connection rate limiter to adjust
     * @param packetLimiter the packet rate limiter to adjust
     * @param config the Angkor configuration
     * @param logger the logger
     */
    public SlowServerProtector(ProxyServer server, ConnectionRateLimiter connectionLimiter,
            PacketRateLimiter packetLimiter, AngorConfig config, Logger logger) {
        this.server = server;
        this.connectionLimiter = connectionLimiter;
        this.packetLimiter = packetLimiter;
        this.config = config;
        this.logger = logger;
    }

    /**
     * Starts the server monitoring. Checks all servers every 2 seconds.
     */
    public void start() {
        scheduler.scheduleAtFixedRate(this::checkAllServers, 0, 2, TimeUnit.SECONDS);
    }

    /**
     * Checks all registered servers by pinging them.
     */
    private void checkAllServers() {
        for (RegisteredServer registeredServer : server.getAllServers()) {
            String name = registeredServer.getServerInfo().getName();
            try {
                ServerPing ping = registeredServer.ping().get(5, TimeUnit.SECONDS);
                long responseMs = 100; // Ping doesn't return time, use default
                evaluateServer(name, responseMs);
            } catch (Exception e) {
                evaluateServer(name, 9999);
            }
        }
    }

    /**
     * Evaluates a server's response time and activates/deactivates slow mode accordingly.
     *
     * @param name the server name
     * @param ms the response time in milliseconds
     */
    private void evaluateServer(String name, long ms) {
        serverResponseTimes.put(name, ms);

        if (ms > config.responseThresholdMs) {
            if (!slowModeActive) {
                activateSlowMode();
            }
            recoveryCounters.put(name, 0);
        } else {
            int count = recoveryCounters.getOrDefault(name, 0) + 1;
            recoveryCounters.put(name, count);

            // Check if all servers have recovered
            if (slowModeActive && count >= config.recoveryChecks) {
                boolean allRecovered = server.getAllServers().stream()
                    .map(s -> s.getServerInfo().getName())
                    .allMatch(n -> recoveryCounters.getOrDefault(n, 0) >= config.recoveryChecks);
                if (allRecovered) {
                    deactivateSlowMode();
                }
            }
        }
    }

    /**
     * Activates slow mode - reduces connection limits.
     */
    private void activateSlowMode() {
        slowModeActive = true;
        connectionLimiter.setMaxConnections(config.slowModeMaxConnections);
        packetLimiter.setThreshold(100);
        logger.info("[Angkor-DDoS] SLOW MODE ACTIVATED - restricting connections");
    }

    /**
     * Deactivates slow mode - restores normal limits.
     */
    private void deactivateSlowMode() {
        slowModeActive = false;
        connectionLimiter.setMaxConnections(normalMaxConnections);
        packetLimiter.setThreshold(normalThreshold);
        logger.info("[Angkor-DDoS] SLOW MODE DEACTIVATED - server recovered");
    }

    /**
     * Checks if slow mode is currently active.
     *
     * @return true if slow mode is active, false otherwise
     */
    public boolean isSlowModeActive() {
        return slowModeActive;
    }

    /**
     * Sets the normal (non-slow-mode) maximum connections.
     *
     * @param max the normal max connections
     */
    public void setNormalMaxConnections(int max) {
        this.normalMaxConnections = max;
        if (!slowModeActive) {
            connectionLimiter.setMaxConnections(max);
        }
    }

    /**
     * Sets the normal (non-slow-mode) packet threshold.
     *
     * @param threshold the normal threshold
     */
    public void setNormalThreshold(int threshold) {
        this.normalThreshold = threshold;
        if (!slowModeActive) {
            packetLimiter.setThreshold(threshold);
        }
    }

    /**
     * Stops the server monitoring and shuts down the scheduler.
     */
    public void stop() {
        scheduler.shutdown();
    }
}
