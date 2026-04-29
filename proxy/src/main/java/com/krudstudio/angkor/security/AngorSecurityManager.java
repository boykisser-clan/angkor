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
import java.util.logging.Logger;

/**
 * Manages all security components and initializes/shuts them down.
 */
public class AngorSecurityManager {

    private final ProxyServer server;
    private final AngorConfig config;
    private final Logger logger;

    private ReconnectChecker reconnectChecker;
    private VpnChecker vpnChecker;
    private AccountChecker accountChecker;
    private PacketRateLimiter packetRateLimiter;
    private SecurityEventListener eventListener;

    /**
     * Creates a new AngorSecurityManager.
     *
     * @param server the proxy server instance
     * @param config the Angkor configuration
     * @param logger the logger
     */
    public AngorSecurityManager(ProxyServer server, AngorConfig config, Logger logger) {
        this.server = server;
        this.config = config;
        this.logger = logger;
    }

    /**
     * Initializes all security checkers and registers the event listener.
     * Must be called after configuration is loaded.
     */
    public void initialize() {
        reconnectChecker = new ReconnectChecker();
        vpnChecker = new VpnChecker();
        vpnChecker.setApiKey(config.vpnApiKey);
        vpnChecker.setEnabled(config.vpnEnabled);
        vpnChecker.setCacheTtlMinutes(config.vpnCacheTtlMinutes);

        accountChecker = new AccountChecker();
        accountChecker.setEnabled(config.accountEnabled);
        accountChecker.setCacheTtlMinutes(config.accountCacheTtlMinutes);

        packetRateLimiter = new PacketRateLimiter();
        packetRateLimiter.setThreshold(config.packetThreshold);
        packetRateLimiter.setEnabled(config.packetLimiterEnabled);

        eventListener = new SecurityEventListener(
            reconnectChecker, vpnChecker, accountChecker,
            packetRateLimiter, config, logger
        );

        server.getEventManager().register(this, eventListener);
        logger.info("[Angkor] Security manager initialized");
    }

    /**
     * Shuts down all security components and releases resources.
     */
    public void shutdown() {
        if (vpnChecker != null) {
            vpnChecker.shutdown();
        }
        if (accountChecker != null) {
            accountChecker.shutdown();
        }
        if (packetRateLimiter != null) {
            packetRateLimiter.shutdown();
        }
        logger.info("[Angkor] Security manager shutdown");
    }

    /**
     * Gets the ReconnectChecker instance.
     *
     * @return the reconnect checker
     */
    public ReconnectChecker getReconnectChecker() {
        return reconnectChecker;
    }

    /**
     * Gets the VpnChecker instance.
     *
     * @return the VPN checker
     */
    public VpnChecker getVpnChecker() {
        return vpnChecker;
    }

    /**
     * Gets the AccountChecker instance.
     *
     * @return the account checker
     */
    public AccountChecker getAccountChecker() {
        return accountChecker;
    }

    /**
     * Gets the PacketRateLimiter instance.
     *
     * @return the packet rate limiter
     */
    public PacketRateLimiter getPacketRateLimiter() {
        return packetRateLimiter;
    }
}
