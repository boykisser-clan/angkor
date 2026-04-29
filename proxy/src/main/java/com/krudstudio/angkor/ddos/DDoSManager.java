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
 * Coordinates all DDoS protection components.
 * Manages lifecycle of UDP detector, connection limiter, slow server protector, and iptables.
 */
public class DDoSManager {

    private final ProxyServer server;
    private final AngorConfig config;
    private final Logger logger;

    private IptablesManager iptables;
    private UDPFloodDetector udpDetector;
    private ConnectionRateLimiter connLimiter;
    private SlowServerProtector slowProtector;
    private NettyUDPChannel udpChannel;
    private DDoSEventListener eventListener;
    private PacketRateLimiter packetLimiter;

    /**
     * Creates a new DDoSManager.
     *
     * @param server the proxy server instance
     * @param config the Angkor configuration
     * @param logger the logger
     */
    public DDoSManager(ProxyServer server, AngorConfig config, Logger logger) {
        this.server = server;
        this.config = config;
        this.logger = logger;
    }

    /**
     * Initializes all DDoS protection components and starts monitoring.
     */
    public void initialize() {
        iptables = new IptablesManager();
        udpDetector = new UDPFloodDetector(iptables);
        udpDetector.setThresholdPps(config.udpThresholdPps);
        udpDetector.setBlockDurationSeconds(config.udpBlockDurationSeconds);
        udpDetector.setEnabled(config.udpProtectionEnabled);

        connLimiter = new ConnectionRateLimiter(iptables);
        connLimiter.setMaxConnections(config.maxConnectionsPerSecond);
        connLimiter.setViolationsBeforeBan(config.violationsBeforeBan);
        connLimiter.setBanDurationSeconds(config.banDurationSeconds);
        connLimiter.setEnabled(config.connLimiterEnabled);

        packetLimiter = new PacketRateLimiter();
        packetLimiter.setThreshold(config.packetThreshold);
        packetLimiter.setEnabled(config.packetLimiterEnabled);

        slowProtector = new SlowServerProtector(server, connLimiter, packetLimiter, config, logger);
        slowProtector.setNormalMaxConnections(config.maxConnectionsPerSecond);
        slowProtector.setNormalThreshold(config.packetThreshold);

        if (config.slowServerEnabled) {
            slowProtector.start();
        }

        if (config.udpProtectionEnabled) {
            udpChannel = new NettyUDPChannel(udpDetector);
            String[] address = NettyUDPChannel.readProxyAddressFromToml(
                config.getDataDirectory().resolve("velocity.toml").toString()
            );
            try {
                udpChannel.start(address[0], Integer.parseInt(address[1]));
            } catch (Exception e) {
                logger.warning("[Angkor] Failed to start UDP channel: " + e.getMessage());
            }
        }

        if (config.iptablesEnabled && config.blockUdpPort && iptables.isRootAvailable()) {
            String[] address = NettyUDPChannel.readProxyAddressFromToml(
                config.getDataDirectory().resolve("velocity.toml").toString()
            );
            iptables.blockUDPPort(Integer.parseInt(address[1]));
        }

        eventListener = new DDoSEventListener(connLimiter, udpDetector, config, logger);
        server.getEventManager().register(this, eventListener);

        logger.info("[Angkor] DDoS protection initialized");
    }

    /**
     * Shuts down all DDoS protection components and cleans up resources.
     */
    public void shutdown() {
        if (slowProtector != null) {
            slowProtector.stop();
        }
        if (udpChannel != null) {
            udpChannel.stop();
        }
        if (iptables != null) {
            iptables.unblockAll();
            iptables.shutdown();
        }
        if (connLimiter != null) {
            connLimiter.shutdown();
        }
        if (udpDetector != null) {
            udpDetector.shutdown();
        }
        if (packetLimiter != null) {
            packetLimiter.shutdown();
        }
        logger.info("[Angkor] DDoS protection shutdown");
    }

    public IptablesManager getIptables() {
        return iptables;
    }

    public UDPFloodDetector getUdpDetector() {
        return udpDetector;
    }

    public ConnectionRateLimiter getConnLimiter() {
        return connLimiter;
    }

    public SlowServerProtector getSlowProtector() {
        return slowProtector;
    }

    public PacketRateLimiter getPacketLimiter() {
        return packetLimiter;
    }
}
