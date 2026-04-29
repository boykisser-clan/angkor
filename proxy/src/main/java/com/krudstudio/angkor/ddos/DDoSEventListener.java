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

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.PostOrder;
import java.util.logging.Logger;

/**
 * Event listener that performs DDoS protection checks before login.
 * Runs before SecurityEventListener (uses PreLoginEvent vs LoginEvent).
 */
public class DDoSEventListener {

    private final ConnectionRateLimiter connLimiter;
    private final UDPFloodDetector udpDetector;
    private final AngorConfig config;
    private final Logger logger;

    /**
     * Creates a new DDoSEventListener.
     *
     * @param connLimiter the connection rate limiter
     * @param udpDetector the UDP flood detector
     * @param config the Angkor configuration
     * @param logger the logger
     */
    public DDoSEventListener(ConnectionRateLimiter connLimiter,
                                 UDPFloodDetector udpDetector, AngorConfig config, Logger logger) {
        this.connLimiter = connLimiter;
        this.udpDetector = udpDetector;
        this.config = config;
        this.logger = logger;
    }

    /**
     * Handles the PreLoginEvent with highest priority (FIRST).
     * Checks connection rate limiting and UDP blacklist.
     *
     * @param event the pre-login event
     */
    @Subscribe(order = PostOrder.FIRST)
    public void onPreLogin(PreLoginEvent event) {
        String ip = event.getConnection().getRemoteAddress().getAddress().getHostAddress();

        // Connection rate limiter check
        if (config.connLimiterEnabled) {
            connLimiter.setMaxConnections(config.maxConnectionsPerSecond);
            connLimiter.setViolationsBeforeBan(config.violationsBeforeBan);
            connLimiter.setBanDurationSeconds(config.banDurationSeconds);

            if (!connLimiter.checkConnection(ip)) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    serializeMessage("&cToo many connections. Try again later.")
                ));
                logger.info("[Angkor-DDoS] Blocked pre-login from " + ip + " - rate limited");
                return;
            }
        }

        // UDP blacklist check
        if (config.udpProtectionEnabled && udpDetector.isBlacklisted(ip)) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                serializeMessage("&cYou are temporarily blocked.")
            ));
            logger.info("[Angkor-DDoS] Blocked pre-login from " + ip + " - UDP blacklist");
        }
    }

    private net.kyori.adventure.text.Component serializeMessage(String message) {
        return net.kyori.adventure.text.minimessage.MiniMessage.miniMessage().deserialize(message);
    }
}
