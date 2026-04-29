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
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.proxy.Player;
import java.util.logging.Logger;

/**
 * Event listener that performs security checks on player login.
 * Runs checks in order: PacketRateLimiter -> ReconnectChecker -> VpnChecker (async) -> AccountChecker (async)
 */
public class SecurityEventListener {

    private final ReconnectChecker reconnectChecker;
    private final VpnChecker vpnChecker;
    private final AccountChecker accountChecker;
    private final PacketRateLimiter packetRateLimiter;
    private final AngorConfig config;
    private final Logger logger;

    /**
     * Creates a new SecurityEventListener.
     */
    public SecurityEventListener(ReconnectChecker reconnectChecker, VpnChecker vpnChecker,
            AccountChecker accountChecker, PacketRateLimiter packetRateLimiter,
            AngorConfig config, Logger logger) {
        this.reconnectChecker = reconnectChecker;
        this.vpnChecker = vpnChecker;
        this.accountChecker = accountChecker;
        this.packetRateLimiter = packetRateLimiter;
        this.config = config;
        this.logger = logger;
    }

    @Subscribe(order = PostOrder.FIRST)
    public void onLogin(LoginEvent event) {
        Player player = event.getPlayer();
        String username = player.getUsername();
        String ip = player.getRemoteAddress().getAddress().getHostAddress();

        // 1. Packet Rate Limiter check (synchronous)
        if (config.packetLimiterEnabled && packetRateLimiter.isRateLimited(ip)) {
            event.setResult(LoginEvent.ComponentResult.denied(
                serializeMessage("&cToo many packets. Try again later.")
            ));
            logger.info("[Angkor-Security] BLOCKED " + username + " (" + ip + ") reason: packet rate limit");
            return;
        }

        // 2. Reconnect Checker (synchronous)
        if (config.reconnectEnabled) {
            reconnectChecker.setExpirePendingMinutes(config.reconnectExpireMinutes);
            reconnectChecker.setVerifiedTtlMinutes(config.reconnectVerifiedTtlMinutes);
            reconnectChecker.setKickMessage(config.reconnectKickMessage);

            CheckResult reconnectResult = reconnectChecker.check(player);
            if (reconnectResult == CheckResult.FAIL) {
                event.setResult(LoginEvent.ComponentResult.denied(
                    serializeMessage(config.reconnectKickMessage)
                ));
                logger.info("[Angkor-Security] BLOCKED " + username + " (" + ip + ") reason: reconnect check failed");
                return;
            }
        }

        // Allow the login to proceed - do async checks after
        // 3. VPN Checker (asynchronous)
        if (config.vpnEnabled) {
            vpnChecker.setApiKey(config.vpnApiKey);
            vpnChecker.setCacheTtlMinutes(config.vpnCacheTtlMinutes);

            vpnChecker.isVpn(ip).thenAccept(isVpn -> {
                if (isVpn) {
                    player.disconnect(serializeMessage(config.vpnKickMessage));
                    logger.info("[Angkor-Security] BLOCKED " + username + " (" + ip + ") reason: VPN detected");
                }
            });
        }

        // 4. Account Checker (asynchronous)
        if (config.accountEnabled && !config.allowCracked) {
            accountChecker.setCacheTtlMinutes(config.accountCacheTtlMinutes);

            accountChecker.isPremium(username).thenAccept(isPremium -> {
                if (!isPremium) {
                    player.disconnect(serializeMessage(config.accountKickMessage));
                    logger.info("[Angkor-Security] BLOCKED " + username + " (" + ip + ") reason: not a premium account");
                }
            });
        }

        logger.info("[Angkor-Security] ALLOWED " + username + " (" + ip + ")");
    }

    private net.kyori.adventure.text.Component serializeMessage(String message) {
        return net.kyori.adventure.text.minimessage.MiniMessage.miniMessage().deserialize(message);
    }
}
