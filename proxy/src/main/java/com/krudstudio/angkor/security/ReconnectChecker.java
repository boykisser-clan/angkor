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

import com.velocitypowered.api.proxy.Player;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Anti-bot reconnect checker that requires players to reconnect to verify they are not bots.
 * Players are kicked on first connection and must reconnect within a time window to be verified.
 */
public class ReconnectChecker {

    private final ConcurrentHashMap<String, Long> pendingReconnect = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> verifiedIPs = new ConcurrentHashMap<>();

    private long expirePendingMs = TimeUnit.MINUTES.toMillis(5);
    private long verifiedTtlMs = TimeUnit.MINUTES.toMillis(30);
    private String kickMessage = "&eAngkor Anti-Bot: Please reconnect to verify.";

    /**
     * Checks if a player should be allowed to connect.
     * First connection: kick with message, add to pending.
     * Reconnect within window: mark as verified, allow.
     * Reconnect after expiry: treat as new connection.
     *
     * @param player the player attempting to connect
     * @return CheckResult.PASS if allowed, CheckResult.FAIL if denied
     */
    public CheckResult check(Player player) {
        String ip = player.getRemoteAddress().getAddress().getHostAddress();

        // Check if IP is verified and not expired
        Long verifiedExpiry = verifiedIPs.get(ip);
        if (verifiedExpiry != null) {
            if (System.currentTimeMillis() < verifiedExpiry) {
                return CheckResult.PASS;
            }
            verifiedIPs.remove(ip);
        }

        // Check pending reconnect
        Long pendingTime = pendingReconnect.get(ip);
        if (pendingTime == null) {
            // First connection - add to pending and kick
            pendingReconnect.put(ip, System.currentTimeMillis());
            player.disconnect(serializeMessage(kickMessage));
            return CheckResult.FAIL;
        }

        // Check if within expire-pending window
        if (System.currentTimeMillis() - pendingTime < expirePendingMs) {
            // Valid reconnect - mark as verified
            pendingReconnect.remove(ip);
            verifiedIPs.put(ip, System.currentTimeMillis() + verifiedTtlMs);
            return CheckResult.PASS;
        }

        // Expired pending - treat as new connection
        pendingReconnect.put(ip, System.currentTimeMillis());
        player.disconnect(serializeMessage(kickMessage));
        return CheckResult.FAIL;
    }

    /**
     * Invalidates a verified IP, requiring them to re-verify.
     *
     * @param ip the IP address to invalidate
     */
    public void invalidate(String ip) {
        verifiedIPs.remove(ip);
        pendingReconnect.remove(ip);
    }

    /**
     * Checks if an IP is verified.
     *
     * @param ip the IP address to check
     * @return true if the IP is verified and not expired, false otherwise
     */
    public boolean isVerified(String ip) {
        Long expiry = verifiedIPs.get(ip);
        if (expiry == null) {
            return false;
        }
        if (System.currentTimeMillis() < expiry) {
            return true;
        }
        verifiedIPs.remove(ip);
        return false;
    }

    /**
     * Sets the pending expiry time in minutes.
     *
     * @param minutes the number of minutes before a pending reconnect expires
     */
    public void setExpirePendingMinutes(int minutes) {
        this.expirePendingMs = TimeUnit.MINUTES.toMillis(minutes);
    }

    /**
     * Sets the verified TTL in minutes.
     *
     * @param minutes the number of minutes a verification remains valid
     */
    public void setVerifiedTtlMinutes(int minutes) {
        this.verifiedTtlMs = TimeUnit.MINUTES.toMillis(minutes);
    }

    /**
     * Sets the kick message for first-time connections.
     *
     * @param message the kick message
     */
    public void setKickMessage(String message) {
        this.kickMessage = message;
    }

    private net.kyori.adventure.text.Component serializeMessage(String message) {
        return net.kyori.adventure.text.minimessage.MiniMessage.miniMessage().deserialize(message);
    }
}
