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
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages whitelisted players who bypass AntiCheat command blocking.
 * Whitelisted players can use any command freely.
 * Commands are still logged and sent to webhook for whitelisted players
 * but with WHITELISTED tag so admins know it was intentional.
 */
public class PlayerWhitelist {

    // UUID based whitelist (permanent)
    private final Set<UUID> whitelistedUUIDs = ConcurrentHashMap.newKeySet();

    // Username based whitelist (fallback if UUID unknown)
    private final Set<String> whitelistedUsernames = ConcurrentHashMap.newKeySet();

    // Temporary whitelist: UUID -> expiry timestamp
    private final ConcurrentHashMap<UUID, Long> temporaryWhitelist = new ConcurrentHashMap<>();

    /**
     * Load whitelist from AngorConfig on startup.
     *
     * @param config the Angkor configuration
     */
    public void load(AngorConfig config) {
        // Load UUIDs from config
        if (config.whitelistUUIDs != null) {
            for (String uuidStr : config.whitelistUUIDs) {
                try {
                    whitelistedUUIDs.add(UUID.fromString(uuidStr));
                } catch (IllegalArgumentException e) {
                    // Invalid UUID format, skip
                }
            }
        }
        // Load usernames from config
        if (config.whitelistUsernames != null) {
            for (String name : config.whitelistUsernames) {
                whitelistedUsernames.add(name.toLowerCase());
            }
        }
    }

    /**
     * Check if player is whitelisted (permanent or temporary).
     *
     * @param player the player to check
     * @return true if whitelisted
     */
    public boolean isWhitelisted(Player player) {
        UUID uuid = player.getUniqueId();
        String name = player.getUsername().toLowerCase();

        // Check permanent UUID whitelist
        if (whitelistedUUIDs.contains(uuid)) return true;

        // Check permanent username whitelist
        if (whitelistedUsernames.contains(name)) return true;

        // Check temporary whitelist
        Long expiry = temporaryWhitelist.get(uuid);
        if (expiry != null) {
            if (System.currentTimeMillis() < expiry) return true;
            else temporaryWhitelist.remove(uuid); // expired
        }

        return false;
    }

    /**
     * Add player to permanent whitelist.
     *
     * @param uuid the player's UUID
     */
    public void addPermanent(UUID uuid) {
        whitelistedUUIDs.add(uuid);
    }

    /**
     * Add player to temporary whitelist for durationMinutes.
     *
     * @param uuid the player's UUID
     * @param durationMinutes how long to whitelist
     */
    public void addTemporary(UUID uuid, int durationMinutes) {
        long expiry = System.currentTimeMillis() + (durationMinutes * 60_000L);
        temporaryWhitelist.put(uuid, expiry);
    }

    /**
     * Remove player from all whitelists.
     *
     * @param uuid the player's UUID
     */
    public void remove(UUID uuid) {
        whitelistedUUIDs.remove(uuid);
        temporaryWhitelist.remove(uuid);
    }

    /**
     * Remove player from whitelist by username.
     *
     * @param username the username to remove
     */
    public void removeByUsername(String username) {
        whitelistedUsernames.remove(username.toLowerCase());
    }

    /**
     * Get all permanently whitelisted UUIDs.
     *
     * @return unmodifiable set of whitelisted UUIDs
     */
    public Set<UUID> getWhitelistedUUIDs() {
        return Collections.unmodifiableSet(whitelistedUUIDs);
    }

    /**
     * Get all whitelisted usernames.
     *
     * @return unmodifiable set of whitelisted usernames
     */
    public Set<String> getWhitelistedUsernames() {
        return Collections.unmodifiableSet(whitelistedUsernames);
    }

    /**
     * Get count of whitelisted players.
     *
     * @return the count
     */
    public int getCount() {
        return whitelistedUUIDs.size() + whitelistedUsernames.size();
    }
}
