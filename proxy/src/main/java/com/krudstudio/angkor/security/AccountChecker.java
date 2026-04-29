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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Checks if a Minecraft username has a premium (paid) account via the Mojang API.
 * Results are cached to avoid excessive API calls.
 */
public class AccountChecker {

    private static final Logger logger = Logger.getLogger("Angkor-Account");
    private static final String API_URL = "https://api.mojang.com/users/profiles/minecraft/%s";
    private static final int TIMEOUT_MS = 3000;

    private final ConcurrentHashMap<String, CacheEntry<Boolean>> cache = new ConcurrentHashMap<>();
    private final ExecutorService threadPool = Executors.newFixedThreadPool(2);

    private long cacheTtlMs = 5 * 60 * 1000; // 5 minutes default
    private boolean enabled = true;

    /**
     * Checks if the given username has a premium Minecraft account.
     * Uses cached result if available, otherwise queries the Mojang API.
     *
     * @param username the Minecraft username to check
     * @return a CompletableFuture that resolves to true if premium, false if cracked/not found
     */
    public CompletableFuture<Boolean> isPremium(String username) {
        CompletableFuture<Boolean> future = new CompletableFuture<>();

        // Check cache
        CacheEntry<Boolean> cached = cache.get(username.toLowerCase());
        if (cached != null && !cached.isExpired()) {
            future.complete(cached.getValue());
            return future;
        }

        // Query API asynchronously
        threadPool.submit(() -> {
            try {
                boolean isPremium = queryApi(username);
                cache.put(username.toLowerCase(), new CacheEntry<>(isPremium, cacheTtlMs));
                future.complete(isPremium);
            } catch (Exception e) {
                logger.warning("[Angkor-Account] error: " + e.getMessage());
                // Fail open - don't wrongly kick premium players
                future.complete(true);
            }
        });

        return future;
    }

    private boolean queryApi(String username) throws IOException {
        String urlStr = String.format(API_URL, username);
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestMethod("GET");

        int responseCode = conn.getResponseCode();
        return responseCode == 200;
    }

    /**
     * Sets the cache TTL in minutes.
     *
     * @param minutes the TTL in minutes
     */
    public void setCacheTtlMinutes(int minutes) {
        this.cacheTtlMs = minutes * 60 * 1000L;
    }

    /**
     * Sets whether the account checker is enabled.
     *
     * @param enabled true to enable, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Shuts down the thread pool.
     */
    public void shutdown() {
        threadPool.shutdown();
    }
}
