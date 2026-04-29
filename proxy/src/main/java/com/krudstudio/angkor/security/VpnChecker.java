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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Checks if an IP address is a VPN or proxy using the proxycheck.io API.
 * Results are cached to avoid excessive API calls.
 */
public class VpnChecker {

    private static final Logger logger = Logger.getLogger("Angkor-VPN");
    private static final String API_URL = "https://proxycheck.io/v2/%s?key=%s&vpn=1&asn=1";
    private static final String FREE_API_URL = "https://proxycheck.io/v2/%s?%s&vpn=1&asn=1";
    private static final int TIMEOUT_MS = 5000;

    private final ConcurrentHashMap<String, CacheEntry<Boolean>> cache = new ConcurrentHashMap<>();
    private final ExecutorService threadPool = Executors.newFixedThreadPool(4);
    private final Gson gson = new Gson();

    private String apiKey = "";
    private long cacheTtlMs = 10 * 60 * 1000; // 10 minutes default
    private boolean enabled = true;

    /**
     * Checks if the given IP address is a VPN or proxy.
     * Uses cached result if available, otherwise queries the API.
     * Whitelisted IPs (localhost, private ranges) always return false.
     *
     * @param ip the IP address to check
     * @return a CompletableFuture that resolves to true if the IP is a VPN/proxy, false otherwise
     */
    public CompletableFuture<Boolean> isVpn(String ip) {
        CompletableFuture<Boolean> future = new CompletableFuture<>();

        // Check whitelist first
        if (isPrivateIP(ip)) {
            future.complete(false);
            return future;
        }

        // Check cache
        CacheEntry<Boolean> cached = cache.get(ip);
        if (cached != null && !cached.isExpired()) {
            future.complete(cached.getValue());
            return future;
        }

        // Query API asynchronously
        threadPool.submit(() -> {
            try {
                boolean isVpn = queryApi(ip);
                cache.put(ip, new CacheEntry<>(isVpn, cacheTtlMs));
                future.complete(isVpn);
            } catch (Exception e) {
                logger.warning("[Angkor-VPN] API error: " + e.getMessage());
                // Fail open - don't block on API errors
                future.complete(false);
            }
        });

        return future;
    }

    private boolean queryApi(String ip) throws IOException {
        String urlStr;
        if (apiKey != null && !apiKey.isEmpty()) {
            urlStr = String.format(API_URL, ip, apiKey);
        } else {
            urlStr = String.format(FREE_API_URL, ip, "");
        }

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestMethod("GET");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            JsonObject response = gson.fromJson(reader, JsonObject.class);

            if (response.has(ip)) {
                JsonObject ipData = response.getAsJsonObject(ip);
                String proxy = ipData.has("proxy") ? ipData.get("proxy").getAsString() : "";
                String type = ipData.has("type") ? ipData.get("type").getAsString() : "";

                return "yes".equalsIgnoreCase(proxy)
                    || type.toLowerCase().contains("vpn")
                    || type.toLowerCase().contains("hosting");
            }
        }
        return false;
    }

    private boolean isPrivateIP(String ip) {
        if (ip.equals("127.0.0.1") || ip.equals("::1")) {
            return true;
        }
        // 10.0.0.0/8
        if (ip.startsWith("10.")) {
            return true;
        }
        // 192.168.0.0/16
        if (ip.startsWith("192.168.")) {
            return true;
        }
        // 172.16.0.0/12
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

    /**
     * Sets the API key for proxycheck.io.
     *
     * @param apiKey the API key (empty string for free tier)
     */
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
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
     * Sets whether the VPN checker is enabled.
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
