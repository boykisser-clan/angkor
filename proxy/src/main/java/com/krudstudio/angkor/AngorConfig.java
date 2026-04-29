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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

/**
 * Configuration for Angkor proxy.
 * Loads from angkor.yml using SnakeYAML.
 */
public class AngorConfig {

    // Reconnect
    public boolean reconnectEnabled = true;
    public int reconnectExpireMinutes = 5;
    public int reconnectVerifiedTtlMinutes = 30;
    public String reconnectKickMessage = "&eAngkor Anti-Bot: Please reconnect to verify.";

    // VPN
    public boolean vpnEnabled = true;
    public String vpnApiKey = "39209u-9tq628-04n187-237063";
    public String vpnAction = "KICK"; // KICK or WARN
    public String vpnKickMessage = "&cVPN/Proxy not allowed.";
    public int vpnCacheTtlMinutes = 10;

    // Account
    public boolean accountEnabled = true;
    public boolean allowCracked = false;
    public String accountKickMessage = "&cInvalid Minecraft account.";
    public int accountCacheTtlMinutes = 5;

    // Packet limiter
    public boolean packetLimiterEnabled = true;
    public int packetThreshold = 500;
    public int packetThrottleSeconds = 60;

    // DDoS UDP
    public boolean udpProtectionEnabled = true;
    public int udpThresholdPps = 100;
    public int udpBlockDurationSeconds = 300;
    public boolean useIptables = true;

    // Connection limiter
    public boolean connLimiterEnabled = true;
    public int maxConnectionsPerSecond = 10;
    public int violationsBeforeBan = 5;
    public int banDurationSeconds = 300;

    // Slow server
    public boolean slowServerEnabled = true;
    public int responseThresholdMs = 200;
    public int recoveryThresholdMs = 100;
    public int recoveryChecks = 3;
    public int slowModeMaxConnections = 3;

    // Iptables
    public boolean iptablesEnabled = true;
    public boolean blockUdpPort = true;

    // AntiCheat Monitor
    public boolean antiCheatEnabled = true;
    public String discordWebhookUrl = "YOUR_DISCORD_WEBHOOK_URL_HERE";
    public boolean webhookEnabled = true;
    public boolean logToConsole = true;
    public List<String> customWatchedCommands = new ArrayList<>();
    public boolean monitorDotCommands = true;
    public boolean monitorAuthCommands = true; // register only, never login

    // Whitelist
    public List<String> whitelistIps = new ArrayList<>();
    public List<String> whitelistUUIDs;       // permanent by UUID
    public List<String> whitelistUsernames;   // permanent by username
    public boolean whitelistLogToWebhook = true;     // send webhook for whitelisted players

    private Path dataDirectory;
    private final Yaml yaml = new Yaml();

    /**
     * Creates a new AngorConfig with default values.
     */
    public AngorConfig() {
        whitelistIps.add("127.0.0.1");
        whitelistIps.add("::1");
        whitelistIps.add("localhost");

        whitelistUUIDs = new ArrayList<>();
        whitelistUsernames = new ArrayList<>();

        customWatchedCommands.add("/vanish");
        customWatchedCommands.add("/invsee");
        customWatchedCommands.add("/noclip");
        customWatchedCommands.add("/fly");
        customWatchedCommands.add("/speed");
        customWatchedCommands.add("/gamemode");
        customWatchedCommands.add("/gm");
        customWatchedCommands.add("/tpall");
        customWatchedCommands.add("/tphere");
        customWatchedCommands.add("/bring");
    }

    /**
     * Loads configuration from angkor.yml in the specified directory.
     * If the file doesn't exist, creates it with default values.
     *
     * @param dataDirectory the directory containing angkor.yml
     */
    @SuppressWarnings("unchecked")
    public void load(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
        File configFile = dataDirectory.resolve("angkor.yml").toFile();

        if (!configFile.exists()) {
            save(dataDirectory);
            return;
        }

        try (FileReader reader = new FileReader(configFile)) {
            Map<String, Object> config = yaml.load(reader);
            if (config == null) {
                return;
            }

            // Parse angkor section
            Map<String, Object> root = (Map<String, Object>) config.getOrDefault("angkor", new LinkedHashMap<>());

            // Security settings
            Map<String, Object> security = (Map<String, Object>) root.getOrDefault("security", new LinkedHashMap<>());
            parseReconnect((Map<String, Object>) security.getOrDefault("reconnect-check", new LinkedHashMap<>()));
            parseVpn((Map<String, Object>) security.getOrDefault("vpn-check", new LinkedHashMap<>()));
            parseAccount((Map<String, Object>) security.getOrDefault("account-check", new LinkedHashMap<>()));
            parsePacketLimiter((Map<String, Object>) security.getOrDefault("packet-limiter", new LinkedHashMap<>()));

            // DDoS settings
            Map<String, Object> ddos = (Map<String, Object>) root.getOrDefault("ddos", new LinkedHashMap<>());
            parseUdpProtection((Map<String, Object>) ddos.getOrDefault("udp-protection", new LinkedHashMap<>()));
            parseConnLimiter((Map<String, Object>) ddos.getOrDefault("connection-limiter", new LinkedHashMap<>()));
            parseSlowServer((Map<String, Object>) ddos.getOrDefault("slow-server-protection", new LinkedHashMap<>()));
            parseIptables((Map<String, Object>) ddos.getOrDefault("iptables", new LinkedHashMap<>()));

            // AntiCheat settings
            Map<String, Object> anticheat = (Map<String, Object>) root.getOrDefault("anticheat", new LinkedHashMap<>());
            parseAntiCheat(anticheat);

             // Whitelist
            List<String> whitelist = (List<String>) root.getOrDefault("whitelist-ips", new ArrayList<>());
            if (whitelist != null) {
                whitelistIps = whitelist;
            }

             // AntiCheat whitelist
            Map<String, Object> acWhitelist = (Map<String, Object>) root.getOrDefault("anticheat", new LinkedHashMap<>());
            if (acWhitelist != null) {
                Map<String, Object> whitelistSection = (Map<String, Object>) acWhitelist.getOrDefault("whitelist", new LinkedHashMap<>());

                whitelistLogToWebhook = getBool(whitelistSection, "log-whitelisted-to-webhook", true);

                List<String> uuids = (List<String>) whitelistSection.getOrDefault("uuids", new ArrayList<>());
                if (uuids != null) {
                    whitelistUUIDs = uuids;
                }

                List<String> usernames = (List<String>) whitelistSection.getOrDefault("usernames", new ArrayList<>());
                if (usernames != null) {
                    whitelistUsernames = usernames;
                }
            }

        } catch (Exception e) {
            // Use defaults on error
        }
    }

    /**
     * Saves the current configuration to angkor.yml in the specified directory.
     *
     * @param dataDirectory the directory to save angkor.yml
     */
    public void save(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
        File configFile = dataDirectory.resolve("angkor.yml").toFile();
        configFile.getParentFile().mkdirs();

        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> root = new LinkedHashMap<>();

        // Security
        Map<String, Object> security = new LinkedHashMap<>();
        security.put("reconnect-check", Map.of(
            "enabled", reconnectEnabled,
            "expire-pending-minutes", reconnectExpireMinutes,
            "verified-ttl-minutes", reconnectVerifiedTtlMinutes,
            "kick-message", reconnectKickMessage
        ));
        security.put("vpn-check", Map.of(
            "enabled", vpnEnabled,
            "api-key", vpnApiKey,
            "action", vpnAction,
            "kick-message", vpnKickMessage,
            "cache-ttl-minutes", vpnCacheTtlMinutes
        ));
        security.put("account-check", Map.of(
            "enabled", accountEnabled,
            "allow-cracked", allowCracked,
            "kick-message", accountKickMessage,
            "cache-ttl-minutes", accountCacheTtlMinutes
        ));
        security.put("packet-limiter", Map.of(
            "enabled", packetLimiterEnabled,
            "threshold", packetThreshold,
            "throttle-seconds", packetThrottleSeconds
        ));

        // DDoS
        Map<String, Object> ddos = new LinkedHashMap<>();
        ddos.put("udp-protection", Map.of(
            "enabled", udpProtectionEnabled,
            "threshold-pps", udpThresholdPps,
            "block-duration-seconds", udpBlockDurationSeconds,
            "use-iptables", useIptables
        ));
        ddos.put("connection-limiter", Map.of(
            "enabled", connLimiterEnabled,
            "max-connections-per-second", maxConnectionsPerSecond,
            "violations-before-ban", violationsBeforeBan,
            "ban-duration-seconds", banDurationSeconds
        ));
        ddos.put("slow-server-protection", Map.of(
            "enabled", slowServerEnabled,
            "response-threshold-ms", responseThresholdMs,
            "recovery-threshold-ms", recoveryThresholdMs,
            "recovery-checks", recoveryChecks,
            "slow-mode-max-connections", slowModeMaxConnections
        ));
        ddos.put("iptables", Map.of(
            "enabled", iptablesEnabled,
            "block-udp-port", blockUdpPort
        ));

        // AntiCheat
        Map<String, Object> anticheat = new LinkedHashMap<>();
        anticheat.put("enabled", antiCheatEnabled);
        anticheat.put("log-to-console", logToConsole);
        anticheat.put("monitor-dot-commands", monitorDotCommands);
        anticheat.put("monitor-auth-commands", monitorAuthCommands);

        Map<String, Object> webhook = new LinkedHashMap<>();
        webhook.put("enabled", webhookEnabled);
        webhook.put("url", discordWebhookUrl);
        webhook.put("batch-interval-seconds", 3);
        webhook.put("batch-size", 5);
        anticheat.put("webhook", webhook);
        anticheat.put("custom-watched-commands", customWatchedCommands);

        // AntiCheat whitelist
        Map<String, Object> acWhitelist = new LinkedHashMap<>();
        acWhitelist.put("log-whitelisted-to-webhook", whitelistLogToWebhook);
        acWhitelist.put("uuids", whitelistUUIDs);
        acWhitelist.put("usernames", whitelistUsernames);
        anticheat.put("whitelist", acWhitelist);

        // Assemble
        root.put("security", security);
        root.put("ddos", ddos);
        root.put("anticheat", anticheat);
        root.put("whitelist-ips", whitelistIps);
        config.put("angkor", root);

        try (FileWriter writer = new FileWriter(configFile)) {
            yaml.dump(config, writer);
        } catch (Exception e) {
            // ignore
        }
    }

    /**
     * Gets the data directory used by this config.
     *
     * @return the data directory
     */
    public Path getDataDirectory() {
        return dataDirectory;
    }

    // Parse helper methods
    private void parseReconnect(Map<String, Object> map) {
        reconnectEnabled = getBool(map, "enabled", true);
        reconnectExpireMinutes = getInt(map, "expire-pending-minutes", 5);
        reconnectVerifiedTtlMinutes = getInt(map, "verified-ttl-minutes", 30);
        reconnectKickMessage = getString(map, "kick-message",
            "&eAngkor Anti-Bot: Please reconnect to verify.");
    }

    private void parseVpn(Map<String, Object> map) {
        vpnEnabled = getBool(map, "enabled", true);
        vpnApiKey = getString(map, "api-key", "39209u-9tq628-04n187-237063");
        vpnAction = getString(map, "action", "KICK");
        vpnKickMessage = getString(map, "kick-message", "&cVPN/Proxy not allowed.");
        vpnCacheTtlMinutes = getInt(map, "cache-ttl-minutes", 10);
    }

    private void parseAccount(Map<String, Object> map) {
        accountEnabled = getBool(map, "enabled", true);
        allowCracked = getBool(map, "allow-cracked", false);
        accountKickMessage = getString(map, "kick-message", "&cInvalid Minecraft account.");
        accountCacheTtlMinutes = getInt(map, "cache-ttl-minutes", 5);
    }

    private void parsePacketLimiter(Map<String, Object> map) {
        packetLimiterEnabled = getBool(map, "enabled", true);
        packetThreshold = getInt(map, "threshold", 500);
        packetThrottleSeconds = getInt(map, "throttle-seconds", 60);
    }

    private void parseUdpProtection(Map<String, Object> map) {
        udpProtectionEnabled = getBool(map, "enabled", true);
        udpThresholdPps = getInt(map, "threshold-pps", 100);
        udpBlockDurationSeconds = getInt(map, "block-duration-seconds", 300);
        useIptables = getBool(map, "use-iptables", true);
    }

    private void parseConnLimiter(Map<String, Object> map) {
        connLimiterEnabled = getBool(map, "enabled", true);
        maxConnectionsPerSecond = getInt(map, "max-connections-per-second", 10);
        violationsBeforeBan = getInt(map, "violations-before-ban", 5);
        banDurationSeconds = getInt(map, "ban-duration-seconds", 300);
    }

    private void parseSlowServer(Map<String, Object> map) {
        slowServerEnabled = getBool(map, "enabled", true);
        responseThresholdMs = getInt(map, "response-threshold-ms", 200);
        recoveryThresholdMs = getInt(map, "recovery-threshold-ms", 100);
        recoveryChecks = getInt(map, "recovery-checks", 3);
        slowModeMaxConnections = getInt(map, "slow-mode-max-connections", 3);
    }

    private void parseIptables(Map<String, Object> map) {
        iptablesEnabled = getBool(map, "enabled", true);
        blockUdpPort = getBool(map, "block-udp-port", true);
    }

    private void parseAntiCheat(Map<String, Object> map) {
        antiCheatEnabled = getBool(map, "enabled", true);
        logToConsole = getBool(map, "log-to-console", true);
        monitorDotCommands = getBool(map, "monitor-dot-commands", true);
        monitorAuthCommands = getBool(map, "monitor-auth-commands", true);

        Map<String, Object> webhook = (Map<String, Object>) map.getOrDefault("webhook", new LinkedHashMap<>());
        webhookEnabled = getBool(webhook, "enabled", true);
        discordWebhookUrl = getString(webhook, "url", "YOUR_DISCORD_WEBHOOK_URL_HERE");

        List<String> custom = (List<String>) map.getOrDefault("custom-watched-commands", new ArrayList<>());
        if (custom != null && !custom.isEmpty()) {
            customWatchedCommands = custom;
        }
    }

    private boolean getBool(Map<String, Object> map, String key, boolean def) {
        Object val = map.get(key);
        return val instanceof Boolean ? (Boolean) val : def;
    }

    private int getInt(Map<String, Object> map, String key, int def) {
        Object val = map.get(key);
        return val instanceof Number ? ((Number) val).intValue() : def;
    }

    private String getString(Map<String, Object> map, String key, String def) {
        Object val = map.get(key);
        return val instanceof String ? (String) val : def;
    }
}
