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
 * Manages all anti-cheat components.
 * Initializes and shuts down the command monitor and webhook sender.
 */
public class AntiCheatManager {

    private final ProxyServer server;
    private final AngorConfig config;
    private final Logger logger;

    private CommandWatchlist watchlist;
    private DiscordWebhookSender webhookSender;
    private ViolationTracker violationTracker;
    private PlayerWhitelist playerWhitelist;
    private CommandMonitorListener listener;

    /**
     * Creates a new AntiCheatManager.
     *
     * @param server the proxy server instance
     * @param config the Angkor configuration
     * @param logger the logger
     */
    public AntiCheatManager(ProxyServer server, AngorConfig config, Logger logger) {
        this.server = server;
        this.config = config;
        this.logger = logger;
    }

    /**
     * Initializes all anti-cheat components.
     * Loads watchlist, starts webhook sender, registers listener.
     */
    public void initialize() {
        // Initialize watchlist
        watchlist = new CommandWatchlist();

        // Load custom blocked commands from config
        if (config.customWatchedCommands != null) {
            for (String cmd : config.customWatchedCommands) {
                watchlist.addCustomCommand(cmd, CommandCategory.UNKNOWN);
            }
        }

        // Initialize webhook sender
        webhookSender = new DiscordWebhookSender();
        webhookSender.setEnabled(config.webhookEnabled);
        webhookSender.setWebhookUrl(config.discordWebhookUrl);
        webhookSender.setBatchIntervalSeconds(3);
        webhookSender.setBatchSize(5);

        // Initialize violation tracker
        violationTracker = new ViolationTracker();

        // Initialize player whitelist
        playerWhitelist = new PlayerWhitelist();
        playerWhitelist.load(config);
        logger.info("[Angkor] Whitelist loaded: " + playerWhitelist.getCount() + " players bypassing anticheat");

        // Initialize and register listener
        listener = new CommandMonitorListener(
            watchlist, webhookSender, violationTracker,
            playerWhitelist, config.logToConsole,
            config.monitorDotCommands, config.monitorAuthCommands, logger
        );

        server.getEventManager().register(this, listener);

        // Send startup notification
        webhookSender.sendStartupNotification();

        logger.info("[Angkor] AntiCheat monitor loaded. Webhook active.");
    }

    /**
     * Shuts down all anti-cheat components.
     * Sends shutdown notification via webhook.
     */
    public void shutdown() {
        if (webhookSender != null) {
            webhookSender.sendShutdownNotification();
            webhookSender.shutdown();
        }
        if (violationTracker != null) {
            violationTracker.shutdown();
        }
        logger.info("[Angkor] AntiCheat monitor shutdown.");
    }

    /**
     * Gets the CommandWatchlist instance.
     *
     * @return the command watchlist
     */
    public CommandWatchlist getWatchlist() {
        return watchlist;
    }

    /**
     * Gets the DiscordWebhookSender instance.
     *
     * @return the webhook sender
     */
    public DiscordWebhookSender getWebhookSender() {
        return webhookSender;
    }

    /**
     * Gets the ViolationTracker instance.
     *
     * @return the violation tracker
     */
    public ViolationTracker getViolationTracker() {
        return violationTracker;
    }

    /**
     * Gets the PlayerWhitelist instance.
     *
     * @return the player whitelist
     */
    public PlayerWhitelist getPlayerWhitelist() {
        return playerWhitelist;
    }
}
