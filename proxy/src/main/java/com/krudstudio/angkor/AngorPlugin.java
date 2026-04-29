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

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Main plugin class for Angkor Proxy.
 * Handles initialization and shutdown of all security and DDoS protection modules.
 *
 * @author KrudStudio
 */
@Plugin(
    id = "angkor",
    name = "Angkor",
    version = "1.0.0",
    description = "Angkor Proxy - Krud Studio",
    authors = {"KrudStudio"}
)
public class AngorPlugin {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private AngorConfig config;
    private AngorSecurityManager securityManager;
    private DDoSManager ddosManager;
    private AntiCheatManager antiCheatManager;

    /**
     * Creates a new AngorPlugin.
     *
     * @param server the proxy server instance
     * @param logger the logger
     * @param dataDirectory the plugin data directory
     */
    @Inject
    public AngorPlugin(ProxyServer server, Logger logger,
                       @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    /**
     * Called when the proxy initializes.
     * Loads configuration, prints banner, and initializes all managers.
     *
     * @param event the proxy initialize event
     */
    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        // 1. Load config
        config = new AngorConfig();
        config.load(dataDirectory);

        // 2. Print banner
        logger.info("  _                  _   __");
        logger.info(" / \\  _ __  __ _ ___| | / /___  _ __");
        logger.info("/ _ \\| '_ \\/ _` / __| |/ / _ \\| '__|");
        logger.info("Angkor Proxy 1.0.0 - Krud Studio");
        logger.info("Security + DDoS Protection Loading...");

        // 3. Init security manager
        securityManager = new AngorSecurityManager(server, config, logger);
        securityManager.initialize();

        // 4. Init DDoS manager
        ddosManager = new DDoSManager(server, config, logger);
        ddosManager.initialize();

        // 5. Init AntiCheat manager
        if (config.antiCheatEnabled) {
            antiCheatManager = new AntiCheatManager(server, config, logger);
            antiCheatManager.initialize();
        }

        logger.info("[Angkor] Fully loaded. Protection active.");
    }

    /**
     * Called when the proxy shuts down.
     * Shuts down all managers and cleans up resources.
     *
     * @param event the proxy shutdown event
     */
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (securityManager != null) {
            securityManager.shutdown();
        }
        if (ddosManager != null) {
            ddosManager.shutdown();
        }
        if (antiCheatManager != null) {
            antiCheatManager.shutdown();
        }
        logger.info("[Angkor] Shutdown complete.");
    }
}
