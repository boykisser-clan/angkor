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
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import java.util.logging.Logger;

/**
 * Event listener that monitors commands for suspicious activity.
 * NOW: Blocks suspicious commands for non-whitelisted players.
 * Whitelisted players: ALLOW command + send webhook with WHITELISTED tag.
 * Login commands: NEVER logged, NEVER blocked (skipped entirely).
 */
public class CommandMonitorListener {

    private final CommandWatchlist watchlist;
    private final DiscordWebhookSender webhookSender;
    private final ViolationTracker violationTracker;
    private final PlayerWhitelist whitelist;
    private final boolean logToConsole;
    private final boolean monitorDotCommands;
    private final boolean monitorAuthCommands;
    private final Logger logger;

    /**
     * Creates a new CommandMonitorListener.
     *
     * @param watchlist the command watchlist
     * @param webhookSender the Discord webhook sender
     * @param violationTracker the violation tracker
     * @param whitelist the player whitelist
     * @param logToConsole whether to log to console
     * @param monitorDotCommands whether to monitor dot commands
     * @param monitorAuthCommands whether to monitor auth commands (register only)
     * @param logger the logger
     */
    public CommandMonitorListener(CommandWatchlist watchlist, DiscordWebhookSender webhookSender,
                                    ViolationTracker violationTracker, PlayerWhitelist whitelist,
                                    boolean logToConsole, boolean monitorDotCommands,
                                    boolean monitorAuthCommands, Logger logger) {
        this.watchlist = watchlist;
        this.webhookSender = webhookSender;
        this.violationTracker = violationTracker;
        this.whitelist = whitelist;
        this.logToConsole = logToConsole;
        this.monitorDotCommands = monitorDotCommands;
        this.monitorAuthCommands = monitorAuthCommands;
        this.logger = logger;
    }

    /**
     * Handles command execution events.
     * NOW: Blocks suspicious commands for non-whitelisted players.
     *
     * @param event the command execute event
     */
    @Subscribe(order = PostOrder.FIRST)
    public void onCommand(CommandExecuteEvent event) {
        // Get raw command
        String rawCommand = "/" + event.getCommand();
        String normalized = rawCommand.toLowerCase().trim();

        // Get player - skip if not a player
        if (!(event.getCommandSource() instanceof Player)) {
            return;
        }
        Player player = (Player) event.getCommandSource();

        // Check if command should be skipped (login commands) - NEVER log, NEVER block
        if (watchlist.isSkipped(normalized)) {
            return; // DO NOT log, DO NOT send webhook
        }

        // Check if this is an auth command and we're not monitoring them
        if (!monitorAuthCommands && watchlist.getCategory(normalized) == CommandCategory.AUTH_EXPLOIT) {
            if (!normalized.startsWith("/register")) {
                return;
            }
        }

        // Get category
        CommandCategory category = watchlist.getCategory(normalized);
        if (category == null) {
            return; // Not suspicious
        }

        // For dot commands, check if we're monitoring them
        if (normalized.startsWith(".") && !monitorDotCommands && category == CommandCategory.DOT_COMMAND) {
            return;
        }

        // Get sanitized command
        String safeCommand = watchlist.sanitizeCommand(rawCommand, category);

        // Check whitelist
        boolean isWhitelisted = whitelist.isWhitelisted(player);

        // Build SuspiciousCommand
        SuspiciousCommand cmd = new SuspiciousCommand(
            player.getUsername(),
            player.getUniqueId(),
            player.getRemoteAddress().getHostString(),
            safeCommand,
            safeCommand,
            category,
            System.currentTimeMillis(),
            player.getCurrentServer()
                .map(s -> s.getServerInfo().getName())
                .orElse("proxy"),
            isWhitelisted
        );

        if (isWhitelisted) {
            // Whitelisted: ALLOW command, but still send webhook with tag
            if (monitorDotCommands || !normalized.startsWith(".")) {
                logger.info("[Angkor-Monitor] [WHITELISTED] " + player.getUsername() + " (" + player.getRemoteAddress().getHostString() + ") used " + category.name() + ": " + safeCommand);
            }
            // Send to Discord webhook with WHITELISTED tag
            webhookSender.sendAlert(cmd);
            // DO NOT deny event - whitelisted player passes through
            return;
        }

        // Non-whitelisted: BLOCK command
        // Deny the event
        event.setResult(CommandExecuteEvent.CommandResult.denied());

        // Send kick message to player
        player.sendMessage(Component.text(
            buildBlockMessage(category), NamedTextColor.RED
        ));

        // Log to console
        if (monitorDotCommands || !normalized.startsWith(".")) {
            logger.info("[Angkor-Monitor] [BLOCKED] " + player.getUsername() + " (" + player.getRemoteAddress().getHostString() + ") tried " + category.name() + ": " + safeCommand);
        }

        // Track violation
        violationTracker.addViolation(player, cmd);

        // Send webhook alert
        webhookSender.sendAlert(cmd);
    }

    /**
     * Handles player chat events.
     * Monitors ALL watched prefix commands in chat.
     * NOW: Blocks suspicious chat commands for non-whitelisted players.
     *
     * @param event the player chat event
     */
    @Subscribe(order = PostOrder.FIRST)
    public void onChat(PlayerChatEvent event) {
        String message = event.getMessage().trim();

        // Check if message starts with any watched prefix
        if (!watchlist.isWatchedPrefix(message)) {
            return;
        }

        Player player = event.getPlayer();
        String normalized = message.toLowerCase().trim();

        // Check if skipped
        if (watchlist.isSkipped(normalized)) {
            return;
        }

        // Check category
        CommandCategory category = watchlist.getCategory(normalized);
        if (category == null) {
            return;
        }

        // Only process DOT_COMMAND and recognized prefix commands
        if (category != CommandCategory.DOT_COMMAND && !watchlist.isWatchedPrefix(normalized)) {
            return;
        }

        if (!monitorDotCommands && category == CommandCategory.DOT_COMMAND) {
            return;
        }

        String safeCommand = watchlist.sanitizeCommand(message, category);

        boolean isWhitelisted = whitelist.isWhitelisted(player);

        SuspiciousCommand cmd = new SuspiciousCommand(
            player.getUsername(),
            player.getUniqueId(),
            player.getRemoteAddress().getHostString(),
            safeCommand,
            safeCommand,
            category,
            System.currentTimeMillis(),
            player.getCurrentServer()
                .map(s -> s.getServerInfo().getName())
                .orElse("proxy"),
            isWhitelisted
        );

        if (isWhitelisted) {
            // Allow chat, log to webhook with WHITELISTED tag
            if (monitorDotCommands || !normalized.startsWith(".")) {
                logger.info("[Angkor-Monitor] [WHITELISTED] " + player.getUsername() + " (" + player.getRemoteAddress().getHostString() + ") chat prefix: " + safeCommand);
            }
            webhookSender.sendAlert(cmd);
            return;
        }

        // Block: cancel chat message
        event.setResult(PlayerChatEvent.ChatResult.denied());

        // Notify player
        player.sendMessage(Component.text(
            buildBlockMessage(category), NamedTextColor.RED
        ));

        // Log + webhook
        if (monitorDotCommands || !normalized.startsWith(".")) {
            logger.info("[Angkor-Monitor] [BLOCKED] " + player.getUsername() + " (" + player.getRemoteAddress().getHostString() + ") chat " + category.name() + ": " + safeCommand);
        }
        violationTracker.addViolation(player, cmd);
        webhookSender.sendAlert(cmd);
    }

    /**
     * Builds the block message for a given category.
     *
     * @param category the command category
     * @return the block message
     */
    private String buildBlockMessage(CommandCategory category) {
        return switch (category) {
            case OP_ABUSE -> "§cAngkor: OP commands are not allowed.";
            case BACKDOOR -> "§cAngkor: Backdoor commands detected and blocked.";
            case CONSOLE_EXPLOIT -> "§cAngkor: Console exploit commands are blocked.";
            case AUTH_EXPLOIT -> "§cAngkor: Auth exploit commands are blocked.";
            case DUPE_EXPLOIT -> "§cAngkor: Dupe commands are blocked.";
            case CRASH_EXPLOIT -> "§cAngkor: Crash commands are blocked.";
            case INFO_LEAK -> "§cAngkor: This command is not allowed.";
            default -> "§cAngkor: That command is blocked.";
        };
    }
}
