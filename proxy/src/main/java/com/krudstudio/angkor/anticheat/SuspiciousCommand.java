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

import java.util.UUID;

/**
 * Represents a suspicious command detected by the anti-cheat monitor.
 * Contains sanitized information about the command and the player who executed it.
 */
public class SuspiciousCommand {
    private final String playerName;
    private final UUID playerUUID;
    private final String playerIP;
    private final String rawCommand;
    private final String safeCommand;
    private final CommandCategory category;
    private final long timestamp;
    private final String serverName;
    private final boolean isWhitelisted;

    /**
     * Creates a new SuspiciousCommand.
     *
     * @param playerName the name of the player
     * @param playerUUID the UUID of the player
     * @param playerIP the IP address of the player
     * @param rawCommand the raw command (may be sanitized)
     * @param safeCommand the safe version of the command for display
     * @param category the category of the suspicious command
     * @param timestamp the timestamp when the command was executed
     * @param serverName the name of the server where the command was executed
     * @param isWhitelisted whether the player is whitelisted
     */
    public SuspiciousCommand(String playerName, UUID playerUUID,
                             String playerIP, String rawCommand,
                             String safeCommand, CommandCategory category,
                             long timestamp, String serverName,
                             boolean isWhitelisted) {
        this.playerName = playerName;
        this.playerUUID = playerUUID;
        this.playerIP = playerIP;
        this.rawCommand = rawCommand;
        this.safeCommand = safeCommand;
        this.category = category;
        this.timestamp = timestamp;
        this.serverName = serverName;
        this.isWhitelisted = isWhitelisted;
    }

    /**
     * Checks if this is a password command (login related).
     *
     * @return true if this is a password/login command
     */
    public boolean isPasswordCommand() {
        String cmd = rawCommand.toLowerCase().trim();
        return cmd.startsWith("/login") || cmd.startsWith("/nlogin") ||
               cmd.startsWith("/l ") || cmd.equals("/l") || cmd.startsWith("/log") ||
               cmd.startsWith("/blogin");
    }

    /**
     * Gets a safe display version of the command.
     * For password commands, returns a skip message.
     * For register commands, hides the password arguments.
     * For other commands, returns the safe command as-is.
     *
     * @return the safe display string
     */
    public String getSafeDisplay() {
        if (isPasswordCommand()) {
            return "[SKIPPED - Login Command]";
        }
        if (category == CommandCategory.AUTH_EXPLOIT && rawCommand.toLowerCase().startsWith("/register")) {
            return "/register [password hidden]";
        }
        return safeCommand;
    }

    public String getPlayerName() { return playerName; }
    public UUID getPlayerUUID() { return playerUUID; }
    public String getPlayerIP() { return playerIP; }
    public String getRawCommand() { return rawCommand; }
    public String getSafeCommand() { return safeCommand; }
    public CommandCategory getCategory() { return category; }
    public long getTimestamp() { return timestamp; }
    public String getServerName() { return serverName; }
    public boolean isWhitelisted() { return isWhitelisted; }
}
