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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the watchlist of suspicious commands and their categories.
 * Supports runtime addition of custom commands.
 * Monitors commands with various prefixes (. # $ * ! // etc.)
 */
public class CommandWatchlist {

    private final Map<String, CommandCategory> exactMatchMap = new ConcurrentHashMap<>();
    private final Map<String, CommandCategory> startsWithMap = new ConcurrentHashMap<>();

    // Prefixes to monitor in chat and commands
    private static final Set<String> WATCHED_PREFIXES = new HashSet<>(Arrays.asList(
        ".",   // Wurst/hacked client
        "#",   // Some hacked clients & backdoor shells
        "$",   // Shell/script style commands
        "*",   // Wildcard backdoor commands
        "!",   // Common bot/backdoor trigger prefix
        "//",  // WorldEdit abuse / double slash backdoor
        "->",  // Some exploit frameworks
        ">>",  // Shell redirect style
        "::",  // Namespace abuse
        "&&"   // Command chaining attempt
    ));

    // Keywords for detecting unknown prefix commands as BACKDOOR
    private static final Set<String> BACKDOOR_KEYWORDS = new HashSet<>(Arrays.asList(
        "op", "deop", "exec", "run", "shell", "cmd", "backdoor",
        "sudo", "eval", "rce", "bypass", "reload", "restart",
        "stop", "kick", "ban", "console", "lp", "perm", "admin",
        "broadcast", "all", "give", "item", "spawner", "spawnmob",
        "creative", "survival", "gm", "gmc", "gms", "gmsp"
    ));

    /**
     * Creates a new CommandWatchlist and populates it with default commands.
     */
    public CommandWatchlist() {
        // OP_ABUSE commands
        addExact("/op", CommandCategory.OP_ABUSE);
        addExact("/deop", CommandCategory.OP_ABUSE);
        addExact("/minecraft:op", CommandCategory.OP_ABUSE);
        addExact("/bukkit:op", CommandCategory.OP_ABUSE);
        addExact("/spigot:op", CommandCategory.OP_ABUSE);
        addExact(".op", CommandCategory.OP_ABUSE);
        addExact(".deop", CommandCategory.OP_ABUSE);

        // OP_ABUSE with prefixes
        addExact("#op", CommandCategory.OP_ABUSE);
        addExact("$op", CommandCategory.OP_ABUSE);
        addExact("*op", CommandCategory.OP_ABUSE);
        addExact("!op", CommandCategory.OP_ABUSE);
        addExact("#deop", CommandCategory.OP_ABUSE);
        addExact("$deop", CommandCategory.OP_ABUSE);
        addExact("!deop", CommandCategory.OP_ABUSE);

        // INFO_LEAK commands (Wurst/hacked client)
        addExact(".ip", CommandCategory.INFO_LEAK);
        addExact(".getip", CommandCategory.INFO_LEAK);
        addExact(".coords", CommandCategory.INFO_LEAK);
        addExact(".pos", CommandCategory.INFO_LEAK);
        addExact(".players", CommandCategory.INFO_LEAK);
        addExact(".names", CommandCategory.INFO_LEAK);
        addExact(".friends", CommandCategory.INFO_LEAK);
        addExact(".entitylist", CommandCategory.INFO_LEAK);
        addExact(".xray", CommandCategory.INFO_LEAK);
        addExact(".esp", CommandCategory.INFO_LEAK);
        addExact("/seen", CommandCategory.INFO_LEAK);
        addExact("/whois", CommandCategory.INFO_LEAK);
        addExact("/realname", CommandCategory.INFO_LEAK);
        addExact("/ipcheck", CommandCategory.INFO_LEAK);
        addExact("/stafflist", CommandCategory.INFO_LEAK);
        addExact("/vanished", CommandCategory.INFO_LEAK);

        // INFO_LEAK with prefixes
        addExact("#ip", CommandCategory.INFO_LEAK);
        addExact("$ip", CommandCategory.INFO_LEAK);
        addExact("*ip", CommandCategory.INFO_LEAK);
        addExact("!ip", CommandCategory.INFO_LEAK);
        addExact("#coords", CommandCategory.INFO_LEAK);
        addExact("$coords", CommandCategory.INFO_LEAK);
        addExact("!coords", CommandCategory.INFO_LEAK);
        addExact("#players", CommandCategory.INFO_LEAK);
        addExact("$players", CommandCategory.INFO_LEAK);
        addExact("!players", CommandCategory.INFO_LEAK);
        addExact("#list", CommandCategory.INFO_LEAK);
        addExact("$list", CommandCategory.INFO_LEAK);
        addExact("!list", CommandCategory.INFO_LEAK);
        addExact("#online", CommandCategory.INFO_LEAK);
        addExact("!online", CommandCategory.INFO_LEAK);
        addExact("#ping", CommandCategory.INFO_LEAK);
        addExact("!ping", CommandCategory.INFO_LEAK);

        // AUTH_EXPLOIT commands (LOG PASSWORDS HIDDEN)
        addExact("/register", CommandCategory.AUTH_EXPLOIT);
        addExact("/changepassword", CommandCategory.AUTH_EXPLOIT);
        addExact("/resetpassword", CommandCategory.AUTH_EXPLOIT);
        addExact("/unregister", CommandCategory.AUTH_EXPLOIT);
        addExact("/authme", CommandCategory.AUTH_EXPLOIT);
        addExact("/premium", CommandCategory.AUTH_EXPLOIT);
        addExact("/cracked", CommandCategory.AUTH_EXPLOIT);
        addExact("/2fa", CommandCategory.AUTH_EXPLOIT);
        addExact("/totp", CommandCategory.AUTH_EXPLOIT);

        // DUPE_EXPLOIT commands - NOTE: /give is intentionally NOT monitored
        addExact(".dupe", CommandCategory.DUPE_EXPLOIT);
        addExact(".dupeitem", CommandCategory.DUPE_EXPLOIT);
        addExact(".dropitems", CommandCategory.DUPE_EXPLOIT);
        addExact("/dupe", CommandCategory.DUPE_EXPLOIT);
        // /give removed - never monitor
        addExact("/item", CommandCategory.DUPE_EXPLOIT);
        addExact("/spawner", CommandCategory.DUPE_EXPLOIT);
        addExact("/spawnmob", CommandCategory.DUPE_EXPLOIT);
        addExact(".creative", CommandCategory.DUPE_EXPLOIT);
        addExact(".survival", CommandCategory.DUPE_EXPLOIT);
        addExact(".gm", CommandCategory.DUPE_EXPLOIT);
        addExact(".gmc", CommandCategory.DUPE_EXPLOIT);
        addExact(".gms", CommandCategory.DUPE_EXPLOIT);
        addExact(".gmsp", CommandCategory.DUPE_EXPLOIT);

        // BACKDOOR commands - original
        addExact(".backdoor", CommandCategory.BACKDOOR);
        addExact("/backdoor", CommandCategory.BACKDOOR);
        addExact("/rce", CommandCategory.BACKDOOR);
        addExact("/exec", CommandCategory.BACKDOOR);
        addExact("/eval", CommandCategory.BACKDOOR);
        addExact("/shell", CommandCategory.BACKDOOR);
        addExact("/cmd", CommandCategory.BACKDOOR);
        addExact("/system", CommandCategory.BACKDOOR);
        addExact("/run", CommandCategory.BACKDOOR);
        addExact("/script", CommandCategory.BACKDOOR);
        addExact("/execute", CommandCategory.BACKDOOR);
        addExact("/function", CommandCategory.BACKDOOR);

        // BACKDOOR with # prefix
        addExact("#op", CommandCategory.BACKDOOR);
        addExact("#deop", CommandCategory.BACKDOOR);
        addExact("#exec", CommandCategory.BACKDOOR);
        addExact("#run", CommandCategory.BACKDOOR);
        addExact("#shell", CommandCategory.BACKDOOR);
        addExact("#cmd", CommandCategory.BACKDOOR);
        addExact("#backdoor", CommandCategory.BACKDOOR);
        addExact("#sudo", CommandCategory.BACKDOOR);
        addExact("#eval", CommandCategory.BACKDOOR);
        addExact("#rce", CommandCategory.BACKDOOR);
        addExact("#bypass", CommandCategory.BACKDOOR);
        addExact("#reload", CommandCategory.BACKDOOR);
        addExact("#restart", CommandCategory.BACKDOOR);
        addExact("#stop", CommandCategory.BACKDOOR);

        // BACKDOOR with $ prefix
        addExact("$op", CommandCategory.BACKDOOR);
        addExact("$exec", CommandCategory.BACKDOOR);
        addExact("$run", CommandCategory.BACKDOOR);
        addExact("$shell", CommandCategory.BACKDOOR);
        addExact("$cmd", CommandCategory.BACKDOOR);
        addExact("$backdoor", CommandCategory.BACKDOOR);
        addExact("$sudo", CommandCategory.BACKDOOR);
        addExact("$eval", CommandCategory.BACKDOOR);
        addExact("$rce", CommandCategory.BACKDOOR);
        addExact("$bypass", CommandCategory.BACKDOOR);
        addExact("$reload", CommandCategory.BACKDOOR);

        // BACKDOOR with * prefix
        addExact("*op", CommandCategory.BACKDOOR);
        addExact("*exec", CommandCategory.BACKDOOR);
        addExact("*run", CommandCategory.BACKDOOR);
        addExact("*shell", CommandCategory.BACKDOOR);
        addExact("*cmd", CommandCategory.BACKDOOR);
        addExact("*backdoor", CommandCategory.BACKDOOR);
        addExact("*sudo", CommandCategory.BACKDOOR);
        addExact("*eval", CommandCategory.BACKDOOR);
        addExact("*rce", CommandCategory.BACKDOOR);
        addExact("*reload", CommandCategory.BACKDOOR);
        addExact("*all", CommandCategory.BACKDOOR);
        addExact("*broadcast", CommandCategory.BACKDOOR);

        // BACKDOOR with ! prefix
        addExact("!op", CommandCategory.BACKDOOR);
        addExact("!exec", CommandCategory.BACKDOOR);
        addExact("!run", CommandCategory.BACKDOOR);
        addExact("!shell", CommandCategory.BACKDOOR);
        addExact("!cmd", CommandCategory.BACKDOOR);
        addExact("!backdoor", CommandCategory.BACKDOOR);
        addExact("!sudo", CommandCategory.BACKDOOR);
        addExact("!eval", CommandCategory.BACKDOOR);
        addExact("!rce", CommandCategory.BACKDOOR);
        addExact("!reload", CommandCategory.BACKDOOR);
        addExact("!stop", CommandCategory.BACKDOOR);
        addExact("!restart", CommandCategory.BACKDOOR);
        addExact("!kick", CommandCategory.BACKDOOR);
        addExact("!ban", CommandCategory.BACKDOOR);

        // BACKDOOR with // prefix
        addExact("//exec", CommandCategory.BACKDOOR);
        addExact("//run", CommandCategory.BACKDOOR);
        addExact("//shell", CommandCategory.BACKDOOR);
        addExact("//sudo", CommandCategory.BACKDOOR);

        // CONSOLE_EXPLOIT commands
        addExact("/console", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/sudo", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/runas", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/admin", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/bypass", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/pex", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/lp", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/luckperms", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/cloudnet", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/bungee", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/velocity", CommandCategory.CONSOLE_EXPLOIT);
        addExact("/perms", CommandCategory.CONSOLE_EXPLOIT);

        // CONSOLE_EXPLOIT with prefixes
        addExact("#console", CommandCategory.CONSOLE_EXPLOIT);
        addExact("$console", CommandCategory.CONSOLE_EXPLOIT);
        addExact("!console", CommandCategory.CONSOLE_EXPLOIT);
        addExact("#lp", CommandCategory.CONSOLE_EXPLOIT);
        addExact("$lp", CommandCategory.CONSOLE_EXPLOIT);
        addExact("!lp", CommandCategory.CONSOLE_EXPLOIT);
        addExact("#perm", CommandCategory.CONSOLE_EXPLOIT);
        addExact("$perm", CommandCategory.CONSOLE_EXPLOIT);
        addExact("!perm", CommandCategory.CONSOLE_EXPLOIT);
        addExact("#admin", CommandCategory.CONSOLE_EXPLOIT);
        addExact("$admin", CommandCategory.CONSOLE_EXPLOIT);
        addExact("!admin", CommandCategory.CONSOLE_EXPLOIT);

        // CRASH_EXPLOIT commands
        addExact("/lag", CommandCategory.CRASH_EXPLOIT);
        addExact("/mem", CommandCategory.CRASH_EXPLOIT);
        addExact("/gc", CommandCategory.CRASH_EXPLOIT);
        addExact("/timings", CommandCategory.CRASH_EXPLOIT);
        addExact("/debug", CommandCategory.CRASH_EXPLOIT);
        addExact("/reload", CommandCategory.CRASH_EXPLOIT);
        addExact("/restart", CommandCategory.CRASH_EXPLOIT);
        addExact("/stop", CommandCategory.CRASH_EXPLOIT);
        addExact(".spam", CommandCategory.CRASH_EXPLOIT);
        addExact(".crashserver", CommandCategory.CRASH_EXPLOIT);

        // CRASH_EXPLOIT with prefixes
        addExact("#reload", CommandCategory.CRASH_EXPLOIT);
        addExact("$reload", CommandCategory.CRASH_EXPLOIT);
        addExact("!reload", CommandCategory.CRASH_EXPLOIT);
        addExact("#lag", CommandCategory.CRASH_EXPLOIT);
        addExact("$lag", CommandCategory.CRASH_EXPLOIT);
        addExact("!lag", CommandCategory.CRASH_EXPLOIT);
        addExact("#gc", CommandCategory.CRASH_EXPLOIT);
        addExact("$gc", CommandCategory.CRASH_EXPLOIT);
        addExact("!gc", CommandCategory.CRASH_EXPLOIT);
        addExact("#tps", CommandCategory.CRASH_EXPLOIT);
        addExact("$tps", CommandCategory.CRASH_EXPLOIT);
        addExact("!tps", CommandCategory.CRASH_EXPLOIT);
    }

    private void addExact(String cmd, CommandCategory category) {
        exactMatchMap.put(cmd.toLowerCase().trim(), category);
    }

    private void addStartsWith(String prefix, CommandCategory category) {
        startsWithMap.put(prefix.toLowerCase().trim(), category);
    }

    /**
     * Checks if a message starts with any watched prefix.
     * Uses startsWith check against the WATCHED_PREFIXES set.
     *
     * @param message the message to check
     * @return true if the message starts with a watched prefix
     */
    public boolean isWatchedPrefix(String message) {
        String normalized = message.toLowerCase().trim();
        for (String prefix : WATCHED_PREFIXES) {
            if (normalized.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the category for a command.
     * Normalizes the command (lowercase, trim) before checking.
     * Checks exact match first, then checks startsWith for commands with arguments.
     * Also checks if the command has a watched prefix but unknown command -
     * in that case, checks if the base command after prefix is a known backdoor keyword.
     *
     * @param command the command to check
     * @return the CommandCategory, or null if not in watchlist
     */
    public CommandCategory getCategory(String command) {
        String normalized = command.toLowerCase().trim();

        // Check exact match first
        CommandCategory category = exactMatchMap.get(normalized);
        if (category != null) {
            return category;
        }

        // Check for commands that start with a prefix (for commands with args)
        String[] parts = normalized.split("\\s+");
        String firstWord = parts[0];

        category = exactMatchMap.get(firstWord);
        if (category != null) {
            return category;
        }

        // Check startsWith map
        for (Map.Entry<String, CommandCategory> entry : startsWithMap.entrySet()) {
            if (normalized.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }

        // Check if message has a watched prefix but unknown command
        // If so, extract base command and check if it's a known backdoor keyword
        if (isWatchedPrefix(normalized)) {
            // Try to extract the base command after the prefix
            String baseCommand = extractBaseCommand(normalized);
            if (baseCommand != null && BACKDOOR_KEYWORDS.contains(baseCommand)) {
                return CommandCategory.BACKDOOR;
            }
        }

        return null;
    }

    /**
     * Extracts the base command from a prefixed command.
     * E.g., "#op foo bar" -> "op", "!exec something" -> "exec"
     *
     * @param command the command with prefix
     * @return the base command, or null if cannot extract
     */
    private String extractBaseCommand(String command) {
        // Remove the prefix (1-3 characters at start)
        String[] parts = command.split("\\s+");
        if (parts.length == 0) {
            return null;
        }

        String firstWord = parts[0];

        // Check if first word itself is a known command
        String noPrefix = firstWord;
        if (firstWord.length() > 1) {
            // Try removing common prefixes
            for (String prefix : WATCHED_PREFIXES) {
                if (firstWord.startsWith(prefix)) {
                    noPrefix = firstWord.substring(prefix.length());
                    break;
                }
            }
        }

        return noPrefix.isEmpty() ? null : noPrefix;
    }

    /**
     * Checks if a command should be skipped entirely (never logged).
     * This covers /login, /nlogin, /l, /log, /blogin.
     *
     * @param command the command to check
     * @return true if the command should be skipped
     */
    public boolean isSkipped(String command) {
        String normalized = command.toLowerCase().trim();
        return normalized.startsWith("/login")
            || normalized.startsWith("/nlogin")
            || normalized.startsWith("/l ")
            || normalized.equals("/l")
            || normalized.startsWith("/log")
            || normalized.startsWith("/blogin");
    }

    /**
     * Checks if a command is a password command.
     *
     * @param command the command to check
     * @return true if this is a password/login command
     */
    public boolean isPasswordCommand(String command) {
        String normalized = command.toLowerCase().trim();
        return normalized.startsWith("/login")
            || normalized.startsWith("/nlogin")
            || normalized.startsWith("/l ")
            || normalized.equals("/l")
            || normalized.startsWith("/log")
            || normalized.startsWith("/blogin");
    }

    /**
     * Sanitizes a command for safe display.
     * If category is AUTH_EXPLOIT and command starts with /register,
     * returns "/register [args hidden]".
     * If category is AUTH_EXPLOIT, returns only the command name (hides all args).
     * For watched prefix commands, returns the full command as-is (no password risk).
     * Otherwise, returns the full command.
     *
     * @param command the raw command
     * @param category the command category
     * @return the sanitized command string
     */
    public String sanitizeCommand(String command, CommandCategory category) {
        if (category == CommandCategory.AUTH_EXPLOIT) {
            String normalized = command.toLowerCase().trim();
            if (normalized.startsWith("/register")) {
                return "/register [args hidden]";
            }
            // For other auth exploits, return only the command name
            String[] parts = command.split("\\s+");
            return parts[0] + " [args hidden]";
        }

        // For prefix commands (., #, $, *, !, etc.), return as-is
        String normalized = command.toLowerCase().trim();
        for (String prefix : WATCHED_PREFIXES) {
            if (normalized.startsWith(prefix)) {
                return command; // Return full command for prefix commands
            }
        }

        return command;
    }

    /**
     * Adds a custom command to the watchlist at runtime.
     *
     * @param cmd the command to add
     * @param category the category to assign
     */
    public void addCustomCommand(String cmd, CommandCategory category) {
        String normalized = cmd.toLowerCase().trim();
        // Determine if it needs startsWith matching
        if (normalized.contains(" ")) {
            addStartsWith(normalized, category);
        } else {
            addExact(normalized, category);
        }
    }
}
