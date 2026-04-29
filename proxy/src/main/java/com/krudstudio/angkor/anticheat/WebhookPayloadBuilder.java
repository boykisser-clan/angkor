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

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Helper class to build Discord embed JSON payloads.
 * Uses only standard Java - no external JSON library needed.
 * Properly escapes all player inputs to prevent JSON injection.
 * Uses SmallCapsConverter for all labels, titles, and footers.
 */
public class WebhookPayloadBuilder {

    private static final int COLOR_GREEN = 3066993;
    private static final int COLOR_RED = 15158332;
    private static final int COLOR_DARK_RED = 10038562;
    private static final int COLOR_ORANGE = 15105570;
    private static final int COLOR_PURPLE = 9442302;
    private static final int COLOR_BLUE = 3447003;
    private static final int COLOR_YELLOW = 16776960;

    /**
     * Builds a Discord webhook payload for a single suspicious command alert.
     *
     * @param cmd the suspicious command
     * @return the JSON payload string
     */
    public static String buildSingleAlert(SuspiciousCommand cmd) {
        int color = getColorForCategory(cmd.getCategory(), cmd.isWhitelisted());
        String timestamp = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        String statusField = cmd.isWhitelisted()
            ? "{\n      \"name\": \"" + SmallCapsConverter.label("status") + "\",\n"
                + "      \"value\": \"✅ " + SmallCapsConverter.convert("allowed - whitelisted") + "\",\n"
                + "      \"inline\": true\n    }"
            : "{\n      \"name\": \"" + SmallCapsConverter.label("status") + "\",\n"
                + "      \"value\": \"🚫 " + SmallCapsConverter.convert("blocked") + "\",\n"
                + "      \"inline\": true\n    }";

        return "{\n" +
               "  \"username\": \"Angkor Security\",\n" +
               "  \"avatar_url\": \"https://i.imgur.com/angkor.png\",\n" +
               "  \"embeds\": [{\n" +
               "    \"title\": \"⚠️ " + SmallCapsConverter.convert("suspicious command detected") + "\",\n" +
               "    \"color\": " + color + ",\n" +
               "    \"fields\": [\n" +
               "      {\n        \"name\": \"👤 " + SmallCapsConverter.label("player") + "\",\n" +
               "        \"value\": \"" + escapeJson(SmallCapsConverter.value(cmd.getPlayerName())) + "\",\n" +
               "        \"inline\": true\n      },\n" +
               "      {\n        \"name\": \"🌐 " + SmallCapsConverter.label("ip address") + "\",\n" +
               "        \"value\": \"" + escapeJson(SmallCapsConverter.value(cmd.getPlayerIP())) + "\",\n" +
               "        \"inline\": true\n      },\n" +
               "      {\n        \"name\": \"🖥️ " + SmallCapsConverter.label("server") + "\",\n" +
               "        \"value\": \"" + escapeJson(SmallCapsConverter.value(cmd.getServerName())) + "\",\n" +
               "        \"inline\": true\n      },\n" +
               "      {\n        \"name\": \"📋 " + SmallCapsConverter.label("category") + "\",\n" +
               "        \"value\": \"" + escapeJson(SmallCapsConverter.category(cmd.getCategory().name())) + "\",\n" +
               "        \"inline\": true\n      },\n" +
               "      {\n        \"name\": \"⚡ " + SmallCapsConverter.label("command") + "\",\n" +
               "        \"value\": \"`" + escapeJson(SmallCapsConverter.value(cmd.getSafeCommand())) + "`\",\n" +
               "        \"inline\": false\n      },\n" +
               "      {\n        \"name\": \"🔑 " + SmallCapsConverter.label("uuid") + "\",\n" +
               "        \"value\": \"" + escapeJson(SmallCapsConverter.value(cmd.getPlayerUUID().toString())) + "\",\n" +
               "        \"inline\": false\n      },\n" +
               statusField + "\n" +
               "    ],\n" +
               "    \"footer\": {\"text\": \"" + SmallCapsConverter.convert("angkor security") + " • " + SmallCapsConverter.convert("krud studio") + "\"},\n" +
               "    \"timestamp\": \"" + timestamp + "\"\n" +
               "  }]\n" +
               "}";
    }

    /**
     * Builds a Discord webhook payload for multiple suspicious commands (batch).
     *
     * @param cmds the list of suspicious commands
     * @return the JSON payload string
     */
    public static String buildBatchAlert(List<SuspiciousCommand> cmds) {
        int count = cmds.size();
        StringBuilder description = new StringBuilder();
        description.append("**").append(SmallCapsConverter.convert("suspicious commands detected")).append(":**\n\n");
        for (SuspiciousCommand cmd : cmds) {
            description.append("• **").append(escapeJson(SmallCapsConverter.value(cmd.getPlayerName()))).append("** (")
                       .append(escapeJson(SmallCapsConverter.value(cmd.getPlayerIP()))).append(") - ")
                       .append(escapeJson(SmallCapsConverter.category(cmd.getCategory().name()))).append(": `")
                       .append(escapeJson(SmallCapsConverter.value(cmd.getSafeCommand()))).append("`\n");
        }
        String timestamp = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        return "{\n" +
               "  \"username\": \"Angkor Security\",\n" +
               "  \"embeds\": [{\n" +
               "    \"title\": \"⚠️ " + count + " " + SmallCapsConverter.convert("suspicious commands detected") + "\",\n" +
               "    \"color\": " + COLOR_YELLOW + ",\n" +
               "    \"description\": \"" + description.toString() + "\",\n" +
               "    \"footer\": {\"text\": \"" + SmallCapsConverter.convert("angkor security") + " • " + SmallCapsConverter.convert("krud studio") + "\"},\n" +
               "    \"timestamp\": \"" + timestamp + "\"\n" +
               "  }]\n" +
               "}";
    }

    /**
     * Builds a Discord webhook payload for startup notification.
     *
     * @return the JSON payload string
     */
    public static String buildStartup() {
        String timestamp = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        return "{\n" +
               "  \"username\": \"Angkor Security\",\n" +
               "  \"avatar_url\": \"https://i.imgur.com/angkor.png\",\n" +
               "  \"embeds\": [{\n" +
               "    \"title\": \"✅ " + SmallCapsConverter.convert("angkor proxy started") + "\",\n" +
               "    \"color\": " + COLOR_GREEN + ",\n" +
               "    \"fields\": [\n" +
               "      {\"name\": \"" + SmallCapsConverter.label("status") + "\", \"value\": \"" + SmallCapsConverter.convert("online") + "\", \"inline\": true},\n" +
               "      {\"name\": \"" + SmallCapsConverter.label("protection") + "\", \"value\": \"" + SmallCapsConverter.convert("active") + "\", \"inline\": true}\n" +
               "    ],\n" +
               "    \"footer\": {\"text\": \"" + SmallCapsConverter.convert("angkor security") + " • " + SmallCapsConverter.convert("krud studio") + "\"},\n" +
               "    \"timestamp\": \"" + timestamp + "\"\n" +
               "  }]\n" +
               "}";
    }

    /**
     * Builds a Discord webhook payload for shutdown notification.
     *
     * @return the JSON payload string
     */
    public static String buildShutdown() {
        String timestamp = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        return "{\n" +
               "  \"username\": \"Angkor Security\",\n" +
               "  \"embeds\": [{\n" +
               "    \"title\": \"🔴 " + SmallCapsConverter.convert("angkor proxy stopped") + "\",\n" +
               "    \"color\": " + COLOR_RED + ",\n" +
               "    \"fields\": [\n" +
               "      {\"name\": \"" + SmallCapsConverter.label("status") + "\", \"value\": \"" + SmallCapsConverter.convert("offline") + "\", \"inline\": true}\n" +
               "    ],\n" +
               "    \"footer\": {\"text\": \"" + SmallCapsConverter.convert("angkor security") + " • " + SmallCapsConverter.convert("krud studio") + "\"},\n" +
               "    \"timestamp\": \"" + timestamp + "\"\n" +
               "  }]\n" +
               "}";
    }

    /**
     * Gets the color code for a command category.
     *
     * @param category the command category
     * @param isWhitelisted whether the player is whitelisted
     * @return the color as an integer
     */
    private static int getColorForCategory(CommandCategory category, boolean isWhitelisted) {
        if (isWhitelisted) return COLOR_GREEN;
        if (category == null) return COLOR_YELLOW;
        return switch (category) {
            case OP_ABUSE -> COLOR_RED;
            case INFO_LEAK -> COLOR_ORANGE;
            case AUTH_EXPLOIT -> COLOR_PURPLE;
            case DUPE_EXPLOIT -> COLOR_BLUE;
            case BACKDOOR -> COLOR_DARK_RED;
            case CONSOLE_EXPLOIT -> COLOR_RED;
            case CRASH_EXPLOIT -> COLOR_YELLOW;
            case DOT_COMMAND -> COLOR_BLUE;
            default -> COLOR_YELLOW;
        };
    }

    /**
     * Escapes a string for safe insertion into JSON.
     * Prevents JSON injection attacks.
     *
     * @param input the input string
     * @return the escaped string
     */
    static String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\t", "\\t")
                   .replace("\r", "\\r");
    }
}
