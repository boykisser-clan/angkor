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

public class BlockResult {

    /**
     * Actions that can be taken when a suspicious command is detected.
     */
    public enum Action {
        BLOCK,        // Block command, send webhook
        ALLOW,        // Allow command, no log
        ALLOW_LOG,    // Whitelisted player - allow but still log to webhook
        SKIP          // Login command - do nothing
    }

    private final Action action;
    private final String reason;
    private final CommandCategory category;
    private final boolean isWhitelisted;

    private BlockResult(Action action, String reason, CommandCategory category, boolean isWhitelisted) {
        this.action = action;
        this.reason = reason;
        this.category = category;
        this.isWhitelisted = isWhitelisted;
    }

    /**
     * Create a BLOCK result.
     *
     * @param cat the command category
     * @param reason the reason for blocking
     * @return a new BlockResult
     */
    public static BlockResult block(CommandCategory cat, String reason) {
        return new BlockResult(Action.BLOCK, reason, cat, false);
    }

    /**
     * Create an ALLOW result.
     *
     * @return a new BlockResult
     */
    public static BlockResult allow() {
        return new BlockResult(Action.ALLOW, null, null, false);
    }

    /**
     * Create an ALLOW_LOG result (whitelisted player).
     *
     * @param cat the command category
     * @return a new BlockResult
     */
    public static BlockResult allowWhitelisted(CommandCategory cat) {
        return new BlockResult(Action.ALLOW_LOG, "whitelisted player", cat, true);
    }

    /**
     * Create a SKIP result (login commands).
     *
     * @return a new BlockResult
     */
    public static BlockResult skip() {
        return new BlockResult(Action.SKIP, null, null, false);
    }

    public Action getAction() { return action; }
    public String getReason() { return reason; }
    public CommandCategory getCategory() { return category; }
    public boolean isWhitelisted() { return isWhitelisted; }
}
