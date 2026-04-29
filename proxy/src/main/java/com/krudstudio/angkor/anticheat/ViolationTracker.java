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

import com.velocitypowered.api.proxy.Player;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Tracks violations per player for statistics.
 * Does not take any action - monitoring only.
 */
public class ViolationTracker {

    private final ConcurrentHashMap<String, ViolationRecord> records = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupScheduler = Executors.newSingleThreadScheduledExecutor();

    /**
     * Creates a new ViolationTracker with automatic cleanup every hour.
     */
    public ViolationTracker() {
        cleanupScheduler.scheduleAtFixedRate(this::cleanOldRecords, 1, 1, TimeUnit.HOURS);
    }

    /**
     * Adds a violation for a player.
     *
     * @param player the player who committed the violation
     * @param cmd the suspicious command
     */
    public void addViolation(Player player, SuspiciousCommand cmd) {
        String uuid = player.getUniqueId().toString();
        ViolationRecord record = records.computeIfAbsent(uuid, k -> new ViolationRecord());

        record.totalViolations++;
        record.byCategory.merge(cmd.getCategory(), 1, Integer::sum);
        record.lastSeen = System.currentTimeMillis();

        if (record.firstSeen == 0) {
            record.firstSeen = System.currentTimeMillis();
        }

        // Add to recent commands (keep last 20)
        record.recentCommands.add(cmd);
        if (record.recentCommands.size() > 20) {
            record.recentCommands.remove(0);
        }
    }

    /**
     * Gets the violation record for a player.
     *
     * @param uuid the player's UUID
     * @return the ViolationRecord, or null if not found
     */
    public ViolationRecord getRecord(String uuid) {
        return records.get(uuid);
    }

    /**
     * Gets the total number of violations for a player.
     *
     * @param uuid the player's UUID
     * @return the total violation count
     */
    public int getTotalViolations(String uuid) {
        ViolationRecord record = records.get(uuid);
        return record != null ? record.totalViolations : 0;
    }

    /**
     * Clears the violation record for a player.
     *
     * @param uuid the player's UUID
     */
    public void clearRecord(String uuid) {
        records.remove(uuid);
    }

    /**
     * Shuts down the cleanup scheduler.
     */
    public void shutdown() {
        cleanupScheduler.shutdown();
    }

    private void cleanOldRecords() {
        long now = System.currentTimeMillis();
        long twentyFourHoursMs = 24 * 60 * 60 * 1000L;

        records.entrySet().removeIf(entry -> {
            ViolationRecord record = entry.getValue();
            return (now - record.lastSeen) > twentyFourHoursMs;
        });
    }

    /**
     * Represents a player's violation history.
     */
    public static class ViolationRecord {
        public int totalViolations = 0;
        public final Map<CommandCategory, Integer> byCategory = new ConcurrentHashMap<>();
        public long firstSeen = 0;
        public long lastSeen = 0;
        public final List<SuspiciousCommand> recentCommands = new ArrayList<>();
    }
}
