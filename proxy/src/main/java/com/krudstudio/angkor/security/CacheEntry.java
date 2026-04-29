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

public class CacheEntry<T> {
    private final T value;
    private final long expiryMs;

    /**
     * Creates a new cache entry with the specified value and TTL.
     *
     * @param value the value to cache
     * @param ttlMs the time-to-live in milliseconds
     */
    public CacheEntry(T value, long ttlMs) {
        this.value = value;
        this.expiryMs = System.currentTimeMillis() + ttlMs;
    }

    /**
     * Checks if this cache entry has expired.
     *
     * @return true if the entry has expired, false otherwise
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > expiryMs;
    }

    /**
     * Gets the cached value.
     *
     * @return the cached value
     */
    public T getValue() {
        return value;
    }
}
