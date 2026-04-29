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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Converts text to Unicode small caps style.
 * Includes letters, numbers, and symbols conversion.
 */
public final class SmallCapsConverter {

    private SmallCapsConverter() {}

    private static final Map<Character, String> MAP = new LinkedHashMap<>();

    static {
        // === LETTERS ===
        MAP.put('a', "ᴀ"); MAP.put('A', "ᴀ");
        MAP.put('b', "ʙ"); MAP.put('B', "ʙ");
        MAP.put('c', "ᴄ"); MAP.put('C', "ᴄ");
        MAP.put('d', "ᴅ"); MAP.put('D', "ᴅ");
        MAP.put('e', "ᴇ"); MAP.put('E', "ᴇ");
        MAP.put('f', "ꜰ"); MAP.put('F', "ꜰ");
        MAP.put('g', "ɢ"); MAP.put('G', "ɢ");
        MAP.put('h', "ʜ"); MAP.put('H', "ʜ");
        MAP.put('i', "ɪ"); MAP.put('I', "ɪ");
        MAP.put('j', "ᴊ"); MAP.put('J', "ᴊ");
        MAP.put('k', "ᴋ"); MAP.put('K', "ᴋ");
        MAP.put('l', "ʟ"); MAP.put('L', "ʟ");
        MAP.put('m', "ᴍ"); MAP.put('M', "ᴍ");
        MAP.put('n', "ɴ"); MAP.put('N', "ɴ");
        MAP.put('o', "ᴏ"); MAP.put('O', "ᴏ");
        MAP.put('p', "ᴘ"); MAP.put('P', "ᴘ");
        MAP.put('q', "ǫ"); MAP.put('Q', "ǫ");
        MAP.put('r', "ʀ"); MAP.put('R', "ʀ");
        MAP.put('s', "ꜱ"); MAP.put('S', "ꜱ");
        MAP.put('t', "ᴛ"); MAP.put('T', "ᴛ");
        MAP.put('u', "ᴜ"); MAP.put('U', "ᴜ");
        MAP.put('v', "ᴠ"); MAP.put('V', "ᴠ");
        MAP.put('w', "ᴡ"); MAP.put('W', "ᴡ");
        MAP.put('x', "x"); MAP.put('X', "x");
        MAP.put('y', "ʏ"); MAP.put('Y', "ʏ");
        MAP.put('z', "ᴢ"); MAP.put('Z', "ᴢ");

        // === NUMBERS (superscript style) ===
        MAP.put('0', "⁰");
        MAP.put('1', "¹");
        MAP.put('2', "²");
        MAP.put('3', "³");
        MAP.put('4', "⁴");
        MAP.put('5', "⁵");
        MAP.put('6', "⁶");
        MAP.put('7', "⁷");
        MAP.put('8', "⁸");
        MAP.put('9', "⁹");

        // === SYMBOLS (keep readable) ===
        MAP.put('.', ".");
        MAP.put(',', ",");
        MAP.put('!', "ꜝ");
        MAP.put('?', "ꟸ");
        MAP.put(':', ":");
        MAP.put(';', ";");
        MAP.put('-', "‐");
        MAP.put('_', "＿");
        MAP.put('/', "⁄");
        MAP.put('\\', "＼");
        MAP.put('@', "＠");
        MAP.put('#', "＃");
        MAP.put('$', "＄");
        MAP.put('%', "％");
        MAP.put('^', "＾");
        MAP.put('&', "＆");
        MAP.put('*', "∗");
        MAP.put('(', "⁽");
        MAP.put(')', "⁾");
        MAP.put('+', "⁺");
        MAP.put('=', "⁼");
        MAP.put('[', "⌈");
        MAP.put(']', "⌉");
        MAP.put('{', "｛");
        MAP.put('}', "｝");
        MAP.put('<', "˂");
        MAP.put('>', "˃");
        MAP.put('"', "ˮ");
        MAP.put('\'', "ʼ");
        MAP.put('`', "ˋ");
        MAP.put('~', "˜");
        MAP.put('|', "ǀ");
        MAP.put(' ', " ");
    }

    /**
     * Convert full string to small caps Unicode.
     * Every character is converted including numbers and symbols.
     *
     * @param text the text to convert
     * @return the converted text
     */
    public static String convert(String text) {
        if (text == null || text.isEmpty()) return text;
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            sb.append(MAP.getOrDefault(c, String.valueOf(c)));
        }
        return sb.toString();
    }

    /**
     * Convert label text only (field names, titles).
     *
     * @param text the label text
     * @return the converted label
     */
    public static String label(String text) {
        return convert(text);
    }

    /**
     * Convert enum category name to small caps.
     * Example: OP_ABUSE -> ᴏᴘ ᴀʙᴜꜱᴇ
     *
     * @param enumName the enum name
     * @return the converted category name
     */
    public static String category(String enumName) {
        return convert(enumName.replace("_", " ").toLowerCase());
    }

    /**
     * Convert violation action to small caps.
     * Example: BLOCKED -> ʙʟᴏᴄᴋᴇᴅ
     *
     * @param text the action text
     * @return the converted action
     */
    public static String action(String text) {
        return convert(text.toUpperCase());
    }

    /**
     * Keep original value text unchanged.
     * Use for player names, IPs, UUIDs, commands.
     *
     * @param text the value text
     * @return the original text unchanged
     */
    public static String value(String text) {
        return text;
    }
}
