package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Parses {@code net accounts}. Output is localised, so labels are matched in English first and the
 * fixed line order is used as a fallback:
 * <pre>
 * 0 Force user logoff how long after time expires?
 * 1 Minimum password age (days)
 * 2 Maximum password age (days)
 * 3 Minimum password length
 * 4 Length of password history maintained
 * 5 Lockout threshold
 * 6 Lockout duration (minutes)
 * 7 Lockout observation window (minutes)
 * </pre>
 */
final class NetAccounts {

    static final String REPRODUCE = "net accounts";

    private NetAccounts() {
    }

    /** Returns the raw value token for a setting, or null. */
    static String value(QueryResult q, String englishLabel, int position) {
        List<String> lines = new ArrayList<>();
        for (JsonNode n : q.list()) {
            lines.add(n.asText(""));
        }
        for (String l : lines) {
            if (l.toLowerCase(Locale.ROOT).startsWith(englishLabel.toLowerCase(Locale.ROOT))) {
                return lastToken(l);
            }
        }
        if (lines.size() >= 8 && lines.get(position).contains(":")) {
            return lastToken(lines.get(position));
        }
        return null;
    }

    /** Parses a number; any non-numeric token (e.g. "Never", "Nunca") yields {@code ifNotNumber}. */
    static Integer number(String token, Integer ifNotNumber) {
        if (token == null) {
            return null;
        }
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            return ifNotNumber;
        }
    }

    private static String lastToken(String line) {
        String t = line.strip();
        int sp = Math.max(t.lastIndexOf(' '), t.lastIndexOf(':'));
        return t.substring(sp + 1).strip();
    }
}
