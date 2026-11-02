package dev.gainsay.host.source;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Result of one allow-listed structured query (a CIM/WMI class, a cmdlet, or a read-only native
 * command), always normalised to a JSON array of rows.
 *
 * @param state  OK or ERROR
 * @param rows   JSON array (possibly empty)
 * @param reason error message when state is ERROR
 * @param denied true when the error looks like "access denied" (the read probably needs elevation)
 */
public record QueryResult(ReadState state, JsonNode rows, String reason, boolean denied) {

    public static QueryResult error(String reason, boolean denied) {
        return new QueryResult(ReadState.ERROR, null, reason, denied);
    }

    @JsonIgnore
    public boolean ok() {
        return state == ReadState.OK;
    }

    @JsonIgnore
    public List<JsonNode> list() {
        List<JsonNode> out = new ArrayList<>();
        if (rows == null || rows.isNull()) {
            return out;
        }
        if (rows.isArray()) {
            rows.forEach(n -> {
                if (n != null && !n.isNull()) {
                    out.add(n);
                }
            });
        } else {
            out.add(rows);
        }
        return out;
    }

    /** First row or null. */
    @JsonIgnore
    public JsonNode first() {
        List<JsonNode> l = list();
        return l.isEmpty() ? null : l.get(0);
    }

    /** Human-readable reason for UNKNOWN findings. */
    @JsonIgnore
    public String why() {
        return denied ? reason + " (this read needs an elevated prompt)" : reason;
    }
}
