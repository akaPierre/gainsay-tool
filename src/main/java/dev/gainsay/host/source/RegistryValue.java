package dev.gainsay.host.source;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * One registry value as read from the host.
 *
 * @param state  OK, ABSENT or ERROR
 * @param type   registry kind as reported by .NET ({@code DWord}, {@code String}, {@code QWord}, …)
 * @param value  the raw value (number or text); null unless OK
 * @param reason error message when state is ERROR
 */
public record RegistryValue(ReadState state, String type, JsonNode value, String reason) {

    public static RegistryValue absent() {
        return new RegistryValue(ReadState.ABSENT, null, null, null);
    }

    public static RegistryValue error(String reason) {
        return new RegistryValue(ReadState.ERROR, null, null, reason);
    }

    @JsonIgnore
    public boolean ok() {
        return state == ReadState.OK && value != null && !value.isNull();
    }

    /**
     * Numeric view. DWORDs arrive from PowerShell as signed Int32, so values with the high bit set
     * (e.g. 0xFFFFFFFF) are converted back to unsigned. REG_SZ numbers ("1") are parsed. Returns
     * null when the value is not numeric.
     */
    @JsonIgnore
    public Long asLong() {
        if (!ok()) {
            return null;
        }
        if (value.isIntegralNumber()) {
            long v = value.asLong();
            if ("DWord".equalsIgnoreCase(type) && v < 0) {
                v &= 0xFFFFFFFFL;
            }
            return v;
        }
        if (value.isTextual()) {
            String t = value.asText().trim();
            try {
                return t.startsWith("0x") || t.startsWith("0X") ? Long.parseLong(t.substring(2), 16) : Long.parseLong(t);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    @JsonIgnore
    public String asText() {
        return ok() ? value.asText() : null;
    }

    /** Short display form for evidence, e.g. {@code "1 (DWord)"}. */
    @JsonIgnore
    public String display() {
        return switch (state) {
            case OK -> {
                Long n = asLong();
                String v = n != null && value.isIntegralNumber() ? n + (n > 9 ? String.format(" (0x%X)", n) : "") : value.asText();
                yield v + (type == null ? "" : " (" + type + ")");
            }
            case ABSENT -> "not present";
            case ERROR -> "read failed: " + reason;
        };
    }
}
