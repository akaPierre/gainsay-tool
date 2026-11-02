package dev.gainsay.host.source;

/** Outcome of one read from the host. */
public enum ReadState {
    /** The value or query result is available. */
    OK,
    /** The registry key/value does not exist (which usually means "OS default applies"). */
    ABSENT,
    /** The read failed (access denied, provider missing, timeout); the check must report UNKNOWN. */
    ERROR
}
