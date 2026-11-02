package dev.gainsay.core;

/**
 * A copy-paste remediation for a finding. Gainsay only <em>prints</em> it; it never runs it.
 *
 * @param command the commands to run (elevated PowerShell unless the note says otherwise), or null when
 *                the fix is not a command (firmware setting, GUI-only, uninstall)
 * @param reboot  true if the change only takes effect after a restart
 * @param note    caveats, e.g. "if this is set by Group Policy, change the GPO instead"
 */
public record Fix(String command, boolean reboot, String note) {
}
