package dev.gainsay.host.checks;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-EXEC-005. Implementation:
 * {@code HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun} (bitmask of
 * drive types; 0x04 = removable, 0xFF = all) and {@code NoAutorun} (1 = ignore autorun.inf entirely).
 * Default 0x91 does not include removable drives; since Windows 7 autorun.inf on USB sticks is ignored
 * anyway (KB971029), but AutoPlay prompts and CD/DVD autorun remain.
 */
public final class AutoRunCheck extends AbstractCheck {

    private static final RegistrySetting MASK = RegistrySetting.of(0x91L, RegistrySetting.local(Reg.EXPLORER_POLICY, "NoDriveTypeAutoRun"));
    private static final RegistrySetting NO_AUTORUN = RegistrySetting.of(0L, RegistrySetting.local(Reg.EXPLORER_POLICY, "NoAutorun"));

    public AutoRunCheck() {
        super("HOST-EXEC-005", "AutoRun/AutoPlay is disabled for removable media", Categories.EXECUTION, Severity.LOW,
                "AutoRun let malware (Conficker, Stuxnet's LNK variants) spread by USB. Modern Windows ignores autorun.inf on USB drives, but "
                        + "AutoPlay prompts and optical media still invite one-click execution.",
                "Read NoDriveTypeAutoRun and NoAutorun from the Explorer policy key.",
                "Group Policy: Windows Components > AutoPlay Policies > Turn off AutoPlay = Enabled (All drives) and 'Set the default behavior for AutoRun' = Do not execute.",
                List.of("https://learn.microsoft.com/windows/win32/shell/autoplay-reg"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        Resolved mask = MASK.resolve(ds);
        Resolved noAutorun = NO_AUTORUN.resolve(ds);
        List<Evidence> ev = new ArrayList<>(mask.evidence());
        ev.addAll(noAutorun.evidence());
        if (mask.error() || noAutorun.error()) {
            return unknown(ds, mask.error() ? mask.errorReason() : noAutorun.errorReason(), ev);
        }
        long m = mask.value() == null ? 0x91 : mask.value();
        boolean removableOff = (m & 0x04) != 0;
        if (removableOff || (noAutorun.value() != null && noAutorun.value() == 1)) {
            return pass(ds, String.format("AutoRun is disabled for removable drives (NoDriveTypeAutoRun=0x%02X).", m), ev);
        }
        return warn(ds, String.format("AutoRun/AutoPlay is not disabled for removable drives (NoDriveTypeAutoRun=0x%02X %s).", m,
                RegistryCheck.origin(mask)), ev);
    }
}
