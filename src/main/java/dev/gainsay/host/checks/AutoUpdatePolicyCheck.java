package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-PATCH-004. Implementation: Group Policy values under
 * {@code HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU}: {@code NoAutoUpdate} (1 = automatic
 * updates off) and {@code AUOptions} (2 notify before download, 3 auto download + notify install,
 * 4 auto download + scheduled install, 5 local admin chooses, 7 auto download + notify restart).
 * Without either value, Windows installs updates automatically.
 */
public final class AutoUpdatePolicyCheck extends AbstractCheck {

    private static final RegistrySetting NO_AUTO = RegistrySetting.of(0L, RegistrySetting.policy(Reg.WU_AU_POLICY, "NoAutoUpdate"));
    private static final RegistrySetting AU_OPTIONS = RegistrySetting.of(null, RegistrySetting.policy(Reg.WU_AU_POLICY, "AUOptions"));

    public AutoUpdatePolicyCheck() {
        super("HOST-PATCH-004", "Automatic updates are not turned off by policy", Categories.PATCHING, Severity.MEDIUM,
                "Updates that wait for a person to click are installed late or never; most exploited Windows bugs were patched weeks before the attack.",
                "Read NoAutoUpdate and AUOptions from the Windows Update Group Policy key; absent means automatic updates.",
                "Remove NoAutoUpdate=1 and set AUOptions to 4 (or manage updates through Windows Update for Business / Intune).",
                List.of("https://learn.microsoft.com/windows/deployment/update/waas-wu-settings"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        Resolved no = NO_AUTO.resolve(ds);
        Resolved opt = AU_OPTIONS.resolve(ds);
        List<dev.gainsay.core.Evidence> ev = new ArrayList<>(no.evidence());
        ev.addAll(opt.evidence());
        if (no.error() || opt.error()) {
            return unknown(ds, no.error() ? no.errorReason() : opt.errorReason(), ev);
        }
        if (no.value() != null && no.value() == 1) {
            return fail(ds, "Automatic updates are turned off by policy (NoAutoUpdate=1).", ev);
        }
        if (opt.value() != null && opt.value() == 2) {
            return warn(ds, "Policy only notifies before downloading updates (AUOptions=2).", ev);
        }
        return pass(ds, opt.value() == null ? "No policy restricts automatic updates (Windows default: automatic)."
                : "Automatic updates allowed by policy (AUOptions=" + opt.value() + ").", ev);
    }
}
