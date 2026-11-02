package dev.gainsay.host.checks;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.RegistrySetting;
import dev.gainsay.host.RegistrySetting.Resolved;
import dev.gainsay.host.source.HostDataSource;

import java.util.List;

/** Base for checks that resolve one {@link RegistrySetting} and judge its effective value. */
abstract class RegistryCheck extends AbstractCheck {

    private final RegistrySetting setting;

    RegistryCheck(String id, String title, String category, Severity severity, String rationale, String howVerified,
                  String remediation, List<String> references, RegistrySetting setting) {
        super(id, title, category, severity, rationale, howVerified, remediation, references);
        this.setting = setting;
    }

    @Override
    public final Finding evaluate(HostDataSource ds) {
        Resolved r = setting.resolve(ds);
        if (r.error()) {
            return unknown(ds, r.errorReason(), r.evidence());
        }
        return judge(ds, r);
    }

    protected Resolved resolve(HostDataSource ds) {
        return setting.resolve(ds);
    }

    /** Grades the effective value; {@code r.value()} is null only when unset and there is no known default. */
    protected abstract Finding judge(HostDataSource ds, Resolved r);

    /** "(Group Policy)", "(local setting)" or "(OS default, not configured)". */
    static String origin(Resolved r) {
        if (r.origin() == null) {
            return "";
        }
        return switch (r.origin()) {
            case POLICY -> "(Group Policy)";
            case LOCAL -> "(local setting)";
            case MEASURED -> "(effective state)";
            case DEFAULT -> "(OS default, not configured)";
        };
    }
}
