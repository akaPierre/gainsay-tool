package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-AV-003. Implementation: {@code Get-MpComputerStatus.AntivirusSignatureAge} (days) when Defender
 * is primary; otherwise the "definitions out of date" bit (0x10) of Security Center's {@code productState}
 * for the active third-party product.
 */
public final class SignatureAgeCheck extends AbstractCheck {

    private final int maxDays;

    public SignatureAgeCheck(HostPolicy policy) {
        super("HOST-AV-003", "Antivirus signatures are up to date", Categories.MALWARE, Severity.MEDIUM,
                "Signature-based detection only knows threats published before its last update. A few days' lag is normal; weeks mean updates are broken.",
                "Read AntivirusSignatureAge from Get-MpComputerStatus (Defender) or the out-of-date bit of the third-party productState.",
                "Run Update-MpSignature (or the vendor's update), then find out why automatic updates stopped (proxy, WSUS, disabled service).",
                List.of("https://learn.microsoft.com/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus"));
        this.maxDays = policy.maxSignatureAgeDays();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("defender.status");
        if (DefenderState.mode(ds) == DefenderState.Mode.ACTIVE) {
            JsonNode s = q.first();
            int age = s.path("AntivirusSignatureAge").asInt(-1);
            Evidence ev = queryEvidence("defender.status", "AntivirusSignatureAge=" + age + " day(s)",
                    "Get-MpComputerStatus | Select AntivirusSignatureAge, AntivirusSignatureLastUpdated");
            if (age < 0) {
                return unknown(ds, "AntivirusSignatureAge not reported", List.of(ev));
            }
            if (age <= maxDays) {
                return pass(ds, "Defender signatures are " + age + " day(s) old (threshold " + maxDays + ").", List.of(ev));
            }
            return fail(ds, "Defender signatures are " + age + " days old (threshold " + maxDays + ").", List.of(ev));
        }
        QueryResult av = ds.query("av.products");
        if (!av.ok()) {
            return unknown(ds, q.ok() ? reason(av) : reason(q), List.of());
        }
        List<Evidence> ev = new ArrayList<>();
        boolean anyEnabled = false;
        for (JsonNode p : av.list()) {
            long st = p.path("productState").asLong();
            if (!DefenderState.productEnabled(st)) {
                continue;
            }
            anyEnabled = true;
            boolean fresh = DefenderState.productUpToDate(st);
            ev.add(queryEvidence("av.products", p.path("displayName").asText("?") + " definitions " + (fresh ? "up to date" : "OUT OF DATE")
                    + String.format(" (productState 0x%06X, bit 0x10)", st), "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct"));
            if (fresh) {
                return pass(ds, "The active antivirus reports up-to-date definitions.", ev);
            }
        }
        if (!anyEnabled) {
            return notApplicable(ds, "No active antivirus to judge (see HOST-AV-001).", ev);
        }
        return fail(ds, "The active antivirus reports out-of-date definitions.", ev);
    }
}
