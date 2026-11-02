package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-BOOT-003. Implementation: WMI {@code root\cimv2\security\microsofttpm\Win32_Tpm}
 * ({@code IsEnabled_InitialValue}, {@code IsActivated_InitialValue}, {@code SpecVersion}); same data as
 * {@code Get-Tpm}. Needs elevation. No instance means no TPM is visible to Windows.
 */
public final class TpmCheck extends AbstractCheck {

    public TpmCheck() {
        super("HOST-BOOT-003", "A TPM is present and ready", Categories.BOOT, Severity.MEDIUM,
                "The TPM anchors BitLocker keys, Windows Hello, measured boot and Credential Guard. Without it those protections fall back to weaker modes or are unavailable.",
                "Read the Win32_Tpm instance (needs elevation).",
                "Enable the TPM (often 'PTT' or 'fTPM') in the firmware settings; then initialise it from tpm.msc.",
                List.of("https://learn.microsoft.com/windows/security/hardware-security/tpm/trusted-platform-module-overview"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("tpm");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        JsonNode t = q.first();
        if (t == null) {
            return fail(ds, "No TPM is visible to Windows.", List.of());
        }
        boolean enabled = t.path("IsEnabled_InitialValue").asBoolean(false);
        boolean active = t.path("IsActivated_InitialValue").asBoolean(false);
        Evidence ev = queryEvidence("tpm", "IsEnabled=" + enabled + ", IsActivated=" + active + ", SpecVersion=" + t.path("SpecVersion").asText("?"),
                "Get-Tpm   # elevated");
        if (enabled && active) {
            return pass(ds, "A TPM is present, enabled and activated.", List.of(ev));
        }
        return warn(ds, "A TPM is present but not enabled/activated.", List.of(ev));
    }
}
