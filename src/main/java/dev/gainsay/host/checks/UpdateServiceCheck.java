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
 * HOST-PATCH-003. Implementation: WMI {@code Win32_Service} where Name='wuauserv', property
 * {@code StartMode} (stored at {@code HKLM\SYSTEM\CurrentControlSet\Services\wuauserv\Start}, 4 = Disabled).
 * The service is trigger-started, so "Manual"/"Stopped" is normal.
 */
public final class UpdateServiceCheck extends AbstractCheck {

    public UpdateServiceCheck() {
        super("HOST-PATCH-003", "Windows Update service is not disabled", Categories.PATCHING, Severity.MEDIUM,
                "Disabling wuauserv is a common 'tweak' that silently stops all security patching.",
                "Read StartMode of the wuauserv service from Win32_Service.",
                "Set-Service wuauserv -StartupType Manual (its default) and run Windows Update.",
                List.of("https://learn.microsoft.com/windows/deployment/update/how-windows-update-works"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("service.state");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        for (JsonNode s : q.list()) {
            if ("wuauserv".equalsIgnoreCase(s.path("Name").asText())) {
                String mode = s.path("StartMode").asText("?");
                Evidence ev = queryEvidence("service.state", "wuauserv StartMode=" + mode + ", State=" + s.path("State").asText("?"),
                        "Get-CimInstance Win32_Service -Filter \"Name='wuauserv'\" | Select StartMode, State");
                return "Disabled".equalsIgnoreCase(mode) ? fail(ds, "The Windows Update service is disabled.", List.of(ev))
                        : pass(ds, "The Windows Update service is not disabled (StartMode " + mode + ").", List.of(ev));
            }
        }
        return unknown(ds, "service wuauserv not found", List.of());
    }
}
