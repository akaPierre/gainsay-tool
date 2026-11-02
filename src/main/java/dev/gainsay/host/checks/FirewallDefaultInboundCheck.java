package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-FW-004. Implementation: {@code Get-NetFirewallProfile.DefaultInboundAction} per profile
 * ({@code Block}, {@code Allow} or {@code NotConfigured}, which means the Windows default: Block).
 *
 * <p>Deliberately not a trial claim: with default-block, allow rules still open ports, so seeing a
 * listening port on the wire does not contradict this setting.
 */
public final class FirewallDefaultInboundCheck extends AbstractCheck {

    public FirewallDefaultInboundCheck() {
        super("HOST-FW-004", "Firewall blocks unsolicited inbound traffic by default", Categories.FIREWALL, Severity.HIGH,
                "Default-allow inbound turns the firewall into a deny-list: every new service is exposed until someone writes a rule for it.",
                "Read DefaultInboundAction for every profile from Get-NetFirewallProfile.",
                "Set-NetFirewallProfile -All -DefaultInboundAction Block, then add explicit allow rules for the services that must be reachable.",
                List.of("https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("firewall.profiles");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        List<Evidence> ev = new ArrayList<>();
        List<String> allowing = new ArrayList<>();
        for (JsonNode p : q.list()) {
            String action = p.path("DefaultInboundAction").asText("");
            String name = p.path("Name").asText("?");
            ev.add(queryEvidence("firewall.profiles", name + ": DefaultInboundAction=" + action,
                    "Get-NetFirewallProfile | Select Name, DefaultInboundAction"));
            if ("Allow".equalsIgnoreCase(action)) {
                allowing.add(name);
            }
        }
        if (ev.isEmpty()) {
            return unknown(ds, "no firewall profiles listed", ev);
        }
        if (!allowing.isEmpty()) {
            return fail(ds, "Default inbound action is Allow for: " + String.join(", ", allowing) + ".", ev);
        }
        return pass(ds, "Every profile blocks unsolicited inbound traffic by default (NotConfigured = Block).", ev);
    }
}
