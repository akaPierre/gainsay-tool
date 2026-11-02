package dev.gainsay.report;

import dev.gainsay.core.Fix;
import dev.gainsay.core.Report;
import dev.gainsay.host.Check;
import dev.gainsay.host.FixCommands;
import dev.gainsay.host.HostAuditor;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.host.source.FixtureHostDataSource;
import dev.gainsay.net.NetAnalysis;
import dev.gainsay.net.synth.Scenarios;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FixPlannerTest {

    static Report trial(String fixture) throws Exception {
        Report host = HostAuditor.audit(FixtureHostDataSource.load(Path.of("samples", "fixtures", fixture)), CheckCatalog.all(HostPolicy.defaults()));
        Report net = NetAnalysis.analyze(Scenarios.demo().source(), NetAnalysis.Options.defaults());
        return ReportComposer.compose(List.of(host, net), null);
    }

    @Test
    void contradictionsComeFirstWithBlastRadius() throws Exception {
        Report r = trial("host-hardened.json");
        Report.FixItem first = r.fixPlan.get(0);
        assertEquals("INVESTIGATE", first.kind());
        assertEquals("WS-HARDENED", first.host());
        assertTrue(first.mayBreak().contains(Scenarios.SCANNER_IP) || first.mayBreak().contains(Scenarios.LEGACY_IP));
        assertTrue(first.resolves().stream().anyMatch(k -> k.startsWith("NET-")), "the contradiction also accounts for the network finding");
    }

    @Test
    void hostFixesCarryCommandsAndAbsorbLinkedNetworkFindings() throws Exception {
        Report r = trial("host-unhardened.json");
        Report.FixItem nla = r.fixPlan.stream().filter(i -> "HOST-NETCFG-005".equals(i.checkId())).findFirst().orElseThrow();
        assertEquals("FIX", nla.kind());
        assertNotNull(nla.fix().command());
        assertTrue(nla.resolves().stream().anyMatch(k -> k.startsWith("NET-EXPOSE-002@10.0.0.20")), nla.resolves().toString());
        assertTrue(nla.resolves().stream().anyMatch(k -> k.startsWith("TRIAL-")));
        assertTrue(nla.mayBreak().contains(Scenarios.ADMIN_IP), "the admin box that connects without NLA");
        assertTrue(r.fixPlan.stream().noneMatch(i -> i.kind().equals("NETWORK") && i.checkId().equals("NET-EXPOSE-002")),
                "a network finding explained by a host fix is not listed twice");
        for (int i = 1; i < r.fixPlan.size(); i++) {
            assertTrue(r.fixPlan.get(i - 1).weight() >= r.fixPlan.get(i).weight(), "ranked by risk removed");
        }
    }

    @Test
    void cleanHostWithoutEvidenceHasNoHostFixes() throws Exception {
        Report host = HostAuditor.audit(FixtureHostDataSource.load(Path.of("samples", "fixtures", "host-hardened.json")),
                CheckCatalog.all(HostPolicy.defaults()));
        assertTrue(ReportComposer.compose(List.of(host), null).fixPlan.isEmpty());
    }

    @Test
    void fixCommandsAreSafeToCopy() {
        for (Check c : CheckCatalog.all(HostPolicy.defaults())) {
            Fix f = FixCommands.forCheck(c.id());
            assertNotNull(f, c.id() + " has no fix guidance");
            String cmd = f.command();
            if (cmd == null) {
                assertNotNull(f.note(), c.id() + " needs a note when there is no command");
                continue;
            }
            // New-Item -Force on an existing registry key recreates it and deletes its values.
            assertFalse(cmd.contains("New-Item") && cmd.contains("-Force"), c.id() + ": never New-Item -Force on registry keys");
            assertFalse(cmd.contains("<") || cmd.contains(">"), c.id() + ": placeholders must not look like redirection");
        }
    }
}
