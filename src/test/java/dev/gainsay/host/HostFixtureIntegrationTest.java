package dev.gainsay.host;

import dev.gainsay.core.Finding;
import dev.gainsay.core.Report;
import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ClaimType;
import dev.gainsay.host.checks.CheckCatalog;
import dev.gainsay.host.source.FixtureHostDataSource;
import dev.gainsay.report.ReportComposer;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** Runs the full catalogue against the two recorded machines in samples/fixtures. */
class HostFixtureIntegrationTest {

    static Report audit(String name) throws Exception {
        var ds = FixtureHostDataSource.load(Path.of("samples", "fixtures", name));
        return ReportComposer.compose(List.of(HostAuditor.audit(ds, CheckCatalog.all(HostPolicy.defaults()))), null);
    }

    static Map<String, Status> byId(Report r) {
        return r.findings.stream().collect(Collectors.toMap(Finding::id, Finding::status, (a, b) -> a));
    }

    @Test
    void hardenedMachineScoresHighWithFullCoverage() throws Exception {
        Report r = audit("host-hardened.json");
        Map<String, Status> s = byId(r);
        assertTrue(r.score.score() >= 95, "score was " + r.score.score());
        assertEquals(0, r.score.unknown(), "every check runs on an elevated snapshot");
        assertTrue(s.values().stream().noneMatch(st -> st == Status.FAIL), "no failures expected: " + s);
        assertEquals(Status.PASS, s.get("HOST-NETCFG-001"));
        assertTrue(r.claims.stream().allMatch(c -> c.secure()), "a hardened host only makes secure claims");
        assertTrue(r.claims.stream().anyMatch(c -> c.type() == ClaimType.SMB1_SERVER_DISABLED));
    }

    @Test
    void unhardenedMachineFailsTheRightChecks() throws Exception {
        Report r = audit("host-unhardened.json");
        Map<String, Status> s = byId(r);
        assertTrue(r.score.score() < 30, "score was " + r.score.score());
        for (String id : List.of("HOST-ACC-002", "HOST-ACC-004", "HOST-ACC-005", "HOST-ACC-006", "HOST-ACC-007", "HOST-ACC-009",
                "HOST-FW-003", "HOST-FW-004", "HOST-PATCH-001", "HOST-PATCH-002", "HOST-PATCH-003", "HOST-PATCH-004",
                "HOST-NETCFG-001", "HOST-NETCFG-002", "HOST-NETCFG-005", "HOST-NETCFG-006", "HOST-NETCFG-007", "HOST-NETCFG-009",
                "HOST-CRED-003", "HOST-CRED-004", "HOST-EXEC-001", "HOST-SW-001", "HOST-AV-001", "HOST-AV-002")) {
            assertEquals(Status.FAIL, s.get(id), id);
        }
        for (String id : List.of("HOST-BOOT-001", "HOST-BOOT-003", "HOST-AUDIT-001")) {
            assertEquals(Status.UNKNOWN, s.get(id), id + " needs elevation and must not be guessed");
        }
        assertTrue(r.score.coverage() < 100);
        assertTrue(r.score.worstCase() <= r.score.score());
        assertTrue(r.notes.stream().anyMatch(n -> n.contains("without elevation")));
    }

    @Test
    void scoresAreDistinct() throws Exception {
        assertNotEquals(audit("host-hardened.json").score.score(), audit("host-unhardened.json").score.score());
    }

    @Test
    void claimsCarryTheHostIdentityForTheTrial() throws Exception {
        Report r = audit("host-unhardened.json");
        Map<ClaimType, Boolean> claims = r.claims.stream().collect(Collectors.toMap(c -> c.type(), c -> c.secure(), (a, b) -> a));
        assertEquals(Boolean.FALSE, claims.get(ClaimType.SMB1_SERVER_DISABLED));
        assertEquals(Boolean.FALSE, claims.get(ClaimType.RDP_NLA_REQUIRED));
        assertTrue(r.claims.stream().allMatch(c -> c.host().hasIp("10.0.0.20")));
        assertEquals("00:15:5d:01:02:14", r.claims.get(0).host().macs().get(0));
    }

    @Test
    void reportNeverContainsSecrets() throws Exception {
        String md = dev.gainsay.report.MarkdownReportWriter.render(audit("host-unhardened.json"));
        assertTrue(md.contains("DefaultPassword present (value not read)"));
        Function<String, Boolean> has = md::contains;
        assertFalse(has.apply("Password="));
    }
}
