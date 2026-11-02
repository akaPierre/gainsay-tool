package dev.gainsay.core.verdict;

import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.HostIdentity;
import dev.gainsay.core.Status;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TribunalTest {

    static final HostIdentity HOST = new HostIdentity("WS1", List.of("10.0.0.5"), List.of("00:11:22:33:44:55"));

    static Claim claim(ClaimType t, boolean secure) {
        return new Claim(t, HOST, secure, t.title(), ClaimStrength.POLICY, "test-basis", "HOST-TEST");
    }

    static Observation obs(ObservationType t, String ip, String peer, int port) {
        return new Observation(t, ip, null, peer, port, Instant.EPOCH, Instant.EPOCH, 1,
                Evidence.of("packet", ip + " -> " + peer, t.name()));
    }

    @Test
    void secureClaimWithViolatingEvidenceIsContradicted() {
        var r = Tribunal.judge(List.of(claim(ClaimType.SMB1_SERVER_DISABLED, true)),
                List.of(obs(ObservationType.SMB1_ACCEPTED_BY_SERVER, "10.0.0.5", "10.0.0.20", 445)), List.of(HOST), List.of());
        Verdict v = r.verdicts().get(0);
        assertEquals(VerdictKind.CONTRADICTED, v.kind());
        assertEquals("ip", v.matchedBy());
        assertTrue(v.surprise() > 0);
        Finding f = r.findings().get(0);
        assertEquals("TRIAL-SMB1-SRV", f.id());
        assertEquals(Status.FAIL, f.status());
        assertEquals(1, r.summary().contradicted());
        assertEquals(1.0, r.summary().coverage());
    }

    @Test
    void secureClaimWithOnlyConformingEvidenceIsCorroborated() {
        var r = Tribunal.judge(List.of(claim(ClaimType.SMB_SERVER_SIGNING_REQUIRED, true)),
                List.of(obs(ObservationType.SMB_SIGNING_REQUIRED_BY_SERVER, "10.0.0.5", "10.0.0.20", 445)), List.of(HOST), List.of());
        assertEquals(VerdictKind.CORROBORATED, r.verdicts().get(0).kind());
        assertEquals(Status.PASS, r.findings().get(0).status());
    }

    @Test
    void claimWithoutRelevantEvidenceIsUntestedAndProducesNoFinding() {
        var r = Tribunal.judge(List.of(claim(ClaimType.LLMNR_DISABLED, true)),
                List.of(obs(ObservationType.SMB1_ACCEPTED_BY_SERVER, "10.0.0.5", "10.0.0.20", 445)), List.of(HOST), List.of());
        assertEquals(VerdictKind.UNTESTED, r.verdicts().stream().filter(v -> v.claimType() == ClaimType.LLMNR_DISABLED).findFirst().orElseThrow().kind());
        assertEquals(0.0, r.summary().coverage());
        assertTrue(r.findings().isEmpty());
    }

    @Test
    void evidenceFromUnauditedAddressIsUnclaimed() {
        var r = Tribunal.judge(List.of(), List.of(obs(ObservationType.LLMNR_QUERY_SENT, "10.0.0.99", null, 5355)), List.of(HOST), List.of());
        assertEquals(1, r.summary().unclaimed());
        assertEquals("10.0.0.99", r.verdicts().get(0).hostLabel());
    }

    @Test
    void matchesByMacWhenIpDiffers() {
        Observation o = new Observation(ObservationType.LLMNR_QUERY_SENT, "10.9.9.9", "00-11-22-33-44-55", null, 5355,
                Instant.EPOCH, Instant.EPOCH, 3, null);
        var r = Tribunal.judge(List.of(claim(ClaimType.LLMNR_DISABLED, true)), List.of(o), List.of(HOST), List.of());
        assertEquals(VerdictKind.CONTRADICTED, r.verdicts().get(0).kind());
        assertEquals("mac", r.verdicts().get(0).matchedBy());
    }

    @Test
    void insecureClaimConfirmedLiveIsInfoNotDoubleCounted() {
        var r = Tribunal.judge(List.of(claim(ClaimType.LLMNR_DISABLED, false)),
                List.of(obs(ObservationType.LLMNR_QUERY_SENT, "10.0.0.5", null, 5355)), List.of(HOST), List.of());
        assertEquals(VerdictKind.CORROBORATED, r.verdicts().get(0).kind());
        assertEquals(dev.gainsay.core.Severity.INFO, r.findings().get(0).severity());
    }

    @Test
    void blastRadiusListsObservedDependants() {
        var r = Tribunal.judge(List.of(claim(ClaimType.SMB1_SERVER_DISABLED, false)),
                List.of(obs(ObservationType.SMB1_ONLY_CLIENT_OFFER, "10.0.0.42", "10.0.0.5", 445),
                        obs(ObservationType.SMB1_ACCEPTED_BY_SERVER, "10.0.0.5", "10.0.0.42", 445)), List.of(HOST), List.of());
        Verdict v = r.verdicts().get(0);
        assertEquals(List.of("10.0.0.42"), v.dependants());
        assertTrue(r.findings().get(0).remediation().contains("10.0.0.42"));
    }

    @Test
    void contradictionsRankFirstBySurprise() {
        Claim policyClaim = claim(ClaimType.RDP_DISABLED, true);
        Claim defaultClaim = new Claim(ClaimType.LLMNR_DISABLED, HOST, true, "x", ClaimStrength.DEFAULT, "b", "c");
        var r = Tribunal.judge(List.of(defaultClaim, policyClaim),
                List.of(obs(ObservationType.LLMNR_QUERY_SENT, "10.0.0.5", null, 5355),
                        obs(ObservationType.SERVICE_LISTENING, "10.0.0.5", "10.0.0.20", 3389)), List.of(HOST), List.of());
        assertEquals(ClaimType.RDP_DISABLED, r.verdicts().get(0).claimType());
        assertTrue(r.verdicts().get(0).surprise() > r.verdicts().get(1).surprise());
    }

    @Test
    void portPredicatesMatter() {
        var r = Tribunal.judge(List.of(claim(ClaimType.RDP_DISABLED, true)),
                List.of(obs(ObservationType.SERVICE_LISTENING, "10.0.0.5", "10.0.0.20", 445)), List.of(HOST), List.of());
        assertEquals(VerdictKind.UNTESTED, r.verdicts().get(0).kind());
    }
}
