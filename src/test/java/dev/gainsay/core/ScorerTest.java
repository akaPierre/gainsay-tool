package dev.gainsay.core;

import dev.gainsay.core.score.ScoreCard;
import dev.gainsay.core.score.Scorer;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScorerTest {

    static Finding f(String id, String cat, Severity sev, Status st) {
        return Finding.builder(id, Plane.HOST).category(cat).title(id).severity(sev).status(st).build();
    }

    @Test
    void weightsBySeverityAndHalvesWarnings() {
        ScoreCard s = Scorer.score(List.of(
                f("A", "c", Severity.HIGH, Status.PASS),     // 6 of 6
                f("B", "c", Severity.MEDIUM, Status.WARN),   // 1.5 of 3
                f("C", "c", Severity.LOW, Status.FAIL)));    // 0 of 1
        assertEquals(Math.round(1000.0 * 7.5 / 10) / 10.0, s.score());
        assertEquals(3, s.ran());
    }

    @Test
    void unknownNeverCountsAsPassAndLowersWorstCaseAndCoverage() {
        ScoreCard s = Scorer.score(List.of(
                f("A", "c", Severity.HIGH, Status.PASS),
                f("B", "c", Severity.HIGH, Status.UNKNOWN)));
        assertEquals(100.0, s.score());
        assertEquals(50.0, s.worstCase());
        assertEquals(50.0, s.coverage());
        assertEquals(1, s.unknown());
    }

    @Test
    void notApplicableAndInfoAreExcluded() {
        ScoreCard s = Scorer.score(List.of(
                f("A", "c", Severity.HIGH, Status.PASS),
                f("B", "c", Severity.HIGH, Status.NOT_APPLICABLE),
                f("C", "c", Severity.INFO, Status.FAIL)));
        assertEquals(100.0, s.score());
        assertEquals(1, s.ran());
    }

    @Test
    void sameIdAggregatesToWorstStatus() {
        ScoreCard s = Scorer.score(List.of(
                Finding.builder("NET-1", Plane.NET).category("n").severity(Severity.HIGH).status(Status.PASS).build(),
                Finding.builder("NET-1", Plane.NET).category("n").severity(Severity.HIGH).status(Status.FAIL).subject("10.0.0.1").build()));
        assertEquals(0.0, s.score());
        assertEquals(1, s.ran());
    }

    @Test
    void hostChecksAreGradedPerHost() {
        ScoreCard s = Scorer.score(List.of(
                Finding.builder("HOST-1", Plane.HOST).category("h").severity(Severity.HIGH).status(Status.PASS).subject("A").build(),
                Finding.builder("HOST-1", Plane.HOST).category("h").severity(Severity.HIGH).status(Status.UNKNOWN).subject("B").build()));
        assertEquals(1, s.ran());
        assertEquals(1, s.unknown(), "B's unknown must not be hidden by A's pass");
    }

    @Test
    void gradesAreBanded() {
        assertEquals("A", Scorer.grade(95));
        assertEquals("C", Scorer.grade(70));
        assertEquals("F", Scorer.grade(10));
    }

    @Test
    void emptyInputHasNoScore() {
        ScoreCard s = Scorer.score(List.of());
        assertNull(s.score());
        assertEquals("n/a", s.grade());
    }
}
