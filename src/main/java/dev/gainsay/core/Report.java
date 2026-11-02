package dev.gainsay.core;

import dev.gainsay.core.score.ScoreCard;
import dev.gainsay.core.verdict.Claim;
import dev.gainsay.core.verdict.Observation;
import dev.gainsay.core.verdict.TrialSummary;
import dev.gainsay.core.verdict.Verdict;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The versioned, machine-readable report ({@code report.json}, schema {@value #SCHEMA}). The same
 * structure is read back by {@code gainsay report}/{@code trial} to merge runs and compare baselines.
 */
public final class Report {

    public static final String SCHEMA = "gainsay.report/1";

    public String schema = SCHEMA;
    public Map<String, String> tool = Map.of("name", "gainsay", "version", Version.VERSION);
    public Instant generatedAt = Instant.now();
    /** Which planes contributed: host, net, scan, trial. */
    public List<String> kinds = new ArrayList<>();
    public List<HostInfo> hosts = new ArrayList<>();
    public List<CaptureInfo> captures = new ArrayList<>();
    public List<Finding> findings = new ArrayList<>();
    public List<Claim> claims = new ArrayList<>();
    public List<Observation> observations = new ArrayList<>();
    public List<Verdict> verdicts = new ArrayList<>();
    public TrialSummary trial;
    public ScoreCard score;
    public List<BoundaryCrossing> boundaries = new ArrayList<>();
    public BaselineDiff baseline;
    /** Ranked "fix these first" actions (see report.FixPlanner). */
    public List<FixItem> fixPlan = new ArrayList<>();
    public List<String> notes = new ArrayList<>();

    /**
     * One recommended action.
     *
     * @param kind     FIX (a host setting with a known fix), INVESTIGATE (a contradiction: the setting looks right but is not
     *                 in effect), or NETWORK (a network-wide issue with no single host setting behind it)
     * @param resolves finding keys this action is expected to clear
     * @param weight   risk removed: sum of severity weights of the resolved problem findings (WARN counts half)
     * @param mayBreak peers seen on the wire relying on the weak behaviour
     */
    public record FixItem(int rank, String kind, String checkId, String host, String title, String why, List<String> resolves, double weight,
                          dev.gainsay.core.Fix fix, List<String> mayBreak) {
    }

    /** A host that testified. */
    public record HostInfo(HostIdentity identity, Instant collectedAt, boolean elevated, String os, String source) {
    }

    /** One capture (live or file) that provided evidence. */
    public record CaptureInfo(String source, long packets, long bytes, long malformed, long flowsEvicted,
                              Instant start, Instant end, String segments) {
    }

    /** Traffic between two network segments, as seen by the monitored path. */
    public record BoundaryCrossing(String fromSegment, String toSegment, String protocol, int port, long flows,
                                   boolean cleartext) {
    }

    /** What changed relative to a previous report. */
    public record BaselineDiff(String baselineGeneratedAt, Double previousScore, Double currentScore,
                               List<Change> regressed, List<Change> improved, List<Change> appeared,
                               List<Change> disappeared) {
    }

    /** One finding whose status changed between baseline and current. */
    public record Change(String key, String title, String from, String to) {
    }
}
