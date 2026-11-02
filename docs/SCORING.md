# Scoring

Gainsay reports two kinds of numbers. **Trial coverage** comes first, because it is what makes Gainsay different. The **posture score** is a conventional 0–100 summary and comes second. Both formulas are below, and the posture formula is also printed in every report.

## 1. Trial coverage (the headline)

```
coverage = (contradicted + corroborated) / claims
```

- **claims**: the network-testable statements made by audited hosts (see [CHECKS.md](CHECKS.md#trial-claims)).
- **tested**: a claim counts as tested only if the capture or scan contained traffic that *could have contradicted it*.
- **untested** claims are listed, never counted as passes. "No SMB1 seen" proves nothing if there was no SMB traffic at all.
- **unclaimed** behaviours (risky traffic from addresses no audited host speaks for) are counted separately. They are not part of coverage.

### Surprise (ranking contradictions)

Contradictions are sorted by how surprising they are:

```
surprise = severity weight × claim strength × evidence confidence
```

| Claim strength | Weight | Meaning |
|---|---|---|
| POLICY | 1.0 | Set by Group Policy/MDM: someone decided this on purpose |
| MEASURED | 0.9 | Reported as the effective state by a cmdlet or WMI provider |
| LOCAL | 0.8 | An explicit local registry value |
| DEFAULT | 0.5 | Nothing configured; the OS default, which varies by build |

Evidence confidence is 1.0 when the host itself put the decisive bytes on the wire (e.g. its own SMB1 NEGOTIATE response). It is lower for indirect inferences, e.g. 0.5 for "NXDOMAIN with no LLMNR fallback seen". The per-type values are in `ObservationType`.

A configured-weak setting that *behaved securely* is also a contradiction, in the benign direction. It is scored as `0.5 × strength × confidence` and graded as a LOW warning: the setting may not be in effect.

## 2. Posture score

1. **Grouping.** Findings are grouped into *checks*:
   - Host and trial findings: per check id **per host**. Two audited machines are two sets of checks.
   - Network and scan findings: per check id across all subjects. The network is one system.
   - A check's status is the worst status of its findings: FAIL > WARN > PASS > UNKNOWN > NOT_APPLICABLE.
   - A check's weight comes from its highest severity.
2. **Weights:**

   | Severity | Weight |
   |---|---|
   | INFO | 0 (never scored) |
   | LOW | 1 |
   | MEDIUM | 3 |
   | HIGH | 6 |
   | CRITICAL | 10 |

3. **Earned points:** PASS = weight, WARN = weight / 2, FAIL = 0.
4. **Measured score** = 100 × Σ earned / Σ weight, over checks that ran (PASS, WARN, FAIL). It is computed overall and per category.
5. **UNKNOWN never counts as a pass.** A check that could not run (access denied, provider missing):
   - is excluded from the measured score;
   - lowers **coverage** = ran / (ran + unknown);
   - counts as a FAIL in the **worst-case score**, which is printed next to the measured score.

   A non-elevated run therefore shows, for example, "16.0 (worst case 14.9), coverage 94%" instead of quietly scoring higher.
6. **NOT_APPLICABLE** checks are excluded entirely, e.g. no TLS traffic to judge, or Defender passive because another AV is active.
7. **Grade** is secondary: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F.

### Why network checks pass only when traffic was seen

A network analyzer with no finding is reported as PASS only if relevant traffic was observed ("no problem in N relevant observations"). Otherwise it is NOT_APPLICABLE. This is the same rule as untested trial claims: absence of evidence is not evidence.

### Trial findings in the score

- CONTRADICTED (secure claim) → FAIL at the claim's severity.
- CORROBORATED (secure claim) → PASS.
- Weakness confirmed live → FAIL at **INFO**, so the underlying HOST finding is not double-counted.
- Benign-direction contradiction → WARN at LOW.

## 3. Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | A FAIL finding at or above `--fail-on SEVERITY` exists (INFO findings never trigger it) |
| 2 | Usage error, including every refusal by the `scan` guardrails |
| 3 | Runtime error (unreadable file, corrupt capture, capture library missing, …) |

## 4. Fix plan ranking

Each action in "Fix these first" is credited with the risk it removes:

```
weight = Σ severity weight of the problem findings it clears   (WARN counts half; INFO counts 0)
```

- A **FIX** item (a host setting) clears its host finding plus the linked network findings about the same host. For example, requiring NLA clears HOST-NETCFG-005, NET-EXPOSE-002 on that host's address, and the matching trial verdict.
- An **INVESTIGATE** item (a contradiction) gets 1.5 × the claim's severity weight plus its linked network findings. A setting that looks right but is not in effect is the most misleading state, so it is boosted.
- A **NETWORK** item groups the remaining network findings of one check id that no host action explains.

Items are sorted by weight. Ties are broken by kind (FIX, INVESTIGATE, NETWORK) and then title. At most 50 items are kept: 10 are shown in the reports and 5 in the terminal.
