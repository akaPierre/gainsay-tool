# Architecture

```
                 ┌──────────────── testimony ────────────────┐      ┌──────────────── evidence ────────────────┐
 Windows host ──▶│ host.source  WindowsHostDataSource        │      │ net.capture  LiveCaptureSource (pcap4j)  │◀── NIC / SPAN
 snapshot.json ─▶│              FixtureHostDataSource        │      │              PcapFileSource (pure Java)  │◀── .pcap/.pcapng
                 │ host.checks  46 Check classes             │      │ net.decode   Decoder + protocol parsers  │
                 │      └─▶ Finding (HOST)  + Claim          │      │ net.analyze  FlowTable, 9 analyzers      │
                 └───────────────────┬───────────────────────┘      │      └─▶ Finding (NET) + Observation     │
                                     │                              └────────────────────┬─────────────────────┘
                                     │        scan: ConnectScanner ─▶ Finding (SCAN) + Observation (guarded)
                                     ▼                                                    ▼
                         ┌────────────────────────── report.ReportComposer ──────────────────────────┐
                         │ merge inputs → core.verdict.Tribunal (claims × observations → verdicts)   │
                         │ → core.score.Scorer → BaselineComparator → JSON / Markdown / HTML writers │
                         └────────────────────────────────────────────────────────────────────────────┘
```

## Packages

| Package | Responsibility |
|---|---|
| `core` | Finding/Evidence/Severity/Status/Plane, `Redactor`, `Report` (versioned JSON schema), `Addresses`/`Cidr` (no DNS ever) |
| `core.verdict` | `Claim`, `ClaimType` (the claim ↔ evidence catalogue), `Observation`, `Verdict`, `Tribunal` |
| `core.score` | Transparent scoring (`Scorer`, see SCORING.md) |
| `host`, `host.checks` | `Check` interface, registry precedence (`RegistrySetting`), 46 checks, local lists |
| `host.source` | `HostDataSource` with live (Windows) and fixture implementations; the PowerShell allow-list |
| `net` | `NetAnalysis` engine, `NetChecks` metadata, `Segments` |
| `net.capture` | `PacketSource` abstraction; **the only native boundary** (`LiveCaptureSource`) |
| `net.decode` | Bounds-checked decoders and parsers (Ethernet/VLAN/SLL, IPv4/IPv6, TCP/UDP/ARP, TLS, SMB, RDP, NTLM, DNS/NBNS, BER, HTTP) |
| `net.analyze` | Flow table, stream heads, analyzers, `AnalysisContext` |
| `scan` | Guarded TCP connect check (`TargetPolicy`, `RateLimiter`, `ConnectScanner`) |
| `report` | Composer, baseline diff, writers |
| `cli` | picocli commands |

## Key design decisions

**Testimony and evidence are separate data, joined late.**
- Host checks emit `Claim`s alongside their findings. Analyzers emit `Observation`s alongside theirs.
- Neither side knows about the other. They meet only in `Tribunal`, which can run at any time on any combination of saved reports (`trial`, `report`, `net --claims-from`, `scan --claims-from`).
- So a snapshot taken on one machine and a capture taken on another can be cross-examined later.

**One snapshot shape for live and fixture.**
- The live collector first runs every check against a *recording* data source, to learn which registry values they read.
- It then reads all of those values in a few batched, read-only PowerShell calls, plus every query in `WindowsQueries`, the fixed allow-list.
- The result is a `HostSnapshot`. That is exactly the fixture format, so `--save-snapshot` produces a replayable, secret-free fixture.

**Registry precedence is modelled, not assumed.**
- `RegistrySetting` reads every location of a setting (Group Policy key first, then the local value) and falls back to a build-dependent default when neither exists.
- The origin of the value becomes the claim's *strength*. That drives the surprise ranking and teaches why "not configured" is not the same as "off".

**The native boundary is one class.**
- pcap4j is used only by `LiveCaptureSource` and `listInterfaces()`.
- pcap4j's offline reader also needs native libpcap, so `.pcap`/`.pcapng` files are parsed in pure Java instead. That is why the test suite runs with no libpcap, no Npcap and no root.

**Bounded everything.**
- Frames over 256 KiB and pcapng blocks over 16 MiB are refused.
- The flow table is an access-ordered LRU with a cap (default 20 000), and evicted flows release their buffers.
- Stream heads keep at most 16 KiB per direction against a shared 64 MiB budget.
- Findings, observations, ARP bindings, MAC↔IP learning, DNS client stats, crossings and services are all capped.
- Parsers use explicit bounds checks (`Bytes`) and throw a private `Malformed` that never leaves the capture loop. Analyzer exceptions are caught per packet and counted.
- Regexes are linear and their input is truncated before matching.

**Evidence is redacted twice.**
- Analyzers build evidence from protocol *metadata* (versions, dialect lists, lengths, names of fields) and mask values themselves.
- Every `Evidence` then passes through `Redactor` in its constructor: Authorization schemes, cookies, password-like parameters and login commands are masked, control bytes escaped, length bounded.
- Some secrets are never read at all: the Winlogon `DefaultPassword` value (only its presence is checked), the RDP `mstshash` cookie, LDAP bind DNs and NTLM user/domain fields.

**MACs are trusted only when they identify one host.**
- Across a router, every packet carries the router's MAC.
- `AnalysisContext` learns MAC→IP bindings and drops the MAC from observations whose MAC was seen with several source IPs. Otherwise matching by MAC would pin routed traffic on the wrong host.

**Reports are safe to open.**
- The HTML is one file with inline CSS, no JavaScript, and a `default-src 'none'` CSP, so it cannot load anything when opened.
- Every data-derived string is escaped. Markdown escapes table and HTML metacharacters.

## Adding a check

- **Host:** implement `Check`, usually by extending `RegistryCheck` or `AbstractCheck`. Document the Windows mechanism in the class Javadoc and add it to `CheckCatalog`. If it has a network signature, add a `ClaimType` with violating/conforming predicates and return a `Claim` from `claims()`. Add tests in `HostChecksTest`, then regenerate `docs/CHECKS.md` (see `DocsGenerator`).
- **Network:** add metadata to `NetChecks`, implement `Analyzer` (`checkIds()`, `onPacket`/`onStream`/`onFlowEnd`) and register it in `NetAnalysis.analyzers`. Emit `Observation`s if the behaviour can test a claim. Build a synthetic capture for it in `AnalyzersTest`.

## The `audit` flow and the fix plan

`gainsay audit` (`cli.AuditCommand`) only orchestrates existing parts. Its five steps:
1. Check elevation with a read-only query.
2. Start a capture:
   - `net.capture.PktmonCapture`, which drives Windows' built-in `pktmon` through the `CommandRunner` seam;
   - or `LiveCaptureSource` on the interface that carries this machine's address;
   - or `--pcap`.
3. Collect the host snapshot while the capture runs.
4. Finish the capture and analyse it.
5. Compose with the previous run in `gainsay-runs/` as the baseline, write the reports, print the terminal summary (`cli.Terminal`) and open the HTML (`cli.Browser`, a local file only).

Every step degrades instead of failing. Without admin, the elevation-only reads come back UNKNOWN and pktmon is skipped with an explanation. Without a capture backend, the run covers the host only and its claims stay UNTESTED.

**pktmon safety:**
- Gainsay starts a capture on the network adapters only (`--comp nics`), with no filters.
- It always stops the session it started, including on Ctrl+C via a shutdown hook.
- If a Packet Monitor session already exists, `start` fails and Gainsay leaves it alone.
- Raw `.etl`/`.pcapng` files are deleted after analysis unless `--keep-capture` is given.

**Fix plan.**
- *Where commands come from:* host findings carry an optional `core.Fix` (command, restart flag, note) from `host.FixCommands`.
- *How it ranks:* `report.FixPlanner` turns the composed report into ranked actions. A host fix gets credit for its own finding, for the trial verdicts built on that check, and for the network findings about the same host that the setting governs (`FixPlanner.NET_LINKS`).
- *Item kinds:* contradictions become INVESTIGATE items. Network problems with no audited host behind them become NETWORK items. The peers seen depending on a weak behaviour are listed as "may break".
- *Safety:* commands are printed, never executed. Registry commands create missing keys one level at a time and never use `New-Item -Force`, which on an existing registry key deletes its values; `FixPlannerTest` enforces this.

**Scheduling.** `cli.ScheduleCommand` only prints the `Register-ScheduledTask` commands; creating a task would change the host. Every value it puts in a command is a PowerShell single-quoted literal (quotes doubled), and the task name is restricted to plain characters. `audit --keep-runs N` (`AuditCommand.pruneRuns`) deletes only folders it recognises as its own runs: a timestamp name, a `report.json`, and no subfolders.

**Packaging.** `packaging/package.ps1` / `package.sh` run `jpackage` with a jlinked runtime of `java.base, java.desktop, java.sql, java.logging` (from `jdeps`). The result is a self-contained `gainsay.exe` or `bin/gainsay`.
