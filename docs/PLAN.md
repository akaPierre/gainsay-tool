# Gainsay — Plan

> The brief's working name was "PosturePilot". The chosen name is **Gainsay** (verb: *to deny or contradict a claim*).
> Status: **approved at Checkpoint 1 and implemented.** The decisions taken during the build are listed at the end.

---

## 1. Landscape and gaps

**Host posture / hardening auditors.**
- *HardeningKitty* (PowerShell, OSS): audits a Windows host against CSV baselines (Microsoft, CIS, DISA STIG, BSI). Output: per-setting pass/fail with a score.
- *CIS-CAT Lite/Pro*: benchmark compliance scanner with a score. Pro needs a licence.
- *Microsoft Security Compliance Toolkit / Policy Analyzer*: compares GPOs and local policy with Microsoft baselines.
- *Lynis*: the Unix equivalent, with a hardening index and suggestions.
- *PingCastle / Purple Knight*: Active Directory risk scoring at domain scope, not at host scope.

**Network-side tools.**
- *Wireshark/tshark*: manual analysis. You can find SMB1, weak TLS or Basic auth if you know the filter to write.
- *Zeek / Suricata / Security Onion*: protocol logs and signature alerts. They are strong at observing traffic, but they know nothing about what the host says its own configuration is.
- *Nmap / Nessus / OpenVAS*: active probing, giving an outside-in view of exposure.
- Small passive "cleartext sniffers" exist, for example the passive module of the Rust AD agent *diego*.

**Drift / intent tools.**
- NetBox Assurance, Gluware and ComplianceNet compare *intended network-device config* with *running config*.
- A few patents tie config changes to performance metrics.

**Gap.** Every tool above answers one question: *"what is the host configured to do?"* or *"what is on the wire?"* None of them treats a host's configuration as a **claim to be tested against observed behaviour**. My research turned up no tool that says *"this host's registry says SMBv1 is off, and here is a packet where it negotiated SMB1"*. None reports **how much of a host's configured posture was ever put to the test** by real traffic either. Host auditors trust the registry. Network monitors cannot tell a misconfiguration from a configuration that is not taking effect. That missing joint is the opportunity.

(Research was a short web pass. The novelty claim is "not found in a short search", not "proven absent".)

## 2. Brainstormed differentiators (12) and verdicts

| # | Candidate | Verdict | Why |
|---|-----------|---------|-----|
| 1 | Letter-grade RAG dashboard | **Rejected** | This is exactly what HardeningKitty, CIS-CAT and Lynis already do, and it is the first idea most LLMs suggest. |
| 2 | Map findings to CIS / STIG / NIST controls | **Rejected** | CIS-CAT and HardeningKitty already do this well. |
| 3 | MITRE ATT&CK technique tagging | **Rejected** | Every vendor does it. It adds labels, not insight. |
| 4 | "AI-explained" findings | **Rejected** | Forbidden by the brief, and it needs network calls. |
| 5 | Attack-path graph across hosts | **Rejected** | BloodHound and PingCastle own this. It also needs AD data we don't collect. |
| 6 | Policy-as-code (Rego/InSpec rules) | **Rejected** | OPA and Chef InSpec already do this. Little learning value for the audience. |
| 7 | Gamified quiz / learning mode | **Rejected** | A gimmick that a typical LLM would suggest. |
| 8 | Posture drift ledger + half-life | **Demoted** | Useful, but drift tooling exists (Gluware, Intune history), and a half-life needs many runs to mean anything. Kept only as the existing `--baseline` diff. |
| 9 | Segment-aware scoring | **Demoted** | Zeek/Security Onion can group by subnet. Kept as a grouping dimension in the report, not as the core idea. |
| 10 | **Claim vs. evidence ("cross-examination")**: every host setting is a *claim* with a predicted network signature, and traffic either corroborates it, contradicts it, or never tests it | **Chosen (signature)** | Not found in any tool surveyed. It joins the two modules instead of putting them side by side. It is grounded in data we really collect. Section 3 explains how it goes beyond the plain "contradiction list" seed. |
| 11 | **Proof-of-mechanism evidence** (exact registry path/WMI property or packet byte offsets, plus a "reproduce by hand" PowerShell/tshark one-liner) | **Chosen (supporting #1)** | HardeningKitty shows the registry path. No tool I found gives a packet-level byte proof with a ready-to-paste tshark filter. It serves the "learn the mechanism" goal directly. |
| 12 | **Observed-dependant blast radius**: for each fix, list the peers *seen on the wire* that would break (e.g. disabling SMB1 server-side breaks 10.0.0.42, which only offered SMB1) | **Chosen (supporting #2)** | This is a narrow, data-backed version of the counterfactual seed. It never guesses: it only names dependants actually observed. Pure-host tools can't do it, and pure-network tools don't know what you are about to change. |

The broader "counterfactual remediation planner" seed was **rejected as stated**. Estimating which unrelated findings disappear needs dependency knowledge the data does not support. Only the observed-dependant part survives, as #12.

## 3. Signature concept: cross-examination of posture

**One sentence:** Gainsay treats each host setting as **testimony**, treats captured traffic as **evidence**, and reports a **verdict** for every claim: *corroborated*, *contradicted*, *untested* or *unclaimed*. It also reports **how much of the posture was actually put on trial**.

How it goes beyond a "list of contradictions":

1. **Claims are first-class data.** Every host check that has a network consequence emits a `Claim`, not only a `Finding`. A claim carries a *predicted signature*, for example:
   `Claim(host=10.0.0.5, "SMB1 server disabled", predicts: NEVER smb.dialect==NT LM 0.12 accepted by 10.0.0.5)`.
2. **Evidence is first-class data.** Network analyzers emit `Observation`s (protocol facts tied to an address, a time and a redacted proof), alongside their own NET findings.
3. **The tribunal** (`core.verdict`) matches claims to observations by host identity (IP/MAC/hostname taken from the host report) and claim type. It returns:
   - **CONTRADICTED**: the configuration says X, and the wire shows not-X. This is the highest-value finding. Possible causes: the setting is not in effect (pending reboot, GPO override, a second NIC or a VM on the same IP), or the check read the wrong key.
   - **CORROBORATED**: matching traffic was seen and agrees with the claim. This is *tested* posture.
   - **UNTESTED**: no traffic was seen that could have falsified the claim. This is reported honestly: an SMB setting with zero SMB traffic proves nothing.
   - **UNCLAIMED**: the wire shows a risky behaviour (for example TLS 1.0 from host X) for which no host claim exists, either because host X was not audited or because no check covers it.
4. **Trial coverage metric**, shown next to the score: *"14 of 22 network-relevant claims were tested by traffic; 2 contradicted."* This is the visible, non-generic headline. The letter grade stays secondary.
5. **Surprise ranking.** Contradictions are ranked by `severity × confidence × (claim strength)`. A claim backed by policy (a GPO key) that is contradicted is more surprising than a default value that is contradicted. The formula is documented in SCORING.md.
6. **Works offline and across a fleet.** `gainsay report --inputs hostA.json,hostB.json,capture.json` puts several hosts' testimony on trial against one capture. Neither module needs to run at the same time or on the same machine as the other.

**Where it shows up:**
- **CLI:** a `trial` subcommand plus a `--claims-from` option on `net`.
- **Data model:** `Claim`, `Observation`, `Verdict` and `TrialSummary` in `report.json`.
- **Report:** the first section is "Testimony vs Evidence", a claim × verdict matrix with proofs. The score comes after it.

### Initial claim ↔ observation mappings (all supported by data we collect)

| Host claim (Module A) | Network evidence that tests it (Module B) |
|---|---|
| SMB1 server/client disabled | SMB1 negotiate request/accept involving that host |
| SMB signing required | SMB2 NEGOTIATE response from the host with SecurityMode lacking SIGNING_REQUIRED |
| TLS 1.0/1.1, SSL 3.0 disabled (SCHANNEL) | ServerHello/ClientHello from that host negotiating or offering those versions |
| LLMNR disabled (GPO EnableMulticast=0) | UDP 5355 queries sourced from the host |
| NetBIOS-over-TCP/IP disabled | UDP 137 NBNS traffic from the host |
| RDP disabled / NLA required | SYN-ACK on 3389 from the host; RDP negotiation without CredSSP/HYBRID |
| WinRM not exposed | SYN-ACK on 5985/5986 |
| ~~Firewall default-inbound = block~~ | *Dropped during the build:* an allow rule makes any listening port legitimate, so traffic alone cannot falsify this setting |
| NTLMv1 disabled (LmCompatibilityLevel ≥ 3) | NTLMSSP AUTHENTICATE with a 24-byte NT response (NTLMv1) from the host |
| WDigest disabled / no cleartext | (no network signature: marked *not testable by network*, which is honest) |

## 4. Architecture

```
cli ──► core (Finding, Severity, Status, Claim, Observation, Verdict, Score, Evidence/Redactor)
         ▲            ▲
host ────┘            └──── net ── net.decode (eth/ip/tcp/udp + protocol parsers, pure Java)
 │                           │── net.analyze (stateful analyzers, bounded flow table)
 │                           └── net.capture (PacketSource; LiveCaptureSource = pcap4j ONLY here;
 │                                            PcapFileSource = pure-Java pcap/pcapng reader)
 └── host.source (HostDataSource: WindowsHostDataSource via PowerShell/reg; FixtureHostDataSource)
verdict (tribunal: claims × observations → verdicts)
report (JSON/MD/HTML writers, baseline diff)
scan (guarded TCP-connect checker)
```

Design decisions:
- **The offline pcap reader is pure Java.** pcap4j's `openOffline` still needs native libpcap. So that `mvn test` passes on Linux without libpcap, `PcapFileSource` parses pcap/pcapng itself (the formats are simple and well specified). pcap4j is used **only** in `LiveCaptureSource`, which is loaded reflectively, so a missing Npcap gives a clean error.
- **Protocol decoding is hand-written in pure Java,** with bounded, offset-checked parsing. I don't use pcap4j's packet classes. This keeps the native boundary to a single class and makes decoders testable from byte arrays.
- **Synthetic pcap generator in test sources** (`PcapWriter` + packet builders). It builds Ethernet/IP/TCP frames carrying HTTP, Telnet, an SMB1 negotiate, a TLS 1.0 ClientHello, LLMNR, and so on.
- **HostDataSource** exposes typed reads: `registryValue(hive, path, name)`, `cim(className, namespace, properties)`, `powershellJson(cmdletId)`. The Windows implementation only runs commands from a **fixed allow-list** of read-only commands with timeouts and output-size caps. Fixtures are JSON keyed the same way.
- **Redactor** in core: every piece of evidence passes through it (Basic/Bearer/cookies/password-like params → `****`), and evidence is truncated to a fixed length.
- **Bounded memory:** LRU flow table (default cap 50k flows), per-analyzer occurrence caps, aggregate counters instead of storing lists.

### Package layout
`dev.gainsay.{core, core.verdict, host, host.checks, host.source, net, net.capture, net.decode, net.analyze, scan, report, cli}`

## 5. Check / analyzer catalogue (IDs)

**Host (HOST-xxx).** Implements all of section 4.2 of the brief.
- **AV (Malware protection):**
  - HOST-AV-001 AV product registered and active (SecurityCenter2 `productState` bits)
  - HOST-AV-002 real-time protection
  - HOST-AV-003 signature age
  - HOST-AV-004 tamper protection
  - HOST-AV-005 cloud protection
- **ACC (Account control):**
  - HOST-ACC-001 UAC EnableLUA
  - HOST-ACC-002 admin consent prompt
  - HOST-ACC-003 secure desktop
  - HOST-ACC-004 built-in Administrator
  - HOST-ACC-005 Guest
  - HOST-ACC-006 min password length
  - HOST-ACC-007 lockout threshold
  - HOST-ACC-008 accounts without password required
  - HOST-ACC-009 AutoAdminLogon with DefaultPassword
- **FW (Firewall):**
  - HOST-FW-001..003 profile enabled (Domain/Private/Public)
  - HOST-FW-004 default inbound block
- **PATCH (Patching):**
  - HOST-PATCH-001 supported build
  - HOST-PATCH-002 last hotfix age
  - HOST-PATCH-003 wuauserv not disabled
  - HOST-PATCH-004 AU policy
- **BOOT (Disk & boot):**
  - HOST-BOOT-001 BitLocker OS volume
  - HOST-BOOT-002 Secure Boot
  - HOST-BOOT-003 TPM ready
- **NETCFG (Network-facing settings):**
  - HOST-NETCFG-001 SMB1 server
  - HOST-NETCFG-002 SMB1 client
  - HOST-NETCFG-003 SMB signing (server)
  - HOST-NETCFG-004 SMB signing (client)
  - HOST-NETCFG-005 RDP/NLA
  - HOST-NETCFG-006 LLMNR
  - HOST-NETCFG-007 NetBIOS over TCP/IP
  - HOST-NETCFG-008 WinRM
  - HOST-NETCFG-009 SCHANNEL legacy protocols
- **CRED (Credential protection):**
  - HOST-CRED-001 RunAsPPL
  - HOST-CRED-002 Credential Guard
  - HOST-CRED-003 WDigest
  - HOST-CRED-004 LmCompatibilityLevel
- **EXEC (Execution & hardening):**
  - HOST-EXEC-001 SmartScreen
  - HOST-EXEC-002 script block logging
  - HOST-EXEC-003 execution policy
  - HOST-EXEC-004 WSH
  - HOST-EXEC-005 AutoRun
- **AUDIT (Auditing):**
  - HOST-AUDIT-001 audit policy categories (`auditpol /get /category:* /r`)
  - HOST-AUDIT-002 Security/System log size
- **SW (Software hygiene):** HOST-SW-001 installed software vs local `eol-software.txt`

**Network (NET-xxx).**
- **HTTP:**
  - NET-HTTP-001 cleartext HTTP
  - NET-HTTP-002 credentials in cleartext HTTP (Basic auth / password params / login forms; redacted)
  - NET-HTTP-003 cookie without Secure on a TLS-observable context
- **LEGACY:**
  - NET-LEGACY-001 Telnet
  - NET-LEGACY-002 FTP
  - NET-LEGACY-003 POP3/IMAP/SMTP plain vs STARTTLS
  - NET-LEGACY-004 TFTP
  - NET-LEGACY-005 SNMP v1/v2c
  - NET-LEGACY-006 rlogin/rsh
  - NET-LEGACY-007 LDAP simple bind without TLS
- **SMB:**
  - NET-SMB-001 SMB1 dialect offered/negotiated
  - NET-SMB-002 SMB2/3 signing not required
  - NET-SMB-003 NTLM over SMB (NTLMv1 detection)
  - NET-SMB-004 SMB crossing segment boundary
- **TLS:**
  - NET-TLS-001 legacy version
  - NET-TLS-002 weak cipher suites
  - NET-TLS-003 expired/self-signed certificate (TLS ≤1.2 Certificate message only; TLS 1.3 certificates are encrypted, which is documented as a limitation)
  - NET-TLS-004 missing SNI
- **NAME (Name resolution):**
  - NET-NAME-001 LLMNR
  - NET-NAME-002 NBT-NS
  - NET-NAME-003 mDNS
  - NET-NAME-004 cleartext DNS volume / unexpected resolvers
- **EXPOSE (Exposed services):** NET-EXPOSE-001 risky listening services inferred passively (SYN-ACK / UDP responses)
- **HYG (Network hygiene):**
  - NET-HYG-001 ARP IP/MAC conflict
  - NET-HYG-002 multiple DHCP servers
  - NET-HYG-003 plaintext across boundary

**Trial (TRIAL-xxx).** One verdict per claim type, e.g. TRIAL-SMB1-SRV, TRIAL-TLS-LEGACY, TRIAL-LLMNR.

**Scan (SCAN-xxx).** SCAN-001 risky port reachable (connect-only).

## 6. Tech stack (confirmation)

- Java **21** language level (`maven.compiler.release=21`). The machine has JDK 25 and Maven 3.10, which compile release 21 fine. Maven, JUnit 5, picocli, Jackson as specified.
- **pcap4j 1.8.2 (pcap4j-core)**, live capture only. It pulls in **JNA** and **slf4j-api** transitively. → **Approval needed** (they come with pcap4j, but they are not named in section 6).
- Logging: slf4j-simple at runtime, or route slf4j to no-op and use `System.err`. → **Your preference?** (my default: slf4j-simple, project-local).
- Shade/assembly plugin to build a runnable fat jar (build plugin, not a runtime dependency).
- No Spring and no other runtime dependencies. HTML report: inline CSS, no JS frameworks, no CDN.

## 7. Risks

- **Identity matching** between a host report and network addresses: the host report records all its NIC IPs and MACs (`Get-NetIPAddress`, `Get-NetAdapter`). DHCP changes between runs can mismatch, so match on MAC when it is available, and say which method was used.
- **False contradictions:** a capture made at a different time from the host run. Verdicts record the time window of both, and we warn if they don't overlap.
- **pcap4j age** (last release 2019): it stays isolated behind `LiveCaptureSource`, so it can be swapped later.
- **Admin-only reads** (BitLocker, auditpol, Credential Guard): these return UNKNOWN with "requires elevation"; they are never guessed.
- **Encrypted TLS 1.3 certificates:** limitation documented.

## 8. Task breakdown

1. Maven skeleton, `.gitignore` (no git init), core model, Redactor, scoring, JSON/MD/HTML writers, CLI skeleton, exit codes, plus tests.
2. Claim/Observation/Verdict model + tribunal, with tests against hand-made claims and observations.
3. Module A: HostDataSource + fixture source + Windows source (allow-listed commands); all HOST checks; hardened/unhardened fixtures; integration test. **→ Checkpoint 2**
4. Module B: pure-Java pcap/pcapng reader, decoders, flow table, analyzers, synthetic pcap generator, integration test (HTTP, Telnet, SMB1, TLS 1.0).
5. End-to-end trial: `trial` command, report section "Testimony vs Evidence", blast-radius notes, contradiction fixture test.
6. `scan` with guardrails + tests (refuses public IPs, refuses without the flag, rate limit).
7. Docs: README, CHECKS.md, SCORING.md, ARCHITECTURE.md.
8. Verify: full test run, CLI end to end, HTML renders offline, genericness re-test, hard-rule audit (no `.git`).

## 9. Proposed CLI (placeholder name replaced)

```
gainsay host   [--fixture FILE] [--out DIR] [--format json,md,html] [--fail-on SEV]
gainsay net    (--iface NAME | --pcap FILE) [--duration SEC] [--claims-from host.json] [--out DIR]
gainsay trial  --host host.json[,host2.json] --net net.json [--out DIR]
gainsay scan   --targets CIDR_OR_FILE --i-am-authorized [--rate N] [--out DIR]
gainsay report --inputs a.json,b.json [--baseline OLD.json] [--out DIR]
gainsay list-checks | list-ifaces | version
```

## 10. Genericness test (pre-checkpoint)

| Feature | Free tool in < 10 min? | Typical LLM's first idea? | Result |
|---|---|---|---|
| Host check catalogue | Yes (HardeningKitty) | Yes | Required by the brief. **Demoted to substrate**, made distinct by proof-of-mechanism evidence |
| Network analyzers | Partly (Zeek + scripts) | Yes | Required by the brief. Substrate |
| Claim/evidence tribunal + trial coverage | No tool found | The contradiction idea was a seed in the brief; the *verdict model with UNTESTED/coverage* is the extension | **Signature** |
| Proof + reproduce-by-hand one-liners | Partially (registry path only) | Moderately | Supporting |
| Observed-dependant blast radius | No | No | Supporting |
| 0–100 score + grade | Yes | Yes | Kept because the brief requires it. **Secondary** in the report |

## 11. Decisions taken during the build

- **Open questions from Checkpoint 1**, approved with the proposed defaults:
  - pcap4j brings in JNA and slf4j-api; slf4j-simple is the runtime logger.
  - Maven Shade builds the runnable jar.
  - `.pcap`/`.pcapng` files are read by a pure-Java reader.
  - `trial` was added as a command, and `--claims-from` was added to both `net` and `scan`.
- **The firewall claim was dropped from the trial.** Default-inbound=block cannot be contradicted by traffic, because allow rules make open ports legitimate. HOST-FW-004 is still a host check.
- **One snapshot format.** Live collection produces a `HostSnapshot`, the same format as a fixture, so `--save-snapshot` gives replayable fixtures. A dry run against a recording data source discovers the registry reads, and all allow-listed queries are always collected.
- **Registry precedence.** Checks resolve policy → local → build default (`RegistrySetting`). The origin becomes the claim's strength (POLICY/MEASURED/LOCAL/DEFAULT), which feeds the surprise ranking.
- **Refusal evidence makes "secure" claims testable.** An SMB1-only offer refused by the server, a legacy-only ClientHello refused by alert or RST, an RST on 3389/5985/139, and an NXDOMAIN with no multicast fallback all count as conforming evidence. A modern negotiation does not, since it says nothing about whether the legacy protocol is disabled.
- **Router MACs are not trusted.** A MAC seen with several source IPs is removed from observations, so routed traffic cannot be pinned on an audited host by MAC.
- **Per-host scoring.** Host and trial checks are graded per host, and network checks per check id.
- **Network PASS needs traffic.** A network check with no finding is PASS only if relevant traffic was seen, otherwise NOT_APPLICABLE. This mirrors UNTESTED.
- **docs/CHECKS.md is generated** from the same metadata the reports use, and a test fails when it is stale.
