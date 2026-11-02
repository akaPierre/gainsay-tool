# MASTER PROMPT — Security Posture Assessment Tool (for Claude Code)

Copy everything below the line into Claude Code, from an empty project directory.

---

## 0. ROLE

You are a senior security engineer and software architect. Build a **defensive, read-only security posture assessment tool** from scratch, in this directory, following the specification below. Work autonomously, but follow the workflow in section 9 and stop at the checkpoints it lists.

## 1. HARD RULES (non-negotiable)

1. **NO COMMITS.** Do not run `git init`, `git add`, `git commit`, `git push`, `git branch`, `git tag`, or any other command that writes to version control. Do not create a repository, do not add a `.git` directory, and do not offer to commit. A `.gitignore` file is fine; nothing else git-related. If a tool or scaffolder tries to initialise git, disable that option (e.g. `--no-git`).
2. **Defensive only.** The tool measures *security posture* (is a best practice in place?), not whether a machine is currently compromised. It must never exploit, brute-force, fuzz, bypass, or modify anything.
3. **Read-only on the host.** Never change registry keys, settings, firewall rules, services, or files outside the project's own output directory. Every Windows check must be a read.
4. **Authorized scope only.** Anything that touches the network actively must require an explicit, user-supplied scope (see 5.4). Default behaviour is passive.
5. **Do not capture or store secrets.** Never persist payload bodies, passwords, cookies, tokens, or credentials seen on the wire. Store only metadata (addresses, ports, protocol, version, timestamps, counts). When a finding needs evidence, redact it (e.g. `Authorization: Basic ****`).
6. Stay inside this project directory. Do not install anything system-wide; use project-local dependencies only. Ask before adding any dependency that is not listed in section 6.
7. No network calls from the tool itself to third-party services (no telemetry, no update checks, no cloud lookups).

## 2. SOURCE IDEA (what this tool is based on)

The tool is entirely based on the following two ideas:

**Idea A — Local host posture check.** A Windows application that evaluates a machine's security posture by checking best practices rather than compromise: is an antivirus active, is UAC enabled, and so on. It gathers data from registry keys, Windows settings and WMI queries. The learning value comes from (a) studying the generally accepted best practices for Windows desktop security and (b) studying how each practice is implemented so it can be verified programmatically.

**Idea B — Network posture check.** Adapt the same concept to the network: instead of checking settings on one machine, route and monitor traffic through a PC with multiple NICs, and flag posture problems such as unencrypted HTTP, outdated SMB, and open ports. Doing this needs low-level packet handling bridged to a higher-level language.

Build **both**, as two modules of one tool sharing a common findings/reporting core.

## 3. PRODUCT SUMMARY

Working name: **PosturePilot** is only a placeholder. Replace it with a distinctive name per section 3b (the CLI examples below use the placeholder).

A command-line tool that:
- runs **host checks** on Windows (Module A) and produces graded findings,
- analyses **network traffic** (Module B) either live on a bridging/multi-NIC machine or offline from a `.pcap/.pcapng` file, and produces graded findings,
- merges everything into one scored report (JSON + HTML + Markdown) with plain-language explanations and concrete remediation steps for each finding.

Primary audience: a technically curious person who wants to learn *why* each best practice matters. Every check must therefore teach: what it checks, why it matters, how it was verified, how to fix it.

## 3b. UNIQUENESS MANDATE (applies to the whole project)

This tool must be **distinctive, not a rebuild of something that already exists**. Treat "generic" as a defect.

**What counts as generic (avoid by default):** a plain checklist-with-a-score clone of Lynis, Microsoft Security Compliance Toolkit, CIS-CAT, HardeningKitty, PingCastle, Nmap, Wireshark/Zeek/Suricata alerts, or Nessus-style reports; a red/amber/green dashboard with a letter grade as the main idea; "AI-powered" anything as a selling point; stock names like "SecScan", "PostureCheck", "NetGuard"; reports that only list "setting X is wrong, set it to Y".

**Process you must follow before designing:**
1. Spend a short research pass (web search is fine) on what existing posture/hardening/network-audit tools do, and write a half-page "landscape and gaps" note in `docs/PLAN.md`.
2. Brainstorm at least **10** candidate differentiators, then **reject** every one that an existing tool already does well or that an average LLM would suggest first. Write down which you rejected and why.
3. Choose **one signature concept** (plus at most two supporting ideas) and build the whole product around it. The signature concept must be visible in the CLI, the data model and the report, not bolted on.
4. Pick a **distinctive project name** (not a generic compound of "security", "scan", "guard", "shield", "posture"). Check that it does not collide with a well-known existing tool or package.

**Seed directions (starting points only — you may use, combine, or beat them; you are explicitly encouraged to invent something better):**
- **Cross-plane contradiction engine.** The article's two ideas (host settings vs. network traffic) are usually run separately. Correlate them: the host report says "SMBv1 disabled", but the network module observes that host speaking SMB1, or "TLS 1.0 disabled" while TLS 1.0 handshakes are seen. Findings are *contradictions between what is configured and what is actually happening*, ranked by how surprising they are. This is the "claimed vs. observed posture" gap.
- **Teach-by-proof findings.** Every finding ships with *proof of mechanism*: the exact registry path/value or WMI property read, or the exact bytes/fields in the packet that triggered it (redacted), plus a "reproduce this check by hand" snippet. The report is a learning artifact, not just an audit.
- **Posture drift ledger.** Instead of a single score, keep an append-only local ledger of runs and show *how posture changed over time* (what regressed, what quietly fixed itself, which settings flip back after updates or Group Policy refresh), with a "posture half-life" per setting.
- **Counterfactual remediation.** For each failing item, estimate which *other* findings would also disappear (or newly break) if it were fixed, and propose the smallest ordered set of changes that removes the most risk, including side-effect warnings (e.g. disabling SMBv1 may break an old scanner seen on the network).
- **Segment-aware posture.** In the multi-NIC placement, score each *network segment and boundary crossing* separately, so the tool answers "which segment is the weak one and which flows cross the boundary in cleartext", not just "the network is bad".

**Genericness test (run before each checkpoint and again at the end):** for each major feature ask "could someone get this from an existing free tool in under 10 minutes?" and "would a typical LLM have proposed this first?" If yes to either, redesign or demote it. Report the result of this test in your checkpoint messages.

**Non-negotiable:** uniqueness never overrides section 1 (no commits, defensive, read-only, authorized scope) or accuracy. Do not claim novelty you have not checked, and do not invent features that the data cannot support.

## 4. MODULE A — WINDOWS HOST POSTURE

### 4.1 Design
- Each check is a small self-contained class implementing a common `Check` interface: `id`, `title`, `category`, `severity`, `rationale`, `howVerified`, `remediation`, `references`, and `evaluate(HostDataSource) -> Finding`.
- **All system access goes through a `HostDataSource` abstraction** with two implementations:
  - `WindowsHostDataSource` — real reads (registry via `reg query` / PowerShell `Get-ItemProperty`, WMI/CIM via PowerShell `Get-CimInstance`, `Get-NetFirewallProfile`, `Get-MpComputerStatus`, `manage-bde -status`, etc.). Use read-only commands only, with timeouts, and parse structured output (prefer `ConvertTo-Json`).
  - `FakeHostDataSource` / fixture-driven implementation — loads recorded JSON fixtures so every check is unit-testable on Linux/macOS.
- On a non-Windows OS, Module A must degrade gracefully: print that live host checks need Windows, and offer `--fixture <file>` to run against recorded data.
- A check that cannot run (missing permission, feature absent, command failed) returns status `UNKNOWN` with the reason; it never crashes the run and never guesses.

### 4.2 Minimum check catalogue (implement all; add more if time permits)
Group by category and give each a stable ID (`HOST-xxx`).

- **Malware protection:** an AV/EDR product is registered and active (Security Center WMI `AntiVirusProduct`, interpret `productState` bits correctly); real-time protection on; signatures up to date (age threshold configurable); Microsoft Defender tamper protection state; cloud-delivered protection.
- **Account control:** UAC enabled (`EnableLUA`), consent-prompt behaviour for admins, secure desktop prompt; built-in Administrator disabled/renamed; Guest disabled; password policy (min length, lockout threshold); no blank-password local accounts; auto-logon not configured with stored credentials.
- **Firewall:** Domain/Private/Public profiles enabled; default inbound action is block.
- **Patching:** OS build is supported; last installed hotfix age; Windows Update service not disabled; automatic update policy.
- **Disk & boot:** BitLocker (or equivalent) on the OS volume; Secure Boot enabled; TPM present/ready.
- **Network-facing settings:** SMBv1 disabled (client and server); SMB signing required/enabled; RDP disabled or NLA required; LLMNR / NetBIOS-over-TCP/IP exposure; WinRM exposure; legacy TLS/SSL protocols (SSL 3.0, TLS 1.0/1.1) disabled in SCHANNEL.
- **Credential protection:** LSA protection (`RunAsPPL`), Credential Guard status, WDigest plaintext caching disabled, NTLMv1 disabled (`LmCompatibilityLevel`).
- **Execution & hardening:** SmartScreen enabled; PowerShell script block logging and execution policy; Windows Script Host exposure; AutoRun/AutoPlay disabled for removable media.
- **Auditing:** key audit policy categories enabled; event log sizes/retention sane.
- **Software hygiene:** list of installed software flagged against a small, local, user-editable "end-of-life / risky" list (no online lookups).

For every check, document in code comments *how the setting is actually implemented* (registry path/value, WMI class, or cmdlet) — this knowledge is the learning goal of the project.

## 5. MODULE B — NETWORK POSTURE

### 5.1 Concept
A machine with two or more NICs acts as a monitored path (bridge/router/tap-style placement) so traffic between segments passes through, or is mirrored to, a capture interface. The module inspects that traffic **passively** and reports posture weaknesses.

### 5.2 Architecture
- **Capture layer (low-level):** abstract behind a `PacketSource` interface with two implementations: `LiveCaptureSource` (libpcap/Npcap on a chosen interface) and `PcapFileSource` (offline `.pcap`/`.pcapng`). The rest of the module must not know which one it is using.
- **Do not write C/C++ yourself unless the chosen Java binding makes it impossible to meet the spec.** The article notes low-level code is typically needed to bridge to a higher-level language; satisfy this by using a mature binding to libpcap/Npcap (see section 6) and keep the native boundary thin and isolated in one package.
- **Decoder layer:** Ethernet → IPv4/IPv6 → TCP/UDP/ICMP; then protocol detectors listed below. Be robust against truncated, malformed and fragmented packets (never throw out of the capture loop).
- **Analyzer layer:** stateful analyzers consuming decoded packets and emitting `Finding`s; flow table keyed by 5-tuple with bounded memory (LRU/eviction + configurable cap).
- **Multi-NIC support:** list interfaces, let the user pick the capture interface(s), and document in the README how to place the machine (Linux bridge, Windows network bridge, or switch port mirroring) — documentation only, the tool must not reconfigure the OS network stack.

### 5.3 Minimum analyzers (`NET-xxx` IDs)
- **Cleartext HTTP:** HTTP on any port, especially login forms/Basic auth/credential-like parameters (flag the *presence*, redact the values); cookies without `Secure` on HTTPS contexts if observable.
- **Cleartext legacy protocols:** Telnet, FTP (control + data), POP3/IMAP/SMTP without TLS (note STARTTLS vs plain), TFTP, SNMP v1/v2c, rlogin/rsh, LDAP simple bind without TLS.
- **SMB posture:** detect SMB1 negotiation (including dialect list in the negotiate request/response), SMB2/3 without signing required, SMB over unusual exposure; flag NTLM-over-SMB usage where visible.
- **TLS posture (from handshake metadata only):** SSL 3.0 / TLS 1.0 / 1.1 negotiated or offered, weak cipher suites (NULL, EXPORT, RC4, 3DES, anon), expired or self-signed certificates visible in the handshake, missing SNI where relevant. Never attempt to decrypt.
- **Name resolution weaknesses:** LLMNR, NBT-NS and mDNS usage on the segment; unencrypted DNS volume and DNS to unexpected resolvers.
- **Exposed services / open ports (passive):** infer listening services from observed SYN-ACK / UDP responses, and report risky ones (RDP, SMB, Telnet, VNC, database ports, management interfaces, Docker/Kubernetes APIs, etc.) especially if they appear reachable across segment boundaries.
- **Network hygiene signals:** ARP anomalies that indicate misconfiguration (duplicate IP/MAC conflicts — report as posture/hygiene, not as an attack verdict), rogue DHCP offers from more than one server, plaintext protocols crossing the monitored boundary.
- Each analyzer carries a unit test fed by small synthetic pcap fixtures that the test suite generates itself (build packets programmatically; do not download captures).

### 5.4 Optional active mode (off by default)
- Provide an `scan` subcommand that performs a **low-rate TCP connect check** of a short, explicit list of common ports.
- It must refuse to run unless **all** of these hold: the user passed `--i-am-authorized`, a target CIDR/host list is given explicitly, and every target is inside private/RFC1918/link-local ranges or in a user-maintained `allowed_targets.txt`. Public IPs are refused unless listed in that allowlist.
- Hard rate limit (configurable, conservative default), connect-only (no SYN-stealth, no payloads, no banner exploitation, no service fuzzing), and a clear banner telling the user they are responsible for having permission.
- Results are merged into the same findings model.

## 6. TECH STACK (defaults — confirm at Checkpoint 1)

- **Language:** Java 21, Maven, JUnit 5. Single CLI entry point (picocli).
- **Packet capture:** `pcap4j` (binding to libpcap/Npcap). Keep all native-dependent code in a single `capture` package so the rest is pure Java and testable without root/admin.
- **Reports:** JSON (Jackson), Markdown, and a single-file self-contained HTML report (no external JS/CSS/CDN, no network at view time).
- No Spring Boot is required; this is a CLI/library. If you believe a different stack is clearly better, state why at Checkpoint 1 and wait for approval.

## 7. SHARED CORE

### 7.1 Finding model
`Finding { id, module, category, title, severity (INFO/LOW/MEDIUM/HIGH/CRITICAL), status (PASS/FAIL/WARN/UNKNOWN/NOT_APPLICABLE), summary, evidence (redacted, bounded), rationale, remediation, references, firstSeen/lastSeen, occurrences }`

### 7.2 Scoring
- A transparent scoring model: weight by severity, show the formula in the report, show per-category subscores and an overall 0–100 score and letter grade.
- `UNKNOWN` never counts as a pass; report coverage (how many checks actually ran) next to the score.
- No hidden magic: the scoring doc lives in `docs/SCORING.md`.

### 7.3 Reports
- `report.json` (machine-readable, versioned schema), `report.md`, `report.html`.
- Sections: executive summary, score + coverage, top risks, findings by category, per-finding "why / how verified / how to fix", and an appendix of checks that could not run.
- A `--baseline previous.json` option to show what improved or regressed.

### 7.4 CLI
```
posturepilot host   [--fixture FILE] [--out DIR] [--format json,md,html]
posturepilot net    (--iface NAME | --pcap FILE) [--duration SEC] [--out DIR]
posturepilot scan   --targets CIDR_OR_FILE --i-am-authorized [--rate N] [--out DIR]
posturepilot report --inputs a.json,b.json [--baseline OLD.json] [--out DIR]
posturepilot list-checks | list-ifaces | version
```
Exit codes: 0 ok, 1 findings at/above `--fail-on` severity, 2 usage error, 3 runtime error.

## 8. QUALITY BAR

- Clean package structure (`core`, `host`, `net`, `net.capture`, `report`, `cli`), small classes, no god objects.
- Every check/analyzer has unit tests; the whole suite must pass with `mvn -q test` on Linux **without** root, Npcap, or Windows.
- Integration test: generate a synthetic pcap containing cleartext HTTP, Telnet, SMB1 negotiate, and TLS 1.0 hello, run `net --pcap`, and assert the expected findings.
- Fixture-based integration test for `host` covering both a "hardened" and an "unhardened" machine fixture, asserting different scores.
- Input hardening: treat all parsed packet data and all command output as untrusted; bound sizes, handle malformed input, no unbounded memory growth, no regex catastrophic backtracking.
- No hard-coded absolute paths; no secrets in code; logs never contain captured payloads.
- Javadoc on public types explaining the security concept behind each check.

## 9. WORKFLOW (follow in order)

1. **Research and differentiate first** (section 3b): landscape note, 10+ brainstormed differentiators, rejected list, chosen signature concept, distinctive name.
2. **Plan.** Write `docs/PLAN.md` with the differentiation work, architecture, package layout, check/analyzer list with IDs, risks, and a task breakdown. Use the task list tool to track progress.
3. **Checkpoint 1 — stop and show me** the signature concept and why it is not generic, the name, the plan, the tech-stack confirmation, and any open questions (batch them in one message). Wait for my approval.
4. Build the **core** (finding model, scoring, report writers, CLI skeleton, plus the data model the signature concept needs) with tests.
5. Build **Module A** (host) with fixtures and tests.
6. **Checkpoint 2 — short status:** what works, what is stubbed, test results, genericness-test result. Continue unless I object.
7. Build **Module B** (capture abstraction, decoders, analyzers, synthetic-pcap test generator) with tests.
8. Build the signature concept end to end (it should tie Modules A and B together where the concept calls for it) with tests.
9. Build the optional **scan** subcommand with all guardrails from 5.4 and tests for the guardrails (refuses public IPs, refuses without the flag, honours rate limit).
10. Write docs: `README.md` (what it is, what it is not, install, usage, multi-NIC placement guide, safety/legal notice), `docs/CHECKS.md` (every check: what/why/how/fix), `docs/SCORING.md`, `docs/ARCHITECTURE.md`.
11. **Verify:** run the full test suite, run the CLI end-to-end on fixtures, open the generated HTML to confirm it renders offline, re-run the genericness test, re-read the hard rules in section 1 and confirm none were violated (in particular: **no git commands were run and no `.git` exists**).
12. Final message: what was built, what makes it distinctive, how to run it, test results, known limitations, and suggested next steps. No recap of every step.

## 10. WHEN TO ASK vs. DECIDE

- Decide yourself: internal structure, severity weights (document them), report styling. (The name and signature concept are proposed by you but approved by me at Checkpoint 1.)
- Ask me (at the checkpoints, batched): changing the tech stack, adding dependencies beyond section 6, anything that would require admin/root during normal tests, anything that could send traffic to non-private addresses.

## 11. DEFINITION OF DONE

- `mvn -q test` passes on Linux with no special privileges.
- `posturepilot host --fixture <hardened>` and `<unhardened>` produce distinct, correct reports.
- `posturepilot net --pcap <synthetic>` reports cleartext HTTP, Telnet, SMB1 and legacy TLS findings with redacted evidence.
- All reports (JSON/MD/HTML) are generated, self-contained and accurate.
- Documentation is complete and every check explains what, why, how verified, how to fix.
- The signature concept works end to end, is visible in the CLI and the report, and passes the genericness test with a written justification.
- The project directory contains no `.git` directory and no commit was ever made.

Begin with step 1 (research and differentiation). Do not write implementation code before Checkpoint 1 is approved.
