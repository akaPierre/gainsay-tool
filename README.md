# Gainsay

**Gainsay cross-examines a machine's security settings against what its traffic actually shows.**

A host audit only tells you what the configuration *claims*. Gainsay treats those settings as **testimony**. It treats what is seen on the network as **evidence**, and gives every claim a **verdict**:

| Verdict | Meaning |
|---|---|
| **CONTRADICTED** | The registry says "SMBv1 disabled", but here is the packet where this host accepted SMB1. |
| **CORROBORATED** | Traffic that could have proved the setting false was seen, and it agreed. |
| **UNTESTED** | Nothing in the capture could test the claim. Gainsay says so instead of calling it a pass. |
| **UNCLAIMED** | Risky behaviour from an address that no audited host speaks for. |

The headline number is **trial coverage**: how much of a host's configured posture was actually put to the test by real traffic. The usual 0–100 score is there too, but it comes second.

Every finding teaches you something:
- **why** it matters;
- **how** Gainsay verified it, with the exact registry value or WMI property read, or the packet fields that triggered it;
- a **"reproduce by hand"** one-liner (PowerShell, or a `tshark` display filter);
- **how to fix** it;
- for trial verdicts, the **blast radius**: the peers seen on the wire that depend on the weak behaviour and will break when you fix it (e.g. the old scanner that only speaks SMB1).

## What it is not

- **Not an antivirus or a compromise detector.** It measures whether best practices are in place and in effect, not whether you are hacked.
- **Not an IDS.** Name-resolution and ARP findings are hygiene signals, not attack verdicts.
- **Not a vulnerability scanner or an exploitation tool.**
  - It never modifies the host. Every Windows read goes through a fixed allow-list of read-only commands.
  - It is passive on the network.
  - The optional `scan` only does a rate-limited TCP connect() to private or allow-listed targets after explicit confirmation.
- **Not a cloud service.** No telemetry, no update checks, no online lookups. The end-of-life and Windows-lifecycle lists are local files you can edit.

## Get started in two minutes (Windows)

1. Download `gainsay-0.1.0-windows-x64.zip` and unzip it anywhere. It includes its own Java runtime, so nothing else needs installing. To build it yourself, see [Building](#building).
2. Open **Terminal as administrator**. Gainsay also runs without admin, but then it reads less and cannot capture traffic.
3. Run:

```bash
gainsay\gainsay.exe audit
```

That single command:
- checks privileges;
- starts a 60-second passive capture, using Npcap if installed, otherwise Windows' built-in Packet Monitor (`pktmon`);
- audits the machine's settings (read-only);
- puts those settings on trial against the traffic;
- compares the result with your previous run;
- prints **"Fix these first"** in the terminal and opens the HTML report.

Each run is kept in `gainsay-runs/<date_time>/`. Raw capture files are deleted after analysis unless you pass `--keep-capture`.

```
Fix these first
 1. INVESTIGATE Find out why "SMB1 server disabled" is not in effect  (WS-HARDENED, clears 2)
      why this may happen: gainsay explain TRIAL-SMB1-SRV
      may break: 10.0.0.42
 2. FIX         Remote Desktop is on WITHOUT Network Level Authentication  (WS-LEGACY, clears 4)
      fix command: gainsay explain HOST-NETCFG-005
```

The plan is ranked by how much risk each action removes. An action gets credit for the host finding, the trial verdict and the network findings it would clear. Each fix comes with a **copy-paste PowerShell command**, which **Gainsay never runs**: review it and run it yourself. Each fix also lists the machines seen on the network that **may break** when you apply it.

Useful extras:

| Command | What it does |
|---|---|
| `gainsay explain HOST-CRED-004` | Explains one check: why it matters, how it's verified, the fix command |
| `gainsay init` | Writes a `gainsay.json` to name your network segments, internal DNS servers and thresholds |
| `gainsay audit --exercise` | During the capture, looks up one random non-existent name so the LLMNR/NetBIOS claims can be tested |
| `gainsay audit --seconds 300` | Captures for longer to test more claims; or set `captureSeconds` in `gainsay.json` |
| `gainsay audit --capture none` | Host audit only |

### Run it regularly

Settings drift: updates, installers and new Group Policy change them quietly. `gainsay schedule` prints the PowerShell commands that register a weekly Windows scheduled task running `gainsay audit`. **Gainsay never creates the task itself**: review the commands and run them in an elevated PowerShell.

```bash
gainsay schedule --weekly monday --at 09:00 --folder C:\GainsayRuns
```

- The task runs as SYSTEM, so every read and the `pktmon` capture are available.
- Each run lands in `<folder>\gainsay-runs\<date_time>\` and is compared with the previous one. `--keep-runs` (default 26) deletes the oldest runs Gainsay made, and nothing else.
- Task Scheduler's *Last Run Result* shows `0x1` when a FAIL of `--fail-on` severity (default HIGH) or above was found. Point your monitoring at that, or at the `report.json` of the newest run.
- Use `--daily` instead of `--weekly`, and run `gainsay init` in the folder first to name your segments and DNS servers.

Typical rhythms:
- **At home:** monthly, and after a Windows feature update.
- **Admins:** weekly on key machines, plus a run straight after every Group Policy change to confirm it actually took effect on the wire.
- **Assessments:** one run at the start and one after the fixes; the comparison is the evidence of what changed.

### Try it without Windows or admin

The `samples/` folder holds two recorded machines and a synthetic capture:

```bash
gainsay audit --fixture samples/fixtures/host-hardened.json --pcap samples/demo.pcap
```

The hardened machine scores 100/100 as a configuration audit, yet the trial finds two contradictions:
- it accepted **SMB1** from `10.0.0.42`, which is also named as the machine that would break;
- it negotiated **TLS 1.0** on port 443, and the report explains that the service may use its own TLS stack rather than SCHANNEL.

### Live capture options

| Backend | Needs | Notes |
|---|---|---|
| `pktmon` (Windows 10 21H1+, 11, Server 2022+) | an elevated prompt | Built in. Gainsay starts a capture on the network adapters, stops it, and converts it to pcapng. It never adds filters and never touches a capture someone else is already running. |
| `npcap` | [Npcap](https://npcap.com) (Windows) or libpcap (Linux/macOS), plus admin/root | Captures on the interface that carries this machine's address (or `--iface`). |
| `--pcap FILE` | nothing | Analyses an existing capture, e.g. from a SPAN port or `tcpdump -w`. |

## Building

Requirements: JDK 21+ and Maven 3.9+.

Build and run the tests:

```bash
mvn -q package
```

Run from the jar:

```bash
java -jar target/gainsay-0.1.0.jar audit
```

Build the standalone Windows app (`dist\gainsay\gainsay.exe` plus a zip, about 30 MB, with its own runtime). Add `-Installer` to also build an MSI; that needs the WiX Toolset.

```bash
powershell -ExecutionPolicy Bypass -File packaging\package.ps1
```

On Linux/macOS, `packaging/package.sh` builds `dist/gainsay/` and a tarball. `PKG_TYPE=deb|rpm|pkg` also builds a native package. jpackage builds only for the OS it runs on. Both scripts write SHA-256 checksums next to the packages.

### Releases

- `.github/workflows/ci.yml` builds and tests on Windows and Linux for every push and pull request.
- `.github/workflows/release.yml` runs when a tag like `v0.2.0` is pushed. It checks the tag matches the `pom.xml` version, builds the Windows zip and Linux tarball, and creates a **draft** GitHub release with `SHA256SUMS.txt` and the matching [CHANGELOG](CHANGELOG.md) section as notes.
- Code signing is optional. Set the `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` secrets and the `SIGNING_ENDPOINT`, `SIGNING_ACCOUNT` and `SIGNING_PROFILE` variables for Azure Trusted Signing (see `packaging/sign-windows.ps1`). Any other signer works through `GAINSAY_SIGN_SCRIPT`.

## All commands

```
gainsay audit   [--seconds N] [--capture auto|pktmon|npcap|none] [--iface NAME] [--pcap FILE] [--fixture FILE]
                [--exercise] [--config FILE] [--out DIR] [--no-open] [--no-baseline] [--keep-capture] [--fail-on SEV]
                [--keep-runs N]
gainsay explain ID
gainsay init    [--file gainsay.json] [--force]
gainsay schedule [--daily | --weekly DAY] [--at HH:MM] [--folder DIR] [--name NAME] [--seconds N]
                [--fail-on SEV] [--keep-runs N] [--exe PATH]
gainsay host    [--fixture FILE] [--save-snapshot FILE] [--out DIR] [--format json,md,html] [--fail-on SEV] [--baseline OLD.json]
gainsay net     (--iface NAME | --pcap FILE) [--duration SEC] [--claims-from host.json,...] [--segments FILE]
                [--expected-resolvers IP,...] [--out DIR] ...
gainsay trial   --host host.json[,...] --net net.json[,...] [--out DIR] ...
gainsay scan    --targets CIDR_OR_FILE --i-am-authorized [--rate N] [--ports P,...] [--allowlist FILE] [--claims-from host.json]
gainsay report  --inputs a.json,b.json [--baseline OLD.json] [--out DIR]
gainsay list-checks | list-ifaces | version
```

`audit` is the everyday command. The others are the building blocks, and are useful for scripting and for combining several hosts.

### `gainsay.json`
Created by `gainsay init`. Command-line options always win over the file. The fields are:
- `runsDir`, `keepRuns` (0 = keep every run), `capture`, `captureSeconds`, `iface`;
- `segments` (name → CIDRs);
- `expectedResolvers` (your internal DNS servers);
- `maxSignatureAgeDays`, `maxHotfixAgeDays`;
- `eolList`, `buildsList` (your own lists);
- `openReport`, `exercise`.

### `host`
- On Windows, run it from an **elevated** prompt to read everything. Without elevation, BitLocker, TPM and audit-policy reads come back UNKNOWN (never guessed), and coverage drops accordingly.
- `--save-snapshot snap.json` stores what was read as a replayable fixture. It contains no secrets.
- On Linux/macOS, use `--fixture`.

### `net`
- Analyses a capture file, or captures live for `--duration` seconds.
- `--segments` lets you name your networks. Each line is `name CIDR [CIDR...]`, for example `office 10.0.0.0/24`. Otherwise every private /24 is its own segment.

### `trial` and `report`
- Both merge saved reports.
- When both testimony (host reports) and evidence (net or scan reports) are present, the claims are put on trial.

### `scan`
- Optional and active. It refuses to run unless all of these hold:
  - `--i-am-authorized` is given;
  - every target is an IP or CIDR literal (no host names);
  - every target is private, link-local, loopback, or listed in `allowed_targets.txt`;
  - the run covers ≤ 1024 addresses and ≤ 64 ports;
  - the rate is ≤ 50 connections/s (default 5).
- It never sends payloads or reads banners.

### Exit codes
0 ok, 1 findings at/above `--fail-on`, 2 usage error or guardrail refusal, 3 runtime error.

## Reading the report

`report.json` (schema `gainsay.report/1`), `report.md` and `report.html` contain the same content, in this order:
1. **Testimony vs evidence**: trial coverage, the claim × verdict matrix with blast radius, and an explanation of every contradiction.
2. **Fix these first**: the ranked action plan with copy-paste commands, restart notes and "may break" warnings.
3. **Executive summary.**
4. **Score and coverage**: the measured score, the worst case if every unknown failed, per-category sub-scores and the formula ([docs/SCORING.md](docs/SCORING.md)).
5. **Top risks.**
6. **Findings by category**: why it matters, how it was verified, proof with a reproduce-by-hand line, how to fix (with the command).
7. **Segment boundary crossings.**
8. **Compared with the previous run**: automatic with `audit`, or `--baseline` with the other commands.
9. **Appendix**: checks that could not run, and why.

## Placing the monitor

Module B watches traffic that passes through, or is mirrored to, the machine running Gainsay. **Gainsay never reconfigures the network stack.** The commands below are for you to run on a machine and network you control. Undo them afterwards.

**Option 1: Linux bridge (inline, two NICs).** The machine sits between two segments and forwards everything.

```bash
sudo ip link add br0 type bridge
```

```bash
sudo ip link set eth0 master br0 && sudo ip link set eth1 master br0
```

```bash
sudo ip link set br0 up && sudo ip link set eth0 up && sudo ip link set eth1 up
```

Then capture on the bridge:

```bash
sudo java -jar target/gainsay-0.1.0.jar net --iface br0 --duration 600 --out out/live
```

- Capture on `br0` to see both directions.
- Use `--segments` so findings name the two sides.
- Prefer a maintenance window: an inline bridge is a single point of failure.

**Option 2: Windows Network Bridge.** In *Network Connections*, select both adapters, right-click and choose *Bridge Connections*. Install Npcap. Then:
1. Run `gainsay list-ifaces` from an elevated prompt.
2. Capture on the bridge adapter.
3. Remove the bridge when you are done.

**Option 3: Switch port mirroring (SPAN/TAP), recommended.**
- Configure the switch to mirror the uplink or VLAN of interest to the port where the monitoring NIC is connected.
- Capture on that NIC. The second NIC can stay on the management network.
- This is passive, out of band and cannot break traffic.

**Option 4: Offline.** Capture with `tcpdump -w`, `dumpcap` or Wireshark anywhere, then run `gainsay net --pcap`.

To make claims testable, generate the traffic that exercises them while capturing:
- browse a file share from and to the audited host (SMB dialects, signing, NTLM);
- connect to its HTTPS/RDP/WinRM ports (TLS versions, NLA, exposure);
- look up a non-existent name (DNS failure and LLMNR/NBT-NS fallback).

## Safety and legal notice

- Use Gainsay only on systems and networks you own or are explicitly authorised to assess.
- Capturing other people's traffic may be regulated where you are, even passively.
- The `scan` command is active. You are responsible for having permission for every target.
- Gainsay stores only metadata: addresses, ports, protocol versions, counts, timestamps and redacted proofs. It never stores payload bodies, passwords, cookies or tokens.
- Treat reports as sensitive anyway: they describe weaknesses.

## Limitations

- **Live host checks are Windows-only.** Other operating systems can audit recorded snapshots.
- **No IP-fragment or full TCP reassembly.** Handshakes are read from the first 16 KiB of each direction, in order; a gap stops collection. HTTP is analysed for the first request and response only, and DNS over TCP is not parsed.
- **TLS 1.3 certificates are encrypted**, so certificate checks only cover TLS ≤ 1.2. Nothing is ever decrypted.
- **Matching testimony to evidence relies on addresses.** DHCP churn between the snapshot and the capture, NAT, or VMs sharing an address can cause false verdicts. Gainsay records how each match was made and warns when snapshot and capture are more than 24 h apart.
- **Some checks rely on assumptions or local data:**
  - Security Center's `productState` bitfield is undocumented; the decoding used is the widely used community interpretation.
  - `net accounts` and `auditpol` output is parsed in English, with positional and GUID fallbacks. Unparseable output becomes UNKNOWN.
  - The end-of-life and Windows lifecycle lists are local and need occasional updates (`--eol-list`, `--builds-list`).
- **pcap4j (1.8.2, 2019) is old.** It is isolated behind one class so it can be swapped.

## Documentation

- [docs/CHECKS.md](docs/CHECKS.md): every check (what / why / how verified / how to fix) and every trial claim.
- [docs/SCORING.md](docs/SCORING.md): trial coverage, surprise ranking, posture score, exit codes.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): packages, data flow, design decisions, how to add a check.
- [docs/PLAN.md](docs/PLAN.md): landscape research, differentiation, plan.

- [CONTRIBUTING.md](CONTRIBUTING.md): the rules every change keeps, and how to add a check.
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately, and how to verify a download.
- [CHANGELOG.md](CHANGELOG.md).

## License

Apache License 2.0; see [LICENSE](LICENSE). Third-party components are listed in [NOTICE](NOTICE).

To regenerate `docs/CHECKS.md` and `samples/demo.pcap` after changing check metadata, run (classpath separator `;` on Windows, `:` elsewhere):

```bash
mvn -q test-compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt && java -cp "target/classes:target/test-classes:$(cat target/cp.txt)" dev.gainsay.docs.DocsGenerator
```
