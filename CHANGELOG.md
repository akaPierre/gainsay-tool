# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org); the report schema (`gainsay.report/1`) has its own version and changes only when the JSON shape does.

## Unreleased

- `gainsay schedule` prints the PowerShell commands to run `gainsay audit` regularly as a Windows scheduled task. Gainsay never creates the task itself.
- Project files for publishing: Apache-2.0 LICENSE and NOTICE, SECURITY.md, CONTRIBUTING.md, and GitHub Actions workflows for tests and signed-ready releases with SHA-256 checksums.

## 0.1.0

First version.

- **Trial:** host settings are claims, network observations are evidence, and every claim gets a verdict (CONTRADICTED, CORROBORATED, UNTESTED, UNCLAIMED), with trial coverage, surprise ranking and blast radius.
- **Host:** 46 read-only Windows checks (registry with Group Policy precedence, WMI, cmdlets), replayable snapshots.
- **Network:** passive analysis of `.pcap`/`.pcapng` files or live capture (Npcap/libpcap or Windows `pktmon`), 26 checks covering legacy protocols, SMB, NTLM, TLS, RDP, name resolution, exposure and hygiene.
- **Scan:** optional, guarded TCP connect check for private or allow-listed targets.
- **Reports:** JSON, Markdown and a self-contained HTML (no JavaScript), with a ranked "Fix these first" plan and copy-paste fix commands that Gainsay never runs.
- **`gainsay audit`:** one command for privileges, capture, host audit, trial, comparison with the previous run, and the report.
- `explain`, `init` / `gainsay.json`, and a standalone `gainsay.exe` with its own Java runtime.
