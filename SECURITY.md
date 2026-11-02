# Security policy

Gainsay is a security tool, so a bug in it can mislead the people who rely on it. Please report problems privately first.

## Reporting a vulnerability

- Use GitHub's **private vulnerability reporting** on this repository (Security → Report a vulnerability).
- Do not open a public issue for anything in the list below until a fix is released.
- Include the Gainsay version (`gainsay version`), the command you ran, and, if possible, a capture or host snapshot that reproduces it. Remove anything sensitive first: snapshots contain no secrets, but captures contain full packets.

You should get an acknowledgement within 7 days. Fixes are released as a new version, with credit in the [CHANGELOG](CHANGELOG.md) unless you prefer otherwise.

## What counts as a vulnerability here

Anything that breaks one of Gainsay's promises:

- **It changes the host.** Any code path that writes to the registry, services, firewall, files outside the output folder, or runs a command outside the read-only allow-list (`WindowsQueries`).
- **It runs a fix command.** Fix commands are printed, never executed.
- **It leaks a secret.** A password, hash, cookie, token or Authorization value that reaches a report, log or terminal output unredacted.
- **Malicious input.** A crafted `.pcap`/`.pcapng`, snapshot or report JSON that crashes Gainsay, exhausts memory, hangs it, or injects script or markup into the HTML/Markdown report.
- **It talks to the internet.** Any network connection to a third party (Gainsay makes none), or `scan` reaching a target its guardrails should refuse.
- **A wrong verdict that hides a weakness.** For example a claim marked CORROBORATED or PASS on evidence that does not support it. These are treated as security bugs even when nothing crashes.
- **Unsafe fix commands.** A printed command that does more than its description says, such as deleting registry values.

## Out of scope

- Findings about the machine you audited (that is what the tool is for).
- Weaknesses in Npcap, libpcap, pktmon or Windows itself; report those to their maintainers.
- The `scan` command contacting targets you explicitly allowed.

## Supported versions

Only the latest release receives fixes.

## Verifying a download

Every release lists the SHA-256 of each file in `SHA256SUMS.txt`. On Windows:

```bash
certutil -hashfile gainsay-0.1.0-windows-x64.zip SHA256
```

Compare the result with the line in `SHA256SUMS.txt`. Releases are built by the workflow in `.github/workflows/release.yml`, so the build log shows exactly what went into each file.
