# Contributing

Thanks for helping. Gainsay is small on purpose, and a few rules keep it trustworthy.

## The rules every change must keep

1. **Defensive and read-only.** Nothing may change the host. New Windows reads go through `WindowsQueries` (the allow-list) and must be read-only commands.
2. **Passive by default.** Only `scan` is active, and its guardrails (`TargetPolicy`, `RateLimiter`) are not to be loosened.
3. **No secrets stored.** Evidence goes through `Redactor`. Prefer not reading a secret at all over masking it.
4. **No network calls to third parties.** No telemetry, update checks or online lookups.
5. **Fix commands are printed, never run.** Registry commands must not use `New-Item -Force` (it deletes existing values); `FixPlannerTest` checks this.
6. **Unknown is never a pass.** If a check cannot read what it needs, it returns UNKNOWN, and a network check with no relevant traffic is NOT_APPLICABLE.

## Getting started

Requirements: JDK 21+ and Maven 3.9+.

```bash
mvn -q package
```

This compiles and runs every test. The tests need no admin rights, no Npcap and no Windows: host checks run against recorded snapshots in `samples/fixtures/`, and network analyzers run against captures built in code (`src/test/java/dev/gainsay/net/synth`).

To try a change end to end:

```bash
java -jar target/gainsay-0.1.0.jar audit --fixture samples/fixtures/host-hardened.json --pcap samples/demo.pcap --no-open
```

## Adding a check

See "Adding a check" in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). In short:

- every check states **why** it matters, **how** it was verified and **how to fix** it;
- add a test with a snapshot or synthetic capture that makes it FAIL, PASS and UNKNOWN (or NOT_APPLICABLE);
- regenerate `docs/CHECKS.md` with `DocsGenerator` (see the README). `DocsUpToDateTest` fails until you do.

## Dependencies

Keep them few. Open an issue before adding one, and explain why the JDK cannot do it. Anything native stays behind `LiveCaptureSource`.

## Pull requests

- One topic per pull request, with tests.
- Describe how you verified it, including on a real machine or capture if the change affects live behaviour.
- Add a line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).
- Security problems go through [SECURITY.md](SECURITY.md), not a public pull request.

By contributing you agree that your contribution is licensed under the Apache License 2.0, as stated in section 5 of the [LICENSE](LICENSE).
