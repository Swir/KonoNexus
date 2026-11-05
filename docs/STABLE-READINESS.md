# Stable release readiness

The 0.1.0-alpha.30 candidate contains startup, persistence and tester recovery
fixes. It remains a prerelease until the existing physical network acceptance
matrix has been completed and reviewed. A passing local suite or build does not
establish that two unrelated NATs can communicate.

## Automated acceptance

CI runs formatting, Clippy with all features, all targets' tests and SDK-only
checks on Windows and Linux with the committed dependency lockfile. The Windows
packaging job runs the test suite before building its static-CRT executables.
The Android workflow separately checks JNI, builds the AAR and runs its emulator
transport tests. Require all applicable checks for the exact candidate commit.

Regression coverage includes concurrent identity initialization, preservation of
invalid existing keys, concurrent routing-cache replacement, invalid timer
configuration, tester command recovery and socket release after shutdown. The
existing runtime suites cover authenticated delivery, receipts, IPv6, relay paths,
backpressure and mesh churn.

## Physical network acceptance still required

| Scenario | Required evidence | Current status |
| --- | --- | --- |
| Same LAN | Reciprocal reports and physical host/run notes | Not supplied for this candidate |
| Two home networks | Reciprocal reports, ISP/router setup | Not supplied |
| Home to mobile | Reciprocal reports, carrier/setup | Not supplied |
| Two mobile/CGNAT networks | Reciprocal reports, reachable mesh entry and selected path | Not supplied |
| Public IPv6 | Both reports show direct native IPv6 and public endpoint evidence | Not supplied |
| Direct interruption | Captured disruption, observed recovery and reciprocal reports | Not supplied |
| Restart/reconnect | Persistent NodeIDs, observed reconnection and reciprocal reports | Not supplied |

Use [TESTING.md](TESTING.md) and the packaged `Verify-KonoNexusEvidence.ps1` to
verify the reports, pair them and create the seven-scenario manifest. Preserve
the exact executable build identity, an operator run ID, UTC interval, network
setup and capture hashes. Review the physical evidence even when the verifier
prints `MANUAL_REVIEW_READY=1`.

Two fresh nodes behind unrelated NATs still require an initial mutually reachable
mesh contact. Supply it with `--peer`; do not interpret an unreachable bootstrap
or a local-only run as proof of universal connectivity.

After the exact candidate passes the automated and physical checks, record the
evidence and supported network limitations, choose the stable version, and build
and validate that exact release commit before publishing it as stable.
