# KonoNexus Alpha.28 External Test Procedure

Status: controlled testing candidate.

This procedure is for real Windows/Linux machines. Do not enable the SDK's local loopback test mode outside automated localhost tests.

## 1. Build

Install stable Rust, clone the repository, then build the probe:

```powershell
cargo build --release --bin kononexus_probe
```

Windows binary:

```text
target\release\kononexus_probe.exe
```

Linux binary:

```text
target/release/kononexus_probe
```

Set diagnostics when needed:

```powershell
$env:RUST_LOG="kononexus=debug"
```

## 2. First test: two PCs on the same LAN

On PC A:

```powershell
.\target\release\kononexus_probe.exe --bind 0.0.0.0:47000 --identity .\state-a.key --run-seconds 300
```

Record the printed `NODE_ID`. Determine PC A's LAN IP, for example `192.168.1.20`.

On PC B:

```powershell
.\target\release\kononexus_probe.exe --bind 0.0.0.0:47000 --peer 192.168.1.20:47000 --identity .\state-b.key --run-seconds 300
```

Record PC B's `NODE_ID`.

Restart PC B (or run another probe instance using the same identity) and send to A:

```powershell
.\target\release\kononexus_probe.exe --bind 0.0.0.0:47000 --peer 192.168.1.20:47000 --identity .\state-b.key --target <A_NODE_ID> --message "hello-from-b" --run-seconds 120
```

Expected:

- A prints `RECV ... text=hello-from-b`
- B prints `DELIVERED ...`
- no `FAILED` event

## 3. Three-node mesh test

Use A as an already known peer. B and C both start with A as their seed.

A:

```powershell
.\kononexus_probe.exe --bind 0.0.0.0:47000 --identity .\a.key --run-seconds 600
```

B:

```powershell
.\kononexus_probe.exe --bind 0.0.0.0:47001 --peer <A_IP>:47000 --identity .\b.key --run-seconds 600
```

C:

```powershell
.\kononexus_probe.exe --bind 0.0.0.0:47002 --peer <A_IP>:47000 --identity .\c.key --run-seconds 600
```

After all three have been running long enough to establish encrypted sessions, send B → C by C's NodeID.

Expected:

- B knows only the target NodeID at application-send time
- discovery/rendezvous builds the path
- C receives the payload
- B receives `DELIVERED`

## 4. Windows GUI WAN test

Use `KonoNexus-Network-Tester.exe` for the normal two-PC test:

1. Start the tester on PC A and click **Kopiuj invite**.
2. Transfer the single `KNX1...` code to PC B.
3. On PC B click **Wklej invite**, then **Połącz** and **START TESTU WAN**.
4. The GUI reports `DIRECT`, `UDP HOLE PUNCH`, or `RELAY`, authenticated delivery RTT, delivery loss, NAT/endpoint evidence, NodeIDs, and a technical log.

The invite is signed with the node's Ed25519 identity and contains no private key. It expires after 24 hours. A modified or malformed invite is rejected before dialing.

The result is honest by design: two fresh nodes behind unrelated NATs cannot universally discover each other without a mutually reachable peer/coordinator. If the invite contains only a private endpoint and no reachable mesh bootstrap exists, the GUI reports failure or inconclusive NAT evidence rather than a false `CONNECTED` status.

## 5. Signed result evidence

After every completed GUI test, the tester atomically writes a signed JSON report under:

```text
%LOCALAPPDATA%\KonoNexus\NetworkTester\reports
```

The report contains the exact local and target NodeIDs, selected path, endpoint and NAT evidence, sample counters, RTT, packet loss and two separate verdicts. Official GitHub-built testers also bind the signed `tester_version` to the complete source commit as `<version>+git.<40-character SHA>`:

- `delivery_passed` means at least one authenticated end-to-end delivery was acknowledged;
- `eligible_for_wan_matrix` additionally requires a selected target path and observed external endpoint evidence.

Verify a copied report without trusting the machine or text editor that supplied it. For release qualification, require the complete build identity printed by the verified package:

```powershell
$EXPECTED_BUILD = "0.1.0-alpha.28+git.<40-character-qualified-commit>"
.\kononexus_probe.exe --verify-report .\KonoNexus-WAN-....json --expected-tester-build $EXPECTED_BUILD
```

A valid file prints `REPORT_VALID=1`. Any changed signed field, public key, NodeID or signature causes a non-zero exit. Matrix eligibility is evidence for one endpoint only; closing a matrix row still requires reports from both physical hosts plus the tested network description. A valid local-only report remains ineligible and cannot close the WAN/NAT roadmap gate.

After copying both endpoint reports to one machine, create a reciprocal matrix-row bundle:

```powershell
.\kononexus_probe.exe --pair-report .\pc-a.json .\pc-b.json --scenario home_nat_pair --network-label "ISP A / ISP B" --pair-output .\home-nat-pair.json
.\kononexus_probe.exe --verify-pair .\home-nat-pair.json --expected-tester-build $EXPECTED_BUILD
```

The supported scenarios are `same_lan`, `home_nat_pair`, `home_to_mobile`, `dual_mobile_cgnat`, `public_ipv6`, `direct_interruption`, and `restart_reconnect`. Pair creation rejects reports unless their signed local/target NodeIDs are reciprocal. `MATRIX_ROW_ELIGIBLE=1` additionally requires both endpoint reports to be WAN-eligible and no more than one hour apart. The bundle records canonical SHA-256 digests for both signed reports; its scenario and network label are operator-supplied metadata, not endpoint-signed claims. One eligible bundle documents one physical run only and never closes the full matrix by itself.

Collect available row bundles into a deterministic manifest. Repeat `--matrix-pair` for each file; partial manifests are valid and print what is still missing:

```powershell
.\kononexus_probe.exe --matrix-pair .\same-lan.json --matrix-pair .\home-nat-pair.json --matrix-output .\wan-matrix.json
.\kononexus_probe.exe --verify-matrix .\wan-matrix.json --expected-tester-build $EXPECTED_BUILD
```

The pair verifier rejects reports produced by different tester builds. The manifest rejects mixed tester builds, duplicate scenarios, modified bundles and any endpoint report reused under another scenario. The optional `--expected-tester-build` guard additionally fails verification unless the signed evidence matches the exact qualified artifact build; use it for final-gate and release review. The probe prints `TESTER_BUILD` for every verified report, pair and non-empty matrix so the evidence can be matched to the qualified GitHub commit. It also prints `MISSING_SCENARIOS`, `INELIGIBLE_SCENARIOS` and `MANUAL_REVIEW_READY`. Readiness becomes `1` only when all seven scenarios contain separate eligible report pairs. This means the set is ready for human inspection of the physical hosts, carriers, router/NAT setup and logs; it is not an automatic claim that the roadmap gate is closed.

## 6. Different-network diagnostic probe test

For the first WAN test, at least one initial seed endpoint must actually be reachable from the other machine.

Valid ways to achieve this for testing:

- public IPv6 with host firewall allowing UDP 47000,
- temporary UDP port forwarding on the seed router,
- another already reachable KonoNexus peer.

KonoNexus does not require that peer to remain a permanent central server; it is only the entry contact into the existing mesh.

Run the seed node on network A and the second node on a different network, such as a mobile hotspot.

Second node:

```powershell
.\kononexus_probe.exe --bind 0.0.0.0:47000 --peer <REACHABLE_SEED_IP>:47000 --identity .\remote.key --target <TARGET_NODE_ID> --message "wan-test" --run-seconds 180
```

Record whether the logs show:

- direct encrypted session,
- UDP punch attempt / success,
- relay fallback,
- delivery receipt or failure.

## 7. NAT/CGNAT matrix

Run separate tests for:

1. same LAN,
2. two normal home NATs,
3. home network ↔ mobile hotspot,
4. two mobile/CGNAT-style networks,
5. public IPv6 where available,
6. direct path interrupted after connection to observe relay fallback,
7. restart/reconnect using persisted routing hints.

For each test save logs from both endpoints.

## 8. Firewall

Allow inbound and outbound UDP for the probe's selected port (default 47000).

Windows Defender Firewall may prompt on first launch. Allow the app on the network profile being tested.

## 9. What counts as a pass

A message test passes only when:

- receiver prints the expected `RECV`,
- sender prints matching `DELIVERED`,
- NodeIDs match the intended endpoints,
- there is no unexpected `FAILED`,
- both runtimes remain alive.

A timeout or `FAILED` event is evidence to diagnose, not something to hide by increasing timeouts.

## 10. Current testing limitation

The alpha.23 route tests deterministically cover cooldown-based path changes and recovery, KonoMind-scored relay choice with hysteresis, route/peer health isolation and bounds, and RelayApp ACK route matching. The runtime samples RTT only from an authenticated delivery ACK arriving on the same direct endpoint or established relay circuit as the latest tracked fragment attempt. These tests do not provide WAN or NAT evidence.

Automated CI now passes a real three-node localhost runtime harness. That proves the runtime/API/discovery delivery path works under controlled conditions.

CI also runs a 32-node `KonoNode` runtime test over loopback UDP sockets: 30 leaves bootstrap to two hubs, while the hubs learn their leaves from signed HELLO/cookie exchanges. Each node establishes encrypted sessions, observes peer endpoints and exchanges signed endpoint attestations. The harness checks that each node has accepted attestations from at least two distinct observers for its own endpoint, and that valid signed DHT stores and replication traverse the runtime handlers. It selects non-neighbor pairs without a cached exact record, delivers before churn, stops every third node (including one hub), waits for HELLO-based expiry, checks that surviving leaves retain the one surviving hub and that hub sees all 20 surviving leaves, then delivers between a second pair. Both lookups correlate an accepted FIND request with an accepted, attested exact NODES response at the origin.

The harness registers only its exact ephemeral loopback socket addresses under a cfg(test)-only DHT policy, and it asserts that the public production endpoint check still rejects loopback. This is large-mesh runtime convergence and churn evidence for one local topology. It does not exercise WAN/NAT/CGNAT behavior, real packet loss, independent networks, or Sybil-resistant observer diversity. The 64-node algorithm simulator remains supplemental evidence and is not used to close the runtime validation item.

CI also exercises the bounded exact-candidate planner: deduplication and the three-endpoint cap, exact supplied-port preservation, stagger/TTL exhaustion, cross-NodeID rejection, global target-state bounds, cancellation after encrypted-session confirmation, and rendezvous-round exhaustion before relay eligibility. These checks prove deterministic logic and admission invariants; they do not prove that any candidate traverses a real NAT or CGNAT.

The exact-candidate planner now places supplied native IPv6 endpoints before IPv4 candidates before deduplication and the three-endpoint cap. Explicit connect hints and independently attested DHT endpoints use the same ordering, with IPv4-mapped IPv6 ranked as IPv4. When mixed-family input exceeds the initial three-candidate cap, one slot is reserved for an exact IPv4 fallback. Explicit hints preserve supplied endpoints and ports; unusable addresses are rejected, including IPv6 link-local hints without an interface scope. DHT candidates must pass record validation and exact endpoint attestation before ordering. This is ordering groundwork only: the runtime still has one bound UDP socket and publishes one observed endpoint, so these checks do not establish dual-stack availability or close the public IPv6 direct-path validation item.

It does **not** prove success through every real NAT, CGNAT, carrier firewall, or router. The external tests above are the next required validation stage before calling the networking foundation stable.
