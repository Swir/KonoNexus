# KonoNexus Alpha.19 External Test Procedure

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

## 5. Different-network diagnostic probe test

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

## 6. NAT/CGNAT matrix

Run separate tests for:

1. same LAN,
2. two normal home NATs,
3. home network ↔ mobile hotspot,
4. two mobile/CGNAT-style networks,
5. public IPv6 where available,
6. direct path interrupted after connection to observe relay fallback,
7. restart/reconnect using persisted routing hints.

For each test save logs from both endpoints.

## 7. Firewall

Allow inbound and outbound UDP for the probe's selected port (default 47000).

Windows Defender Firewall may prompt on first launch. Allow the app on the network profile being tested.

## 8. What counts as a pass

A message test passes only when:

- receiver prints the expected `RECV`,
- sender prints matching `DELIVERED`,
- NodeIDs match the intended endpoints,
- there is no unexpected `FAILED`,
- both runtimes remain alive.

A timeout or `FAILED` event is evidence to diagnose, not something to hide by increasing timeouts.

## 9. Current testing limitation

Automated CI now passes a real three-node localhost runtime harness. That proves the runtime/API/discovery delivery path works under controlled conditions.

It does **not** prove success through every real NAT, CGNAT, carrier firewall, or router. The external tests above are the next required validation stage before calling the networking foundation stable.
