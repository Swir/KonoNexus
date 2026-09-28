# KonoNexus

**KonoNexus** is an experimental, serverless global mesh networking project.

The protocol is called **KonoNexus Protocol (KNP)**. Its goal is to let applications such as Konofix communicate without a central application server, VPS, hosted API, or single relay provider. Every running KonoNexus instance can act as an endpoint and, in later protocol phases, as a privacy-preserving relay for other peers.

> Status: **0.1.0-alpha.7 — signed DHT discovery foundation**. KNP now exchanges short-lived Ed25519-signed peer records over encrypted sessions, keeps a bounded DHT-style record table, answers bounded nearest-record queries, and can use an exact signed record for a requested NodeID to begin normal HELLO/cookie/session establishment. Iterative multi-hop DHT walking, persistent routing buckets, cooperative relay, and broad real-world NAT validation are still not claimed complete.

## Principles

- **No central authority in the data path.**
- **Every node is equal.** There is no permanent "master" node.
- **Self-healing topology.** Future routing will choose alternate peers when a path disappears.
- **End-to-end privacy.** Relay nodes must never need plaintext application data.
- **Cryptographic identity.** A node identity is derived from its public key, not from an IP address.
- **Portable core.** The networking core is written in Rust for Windows/Linux first, with Android integration planned.
- **No custom cryptography.** KNP composes established cryptographic primitives rather than inventing new ciphers.

## What works now

Two admitted peers can establish an authenticated X25519/HKDF/ChaCha20-Poly1305 session. Each `HELLO_ACK` also contributes an independent observation of the local node's externally visible UDP endpoint.

With at least two observers, KNP can currently distinguish whether those observations look:

- stable,
- stable-address but port-varying,
- address-varying.

This is **mapping-behavior evidence**, not a claim to fully identify every NAT/filtering type.

### Experimental decentralized rendezvous

A normal KonoNexus node that already has encrypted sessions with peers A and B can temporarily coordinate a direct-path attempt:

```text
A ===== encrypted ===== C ===== encrypted ===== B
           request      |       offers
                        |
A -------- signed PUNCH_PROBE / ACK -------- B
```

C is not a fixed service. It is just another running KonoNexus peer and does not become a permanent dependency after a direct A↔B path is established.

For controlled tests, A can still name a coordinator explicitly:

```bash
cargo run -- \
  --peer COORDINATOR_IP:47000 \
  --rendezvous COORDINATOR_IP:47000=TARGET_KNP_NODE_ID
```

Automatic mode only needs the target NodeID. It now runs both bounded rendezvous selection and encrypted DHT lookup:

```bash
cargo run -- --peer KNOWN_PEER:47000 --connect-node TARGET_KNP_NODE_ID
```

KNP then tries at most three currently encrypted peers per round as coordinators, avoids repeating them in the same round, and backs off before another round.

Both A and B must already have an encrypted KNP session with that coordinator. The coordinator sends each side the UDP source endpoint it currently observes for the other side. Each side waits briefly, then emits a locally bounded seven-probe backoff burst over roughly 2.7 seconds while the signed punch authorization remains valid for five seconds. A successful `PUNCH_PROBE/PUNCH_ACK` stops the schedule, establishes the authenticated direct endpoint, and starts a fresh encrypted KNP session over it.

This is an experimental primitive. NATs that create destination-specific mappings can still defeat this strategy; cooperative relay is the later fallback.

## Roadmap

- [x] KNP wire envelope and protocol versioning
- [x] Persistent Ed25519 node identity
- [x] Signed discovery and bounded replay protection
- [x] Stateless anti-amplification endpoint cookies
- [x] Authenticated X25519 session handshake
- [x] HKDF-SHA256 directional session keys
- [x] ChaCha20-Poly1305 encrypted secure frames
- [x] Peer-reported external UDP endpoint observations
- [x] Bounded NAT mapping-behavior profile
- [x] Experimental decentralized rendezvous messages
- [x] Signed UDP punch probe/ack primitive
- [x] Multi-attempt timed hole-punch burst/state machine
- [x] Consent-based endpoint-independent filtering evidence test
- [ ] Broader filtering-behavior matrix and negative-result interpretation
- [ ] Multi-candidate/path prioritization without unsafe port spraying
- [x] Bounded automatic selection of encrypted rendezvous peers
- [ ] IPv6 direct-path preference
- [x] Signed bounded DHT peer records and encrypted exact lookup
- [ ] Iterative multi-hop DHT routing buckets and global convergence
- [ ] Cooperative multi-hop relay fallback
- [ ] Path scoring and self-healing routing
- [x] KonoMind advisory scaffold
- [ ] KonoMind local learning from real NAT/relay outcomes
- [ ] Session key rotation and sliding encrypted anti-replay window
- [ ] KonoNexus Network Tester GUI
- [ ] Konofix SDK and Windows integration
- [ ] Android transport integration

See [docs/KNP-SPEC.md](docs/KNP-SPEC.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## KonoMind

KonoMind remains advisory-only. It cannot bypass KNP cryptographic or admission rules. Once real NAT and relay measurements exist, it can use those observations to rank connection strategies.

## Why a seed is still needed

A completely new node cannot discover an existing global mesh from nothing. It needs at least one reachable peer address, cached peer, invite, LAN discovery result, or later a DHT-derived record. No permanent central bootstrap service is required by the protocol.

## Security note

KonoNexus is pre-release networking/security software. Its security and NAT traversal designs have automated tests but have not undergone independent review. Do not treat an alpha build as production-ready.

## License

MIT


### Consent-based filtering evidence

A controlled positive filtering-evidence test can be requested through a coordinator:

```bash
cargo run -- --peer COORDINATOR_IP:47000 --filter-test COORDINATOR_IP:47000
```

The coordinator proposes an independent helper and the exact endpoint it already observes for the tested node. The tested node signs a short-lived Ed25519 authorization binding its NodeID/public key, that endpoint, the helper NodeID, and a random token. Only then may the helper send one signed direct probe. Receiving it is positive evidence that an independent endpoint can reach the mapping. Failure to receive it remains **inconclusive**, not proof of restrictive filtering.


### Signed DHT discovery foundation

Each node may publish a short-lived `PeerRecord` containing its NodeID, Ed25519 public key, a small set of public UDP endpoints, issue/expiry times, and a signature. Records are accepted only when the NodeID matches the public key, the signature verifies, the TTL is bounded, and every endpoint passes publishability checks.

DHT control messages travel inside the existing encrypted KNP session:

- `DHT_STORE` — share a signed peer record,
- `DHT_FIND` — ask for a target NodeID,
- `DHT_NODES` — return the exact record when known plus a bounded nearest-record set.

The local table is bounded to 4,096 records and responses to at most 8 records. Records expire automatically. KNP may cache nearest records, but it **does not automatically dial arbitrary nearest nodes**. A new network connection is attempted only from an exact valid record for a NodeID that the local user/application is already trying to reach.

This is the DHT foundation, not yet a complete Kademlia implementation. Multi-hop iterative lookups, persistent k-buckets, endpoint attestations, and convergence testing across a large mesh remain future work.
