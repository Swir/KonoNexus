# KonoNexus

**KonoNexus** is an experimental, serverless global mesh networking project.

The protocol is called **KonoNexus Protocol (KNP)**. Its goal is to let applications such as Konofix communicate without a central application server, VPS, hosted API, or single relay provider. Every running KonoNexus instance can act as an endpoint and, in later protocol phases, as a privacy-preserving relay for other peers.

> Status: **0.1.0-alpha.3 — secure-session foundation**. The implementation now provides persistent cryptographic node identities, signed UDP discovery, bounded replay protection, stateless endpoint cookies, authenticated ephemeral X25519 session establishment, HKDF-SHA256 directional key derivation, and ChaCha20-Poly1305 encrypted session frames. NAT traversal, DHT routing, multi-hop relay, key rotation, and store-and-forward are intentionally not claimed as complete yet.

## Principles

- **No central authority in the data path.**
- **Every node is equal.** There is no permanent "master" node.
- **Self-healing topology.** Future routing will choose alternate peers when a path disappears.
- **End-to-end privacy.** Relay nodes must never need plaintext application data.
- **Cryptographic identity.** A node identity is derived from its public key, not from an IP address.
- **Portable core.** The networking core is written in Rust for Windows/Linux first, with Android integration planned.
- **No custom cryptography.** KNP composes established cryptographic primitives rather than inventing new ciphers.

## What works now

```text
Node A                              Node B
  |                                  |
  | signed HELLO                     |
  |--------------------------------->|
  | signed COOKIE_CHALLENGE          |
  |<---------------------------------|
  | signed HELLO + cookie            |
  |--------------------------------->|
  | signed HELLO_ACK                 |
  |<---------------------------------|
  | signed SESSION_INIT (X25519 eph) |
  |--------------------------------->|
  | signed SESSION_ACK  (X25519 eph) |
  |<---------------------------------|
  |   ChaCha20-Poly1305 secure data  |
  |<================================>|
```

The X25519 ephemeral keys are carried inside Ed25519-signed KNP envelopes, so the session transcript is tied to authenticated node identities. HKDF-SHA256 derives separate keys for each direction. Session frames use sequence-bound AEAD and reject duplicate/older sequence numbers in the current alpha implementation.

## Quick start

Install a current Rust toolchain, then:

```bash
cargo run -- --bind 0.0.0.0:47000
```

Start a second node and point it at the first:

```bash
cargo run -- --bind 0.0.0.0:47001 --peer 127.0.0.1:47000
```

For two computers on different networks, pass the reachable peer endpoint for now. Automatic NAT traversal and decentralized peer discovery are milestones for upcoming KNP phases.

Useful options:

```text
--bind <IP:PORT>        Local UDP endpoint
--peer <IP:PORT>        Seed peer; may be repeated
--identity <PATH>       Identity key path
--hello-interval <SEC>  Discovery refresh interval
```

Set `RUST_LOG=debug` for verbose diagnostics.

## Roadmap

- [x] KNP wire envelope and protocol versioning
- [x] Persistent Ed25519 node identity
- [x] Signed HELLO / HELLO_ACK
- [x] Peer table and health timestamps
- [x] Signed PING / PONG fallback
- [x] CI: formatting, Clippy, tests
- [x] Replay window / bounded replay protection
- [x] Stateless anti-amplification endpoint cookies
- [x] Bounded active peer table
- [x] Authenticated X25519 session handshake
- [x] HKDF-SHA256 directional session keys
- [x] ChaCha20-Poly1305 encrypted secure frames
- [ ] Session handshake retransmission and key rotation
- [ ] Sliding anti-replay window for reordered encrypted UDP frames
- [ ] Automatic NAT type detection
- [ ] UDP hole punching
- [ ] LAN discovery without configuration
- [ ] Distributed peer discovery / DHT
- [ ] Multi-hop onion-style relay envelopes
- [ ] Path scoring and self-healing routing
- [x] KonoMind advisory scaffold (deterministic baseline + metrics interface)
- [ ] KonoMind local learning model trained from NAT/relay outcomes
- [ ] Distributed offline mailbox / store-and-forward
- [ ] Konofix SDK and Windows integration
- [ ] Android transport integration

See [docs/KNP-SPEC.md](docs/KNP-SPEC.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## KonoMind

KonoMind is an optional adaptive routing layer. Its current scaffold can collect connection observations and score candidate paths from latency, packet loss, stability, and relay load. It is intentionally advisory only: KNP Core remains authoritative for cryptography, authentication, replay checks, and packet validation. A learned model will only be introduced after NAT traversal and cooperative relay produce enough real test data.

## Why a seed is still needed

A completely new node cannot discover an existing global mesh from nothing: it needs at least one piece of information that reaches an existing peer. KonoNexus will support multiple decentralized bootstrapping methods so no single server is required: cached peers, invite links/QR codes, LAN discovery, and eventually peer lists learned from the DHT. Once connected, discovery information is exchanged between peers.

## Security note

KonoNexus is pre-release networking/security software. The secure-session design has automated tests but has not undergone independent cryptographic review. Do not treat an alpha build as production-ready.

## License

MIT
