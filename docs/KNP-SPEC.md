# KonoNexus Protocol (KNP) — Draft Specification

Status: **Draft 0.1 / experimental**

## 1. Goals

KNP is a decentralized transport and routing layer intended for applications that need direct or cooperative peer-to-peer communication without a permanent central application server.

The protocol separates four concerns:

1. **Identity** — a node is identified cryptographically.
2. **Discovery** — a node learns how to reach other nodes.
3. **Session security** — peers establish authenticated encrypted sessions.
4. **Routing** — packets may later traverse cooperative relays when direct connectivity is impossible.

The current implementation covers the first discovery foundation only.

## 2. Node identity

Each node owns an Ed25519 key pair.

```text
NodeID = "knp1" || HEX(SHA-256(Ed25519PublicKey)[0..20])
```

An IP address is an endpoint hint, never the node identity.

## 3. KNP/1 signed envelope

The alpha wire representation is JSON for inspectability during development. A compact binary representation is planned before stable KNP/1.

Fields:

- `version` — protocol version, currently `1`
- `sender_node_id` — deterministic ID derived from public key
- `sender_public_key` — Ed25519 public key
- `timestamp_unix_ms` — sender wall-clock timestamp
- `nonce` — per-message random value
- `body` — typed KNP control message
- `signature` — Ed25519 signature over every field except `signature`

A receiver MUST verify that the NodeID matches the included public key and MUST verify the signature before accepting the sender into its peer table.

## 4. Control messages

### HELLO

Announces protocol capabilities to a known endpoint.

### HELLO_ACK

Acknowledges a valid HELLO and reports the sender endpoint observed by the receiver. This observation is groundwork for NAT classification and hole punching.

### PING / PONG

Provides a minimal liveness signal.

## 5. Bootstrap

KNP deliberately does not require a central bootstrap server. A new node can start from one or more of:

- cached peers from previous sessions,
- a peer address provided by the user/application,
- a signed invite,
- LAN discovery,
- future DHT peer records.

At least one reachable contact is required to join an already-running disconnected global mesh. No network protocol can discover an arbitrary remote mesh with zero prior information.

## 6. Planned session handshake

The next security layer will add ephemeral key agreement and AEAD-protected frames. Long-term Ed25519 identities authenticate ephemeral session keys. KNP will use established cryptographic implementations rather than a new cipher.

Target properties:

- mutual authentication,
- forward secrecy,
- replay resistance,
- key rotation,
- authenticated transcript,
- no plaintext application payload visible to relay nodes.

## 7. Planned NAT traversal

Connection establishment will progressively attempt:

1. direct known endpoint,
2. peer-reflexive endpoint discovery,
3. coordinated UDP hole punching,
4. IPv6 direct path where available,
5. cooperative KonoNexus relay through other ordinary nodes.

The relay path is part of the decentralized mesh; no fixed relay service is required by the protocol.

## 8. Planned routing

Future routing records will be keyed by NodeID rather than address. The route selector will score paths using reachability, latency, stability, relay load, and privacy constraints.

Relay nodes MUST NOT need application plaintext.

## 9. Versioning

Unknown protocol versions are rejected in the alpha implementation. Before a stable specification, capability negotiation will allow compatible extensions without silently changing security semantics.
