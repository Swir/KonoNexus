# KonoNexus Protocol (KNP) — Draft Specification

Status: **Draft 0.1 / experimental**

## 1. Goals

KNP is a decentralized transport and routing layer intended for applications that need direct or cooperative peer-to-peer communication without a permanent central application server.

The protocol separates four concerns:

1. **Identity** — a node is identified cryptographically.
2. **Discovery** — a node learns how to reach other nodes.
3. **Session security** — peers establish authenticated encrypted sessions.
4. **Routing** — packets may later traverse cooperative relays when direct connectivity is impossible.

The current implementation covers identity, signed discovery, replay filtering, endpoint reachability cookies, authenticated ephemeral session establishment, encrypted ping/pong frames, and basic liveness. Global NAT traversal and mesh routing are not complete.

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
- `body` — typed KNP control message or encrypted frame
- `signature` — Ed25519 signature over every field except `signature`

A receiver MUST verify that the NodeID matches the included public key and MUST verify the signature before processing the message.

After signature verification, a receiver applies a bounded replay window. Packets outside the accepted timestamp skew or packets reusing a remembered nonce for the same NodeID are rejected.

## 4. Discovery and admission control

### HELLO

Announces protocol capabilities to a known endpoint. A HELLO may carry a short-lived endpoint cookie.

### COOKIE_CHALLENGE

A stateless reachability challenge. The cookie is HMAC-SHA256 over protocol context, the observed source endpoint, and a rotating time bucket using a node-local random secret.

The receiver does not admit a new inbound peer until the sender returns a valid cookie in HELLO. Current and immediately previous time buckets are accepted to tolerate boundary races.

### HELLO_ACK

Acknowledges a cookie-validated HELLO and reports the sender endpoint observed by the receiver.

## 5. Peer admission and resource bounds

New inbound peers are admitted only after:

1. envelope version and structure validation,
2. NodeID/public-key binding verification,
3. Ed25519 signature verification,
4. timestamp/nonce replay validation,
5. endpoint cookie validation.

The alpha node bounds both replay tracking and its active peer table. Old peer entries are evicted when limits are reached.

## 6. Authenticated secure session

After peer admission, KNP can establish an encrypted session.

### SESSION_INIT

The initiator creates a fresh X25519 ephemeral secret and sends its public key with a random `handshake_id` inside the Ed25519-signed KNP envelope.

### SESSION_ACK

The responder creates its own fresh X25519 ephemeral secret and sends the corresponding public key with the same `handshake_id`, also inside a signed KNP envelope.

Both peers compute the same X25519 shared secret. All-zero X25519 shared secrets are rejected.

The key schedule hashes an authenticated transcript containing:

- protocol session context,
- initiator NodeID,
- responder NodeID,
- handshake ID,
- initiator X25519 public key,
- responder X25519 public key.

HKDF-SHA256 uses that transcript hash as salt and derives 64 bytes of key material. The first 32 bytes are the initiator-to-responder key and the second 32 bytes are the responder-to-initiator key. This creates separate keys for each direction.

Because the ephemeral public keys and handshake ID are inside Ed25519-signed envelopes, the derived session is authenticated to the long-term KNP identities while the fresh X25519 secrets provide forward-secrecy groundwork. Ephemeral secrets are not persisted.

## 7. Encrypted frames

`ENCRYPTED` carries:

- a transcript-derived `session_id`,
- a per-direction sequence number,
- ChaCha20-Poly1305 ciphertext.

The AEAD nonce is deterministic from a protocol prefix plus the 64-bit per-direction sequence. Separate directional keys prevent nonce/key reuse across opposite directions.

The AEAD additional authenticated data binds the session ID and sequence number. The current alpha receiver accepts only a sequence strictly greater than the highest authenticated sequence already seen. This rejects replay but can reject legitimately reordered UDP datagrams; a bounded sliding receive window is planned.

The current node sends secure PING/PONG payloads once a session is established. Plain signed PING/PONG remains a fallback before session establishment.

## 8. Bootstrap

KNP deliberately does not require a central bootstrap server. A new node can start from one or more of:

- cached peers from previous sessions,
- a peer address provided by the user/application,
- a signed invite,
- LAN discovery,
- future DHT peer records.

At least one reachable contact is required to join an already-running disconnected global mesh. No network protocol can discover an arbitrary remote mesh with zero prior information.

## 9. Planned NAT traversal

Connection establishment will progressively attempt:

1. direct known endpoint,
2. peer-reflexive endpoint discovery,
3. coordinated UDP hole punching,
4. IPv6 direct path where available,
5. cooperative KonoNexus relay through other ordinary nodes.

The relay path is part of the decentralized mesh; no fixed relay service is required by the protocol.

## 10. Planned routing

Future routing records will be keyed by NodeID rather than address. The route selector will score paths using reachability, latency, stability, relay load, and privacy constraints.

Relay nodes MUST NOT need application plaintext.

## 11. Remaining session work

Before a stable protocol, session security still needs:

- handshake retransmission/timeout behavior,
- periodic key rotation,
- bounded sliding anti-replay windows suitable for UDP reordering,
- explicit session teardown,
- fuzzing and independent security review.

## 12. Versioning

Unknown protocol versions are rejected in the alpha implementation. Before a stable specification, capability negotiation will allow compatible extensions without silently changing security semantics.
