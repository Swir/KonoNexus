# KonoNexus Protocol (KNP) — Draft Specification

Status: **Draft 0.1 / experimental**

## 1. Current scope

KNP currently implements cryptographic node identity, signed discovery, endpoint cookies, replay filtering, authenticated encrypted sessions, peer-reported external endpoint observations, and an experimental peer-coordinated UDP rendezvous primitive.

Automatic global peer discovery, robust NAT/filtering classification, production-grade hole punching, DHT routing, and cooperative relay are not complete.

## 2. Identity and signed envelope

Each node owns an Ed25519 key pair.

```text
NodeID = "knp1" || HEX(SHA-256(Ed25519PublicKey)[0..20])
```

All KNP outer control messages are carried in Ed25519-signed envelopes. NodeID/public-key binding, signature verification, timestamp skew, and bounded nonce replay checks are applied before control processing.

## 3. Admission

A new ordinary inbound peer must return a stateless HMAC-SHA256 endpoint cookie before normal peer admission. The cookie binds the observed UDP source endpoint and a rotating time bucket.

## 4. Secure sessions

Admitted peers use ephemeral X25519 key agreement authenticated by the signed outer envelope. HKDF-SHA256 derives separate directional keys from a transcript containing both NodeIDs, the handshake ID, and both ephemeral public keys. Secure payloads use ChaCha20-Poly1305.

## 5. External endpoint observation

A receiver of HELLO reports the sender's observed UDP source endpoint in HELLO_ACK. The sender stores this as an observation attributed to that peer NodeID.

The current `NatProfile` is bounded and classifies **mapping behavior only**:

- no evidence,
- single observation,
- stable endpoint across at least two observers,
- same public address with varying ports,
- varying public addresses.

These categories do not prove classic full-cone/restricted/port-restricted/symmetric filtering behavior. Separate filtering probes are required for that.

## 6. Decentralized rendezvous

Rendezvous uses an ordinary KonoNexus node C that already has authenticated encrypted sessions with A and B.

1. A sends an encrypted `RendezvousRequest(target_node_id=B)` to C.
2. C verifies that B is a known peer with an encrypted session.
3. C creates a random short-lived punch token.
4. C sends encrypted `RendezvousOffer` messages to A and B.
5. Each offer contains the other peer's NodeID, the UDP endpoint observed by C, and the same punch token.
6. A and B send signed `PUNCH_PROBE` packets toward the offered endpoint.
7. A probe is accepted only when the token is locally pending and the signed sender NodeID equals the expected peer NodeID.
8. The receiver responds with signed `PUNCH_ACK`, records the direct source endpoint, and starts a fresh encrypted KNP session on that path.

The authorization is short-lived and is removed after successful use.

This coordinator is not a fixed server. Any suitable peer with encrypted sessions to both endpoints may perform this role.

## 7. Current limitations of punching

The present alpha sends one immediate probe to the candidate endpoint. It does not yet implement:

- synchronized multi-packet bursts,
- port prediction,
- alternate candidate sets,
- retry/backoff state,
- filtering-behavior probes,
- ICE-like prioritization,
- automatic rendezvous selection.

Destination-specific/symmetric NAT mappings may therefore fail. Cooperative relay remains the planned fallback.

## 8. Security properties of rendezvous

Rendezvous control data is sent inside the existing AEAD session to the coordinator. Direct punch packets remain signed outer KNP messages so that a peer can authenticate a previously unseen direct source endpoint before a direct encrypted session exists.

A token alone is insufficient: the punch sender must also prove possession of the Ed25519 identity corresponding to the NodeID named in the encrypted rendezvous offer.

## 9. Planned next stages

1. timed hole-punch burst and retry state machine,
2. richer mapping/filtering tests,
3. automatic rendezvous peer selection,
4. IPv6 direct-path preference,
5. DHT-based peer discovery,
6. cooperative encrypted relay fallback,
7. route scoring and KonoMind optimization.

## 10. Versioning

Unknown protocol versions are rejected in the alpha implementation. Stable KNP will require explicit capability negotiation and documented compatibility semantics.
