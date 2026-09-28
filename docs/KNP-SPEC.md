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

## 7. Timed punch burst

A rendezvous offer creates a bounded local punch schedule instead of sending only one probe.

- first probe is delayed by 100 ms to give both peers time to receive their offers,
- at most seven signed probes are sent,
- retries use increasing local delays (100, 150, 250, 400, 650 and 1000 ms after prior sends),
- authorization remains valid for five seconds so delayed replies can still succeed,
- success removes the schedule immediately,
- expiration removes the schedule deterministically and logs the attempt count,
- at most 128 punch schedules may be pending on one node.

The implementation deliberately sends only to the coordinator-observed candidate. It does not spray adjacent ports. Rendezvous candidates with port 0, loopback, unspecified, multicast, or IPv4 broadcast addresses are rejected locally.

## 8. Automatic rendezvous selection

A node may request a target NodeID without naming a coordinator. KNP considers only peers with established encrypted sessions, prefers IPv6 and longer-lived peers deterministically, and tries at most three different coordinators per round. A negative coordinator response accelerates trying the next candidate. An unsuccessful punch resumes coordinator selection after the punch authorization expires.

The bounded selector does not discover new peers by itself; DHT discovery is still required for a truly global rendezvous pool.

## 9. Consent-based filtering evidence

KNP can gather positive evidence for endpoint-independent inbound filtering using a third helper peer.

1. The tested node asks coordinator C for a filtering test.
2. C selects helper H only if H has an encrypted session with C and C observes H on a different IP from the tested node.
3. C proposes H and the tested node's C-observed endpoint.
4. The tested node rejects the proposal unless that endpoint exactly matches its existing observation attributed to C and unless it has no existing direct relationship with H.
5. The tested node creates an Ed25519-signed, short-lived authorization binding its NodeID/public key, target endpoint, H's NodeID, and a random probe token.
6. C verifies the consent against its pending proposal and forwards it to H.
7. H independently verifies the signature, NodeID binding, expiry, helper identity, and target endpoint before sending one signed direct FILTER_PROBE.
8. The tested node counts evidence only if the arriving probe carries the expected signed H identity and token.

A successful probe is positive evidence that an independent endpoint reached the mapping. A timeout is only inconclusive; packet loss or helper reachability can cause false negatives.

## 10. Current limitations

The punch burst still does not implement port prediction or broad ICE-like candidate prioritization. Filtering evidence currently proves only successful independent-endpoint reachability; it does not infer a restrictive filtering class from non-arrival.

Destination-specific/symmetric NAT mappings may therefore still fail. Cooperative relay remains the planned fallback.

## 11. Security properties of rendezvous

Rendezvous control data is sent inside the existing AEAD session to the coordinator. Direct punch packets remain signed outer KNP messages so that a peer can authenticate a previously unseen direct source endpoint before a direct encrypted session exists.

A token alone is insufficient: the punch sender must also prove possession of the Ed25519 identity corresponding to the NodeID named in the encrypted rendezvous offer.

## 12. Planned next stages

1. broader filtering-behavior validation,
2. IPv6 direct-path preference,
3. safe multi-candidate/path prioritization,
4. DHT-based peer discovery,
5. cooperative encrypted relay fallback,
6. route scoring and KonoMind optimization.

## 13. Versioning

Unknown protocol versions are rejected in the alpha implementation. Stable KNP will require explicit capability negotiation and documented compatibility semantics.
