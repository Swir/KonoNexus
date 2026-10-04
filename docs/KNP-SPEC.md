# KonoNexus Protocol (KNP) — Draft Specification

Status: **Draft 0.1 / experimental**

## 1. Current scope

KNP currently implements cryptographic node identity, signed discovery, endpoint cookies, replay filtering, authenticated encrypted sessions, peer-reported external endpoint observations, peer-coordinated UDP rendezvous, and a signed DHT-style peer-record discovery foundation.

Bounded recursive multi-hop DHT routing now exists across established encrypted peers. Alpha.9 persists authenticated-peer routing hints across restarts and added the bounded single-hop cooperative relay circuit foundation. Alpha.10 adds an authenticated end-to-end session inside that relay transport plus deterministic fallback from a failed coordinated punch to the same relay-capable coordinator. Alpha.11 adds a live bounded application API, MTU-aware fragmentation/reassembly, and ACK-based backpressure on top of that relay E2E session. Alpha.12 adds bounded RelayApp retransmission, duplicate-delivery suppression, a 128-sequence sliding anti-replay window that tolerates authenticated UDP reordering, and relay circuit/bandwidth abuse quotas. Alpha.13 adds explicit RelayApp delivery-failure events, bounded direct-session handshake retransmission with cached responder ACKs, responder-side confirmation before deferred encrypted control traffic is flushed, and bounded alternate relay selection across existing encrypted peers. Alpha.14 adds periodic fresh-X25519 rekey for direct KNP sessions with previous-session grace, plus NodeID-centric RelayApp transport migration that prefers confirmed direct sessions and falls back to relay E2E without resetting application message state. The current main branch also rotates relay-inner E2E sessions with the same bounded fresh-X25519 pattern and persists the complete bounded k-bucket membership snapshot for restart bootstrap. Endpoint attestations, broad convergence testing, multi-network validation, and production hardening are not complete.

## 2. Identity and signed envelope

Each node owns an Ed25519 key pair.

```text
NodeID = "knp1" || HEX(SHA-256(Ed25519PublicKey)[0..20])
```

All KNP outer control messages are carried in Ed25519-signed envelopes. NodeID/public-key binding, signature verification, timestamp skew, and bounded nonce replay checks are applied before control processing.

## 3. Admission

A new ordinary inbound peer must return a stateless HMAC-SHA256 endpoint cookie before normal peer admission. The cookie binds the observed UDP source endpoint and a rotating time bucket.

## 4. Secure sessions

Admitted peers use ephemeral X25519 key agreement authenticated by the signed outer envelope. HKDF-SHA256 derives separate directional keys from a transcript containing both NodeIDs, the handshake ID, and both ephemeral public keys. Secure payloads use ChaCha20-Poly1305. Each receive direction maintains a 128-sequence sliding replay window: authenticated frames may arrive out of order while duplicate sequence numbers and frames older than the window are rejected. The initiator may retransmit the same `SESSION_INIT` after a one-second timeout, up to four total attempts. The responder caches the corresponding ACK for ten seconds and re-sends the same responder ephemeral public key for a matching duplicate. Responder-side queued encrypted work is released only after an authenticated encrypted frame confirms that the initiator completed the session.

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

## 13. Signed DHT discovery foundation

A peer record contains NodeID and Ed25519 public key, up to four public socket endpoints, a time-based sequence/issue timestamp, an expiry timestamp, and an Ed25519 signature over the complete unsigned record.

The default lifetime is ten minutes and the maximum accepted lifetime is thirty minutes. Endpoints with port zero, loopback, private/link-local, multicast, broadcast, unspecified, IPv6 unique-local, or IPv6 link-local addresses are not publishable through the global DHT record format.

The local DHT table stores at most 4,096 records. A newer valid sequence replaces an older record for the same NodeID; rollback records are ignored. Expired records are removed.

DHT control travels inside encrypted SecurePayload messages: `DhtStore` carries one signed record, `DhtFind` carries a requested NodeID, and `DhtNodes` carries that target plus at most eight records. Responses return an exact record first when available and then a bounded nearest-record set ordered by XOR distance over SHA-256(NodeID).

Nearest records may be cached for future answers, but the current implementation does not automatically dial them. Only an exact valid record matching a locally pending NodeID lookup can create temporary discovery candidates. Those candidates still pass through signed HELLO, anti-amplification cookie, peer admission, and encrypted-session handshake.

This deliberately avoids turning untrusted nearest-record gossip into automatic outbound connection scanning.

## 14. Bounded multi-hop lookup and routing buckets

Each node maintains an in-memory routing table with 256 XOR-distance buckets derived from SHA-256(NodeID). A bucket stores at most 8 peers and contains only nodes that already have an established encrypted KNP session. Existing entries refresh their endpoint/last-seen time; a full bucket evicts its least-recently-seen entry.

For a pending NodeID lookup, the origin selects up to 2 nearest active routing peers and sends an encrypted `DhtFind` containing a random query ID, origin NodeID, target NodeID, and hop budget. The initial hop budget is 3.

An intermediate node validates NodeID shape and hop bounds, suppresses duplicate `(origin, query_id)` pairs, returns its current exact/nearest signed records, stores a short-lived reverse route toward the requester, and forwards the query to at most 2 other established encrypted peers when no exact record is known and hops remain.

`DhtNodes` responses are cached after signature/TTL verification. If the node is not the origin, the response is forwarded along the encrypted reverse path. At the origin, only an exact current record for the requested NodeID can activate temporary discovery endpoints.

To constrain amplification and loops, query state expires after 8 seconds, forwarding from the same immediate peer is throttled, and the seen-query cache is capped. The design intentionally favors bounded reachability over aggressive flooding.

## 15. Remaining DHT work

- runtime exchange and policy enforcement for endpoint ownership/observation attestations (the bounded signed observation primitive is implemented),
- replication/refresh strategy,
- stronger long-window query rate limiting,
- Sybil-resistant routing diversity,
- large-mesh convergence and churn testing.

## 16. Persistent routing bucket snapshot

The runtime persists the complete bounded routing-table membership snapshot: bucket index, NodeID, endpoint, and last-seen time. The file is bound to the local NodeID, stores at most 8 entries in each of the 256 XOR-distance buckets (2,048 entries total), rejects future/stale entries older than seven days, validates that every stored NodeID maps back to the claimed bucket, and keeps atomic replace semantics. Legacy version-1 flat hint caches are accepted and migrated on the next save.

Restart does **not** restore trust. At most the 256 freshest cached endpoints are promoted to bootstrap probes, and every one must complete the normal signed HELLO, anti-amplification cookie, identity verification, and encrypted-session handshake before it can again participate as an authenticated routing peer. This keeps restart recovery bounded while preserving the full k-bucket layout on disk for safe revalidation.

## 17. Cooperative relay circuit foundation

A relay circuit is single-hop and exists only through a node that already has authenticated encrypted KNP sessions with both endpoints.

Control flow:

1. origin sends `RelayOpen(circuit_id, target_node_id)` to the relay,
2. relay resolves the target only from its authenticated peer table and sends `RelayOffer` to that target,
3. target returns `RelayAccept`,
4. relay verifies the accepting endpoint/NodeID against the pending circuit,
5. relay sends `RelayReady` to both sides,
6. endpoints may exchange bounded `RelayCell` messages through the relay,
7. either side may send `RelayClose`.

The relay manager allows at most 256 circuits globally and at most 16 circuits involving any one NodeID. Idle circuits expire after 120 seconds. A relay cell contains circuit ID, per-direction sequence, and at most 3 KiB of opaque payload before hex encoding. Each direction is limited to 128 cells and 256 KiB per one-second quota window. The lower payload limit leaves room for nested secure framing inside the 16 KiB outer KNP datagram. Relay forwarding and endpoint receive paths use the same 128-sequence sliding replay window, so bounded reordering is accepted while duplicate/too-old cells are rejected. `RelayReady` is accepted only if it matches either a locally requested relay circuit or a specific pending target-side offer.

The relay layer does not parse the opaque payload. Alpha.10 runs a separate endpoint-to-endpoint session protocol inside those cells. The inner INIT/ACK handshake is signed with Ed25519 and binds the circuit ID, sender NodeID/public key, recipient NodeID, handshake ID, and ephemeral X25519 key. Both endpoints derive fresh directional session keys with the existing X25519/HKDF schedule and protect inner DATA with ChaCha20-Poly1305. The relay never receives the inner private keys or derived session keys.

## 18. Relay E2E session and automatic fallback

After a valid `RelayReady`, the endpoint with the lexicographically lower NodeID initiates the inner E2E handshake. This deterministic rule prevents both endpoints from starting competing inner sessions. Relay transport sequence numbers are checked on the receiving endpoint in addition to the inner secure-session sequence checks.

When a rendezvous offer creates a punch schedule, the endpoint remembers that encrypted coordinator as a possible relay. If the punch expires, only the endpoint with the lower NodeID attempts `RelayOpen` through that coordinator. The normal target-side `RelayOffer` / `RelayAccept` consent path still applies. A successful relay setup pauses immediate repeat rendezvous attempts.

The core sends an encrypted inner PING after the initiator completes the handshake and returns an encrypted PONG from the responder. This verifies the complete E2E path in protocol logic without treating relay transport confidentiality as endpoint-to-endpoint confidentiality.

## 19. Remaining relay work

- longer-window abuse accounting and adaptive quotas,
- full control-plane path migration rather than RelayApp-only migration,
- optional multi-relay path selection/failover and privacy analysis,
- real multi-network/CGNAT load and churn validation.

## 20. RelayApp application transport

Relay application messages are accepted only through an established inner E2E relay session. An application message is limited to 256 KiB and is split into 512-byte fragments. Each fragment carries a random message ID, fragment index/count, total message length, and hex-encoded data inside the encrypted inner `SecurePayload`.

The sender keeps at most 64 outbound messages and 2 MiB of queued application bytes. A message remains accounted against those limits after all fragments are sent until the remote endpoint completes reassembly and returns encrypted `RelayAppAck(message_id)`. Outbound state expires after 120 seconds.

The receiver permits at most 64 simultaneous reassemblies and reserves at most 4 MiB for their declared total lengths. Fragment count and lengths must exactly match the declared total length. Identical duplicate fragments are harmless; conflicting duplicates or metadata changes are rejected. Incomplete reassemblies expire after 30 seconds. Completed messages are held in a bounded queue of at most 128 messages / 4 MiB if the application consumer is temporarily backpressured.

`RelayAppHandle` uses bounded Tokio channels. Application `send()` waits for command-channel capacity, the node validates/queues the message, and a oneshot response returns the assigned message ID or queue error. `recv()` yields only fully authenticated, decrypted, and reassembled messages. The node transmits at most four application fragments per 50 ms transport tick to bound work added to the event loop.

After all fragments for a message are sent, the sender waits one second for encrypted `RelayAppAck`. On timeout it restarts the message from fragment zero; at most four retransmissions are permitted. The receiver keeps a bounded delivered-message cache for 120 seconds. If a retransmission arrives for an already delivered message with matching metadata, the receiver returns the ACK again without delivering a duplicate application event. After retry exhaustion the sender drops the message, releases its queued bytes, and enqueues a `RelayAppDeliveryFailure` event with the target NodeID, message ID, and `RetriesExhausted` reason. A separate `Expired` reason is reported when the hard outbound TTL removes a message. `RelayAppHandle::recv_failure()` exposes these failures to the application. The sliding secure-session replay window allows authenticated out-of-order frames within 128 sequence numbers.

## 21. Relay reliability and abuse limits

RelayApp reliability uses whole-message retry rather than selective fragment ACKs in alpha.12. This keeps state bounded and simple: one ACK confirms complete reassembly; loss of any fragment or the final ACK causes a full-message retransmission after one second. Four retransmissions are allowed. The deduplication cache ensures that a lost ACK does not produce duplicate application delivery.

Replay protection is layered. Signed outer KNP control messages keep the timestamp/nonce replay guard. Encrypted session sequences, relay forwarding sequences, and endpoint relay transport sequences use an independent 128-sequence sliding bitmap window. Authentication is verified before a secure-session sequence is committed to the window.

Relay abuse controls are applied per active circuit direction: 128 cells and 256 KiB per second. One NodeID may participate in at most 16 circuits on a relay, and the relay still has a 256-circuit global cap. These are conservative alpha defaults and require load testing before stable release.

## 22. Handshake and alternate-relay reliability

Direct session setup keeps one initiator attempt state per endpoint. `SESSION_INIT` is re-sent with the same handshake ID and X25519 ephemeral public key after one second, for at most four total sends. A responder caches at most 256 recent ACK descriptors for ten seconds. A duplicate init is accepted only when endpoint, peer NodeID, handshake ID, and initiator ephemeral key all match the cached state; the same responder public key is then returned. This prevents duplicate retransmission from silently switching the session key agreement.

The responder may derive and store the session immediately, but it does not treat the path as application-ready until one authenticated encrypted frame decrypts successfully. That first secure frame confirms the initiator received the ACK. Only then are queued rendezvous, filter-test, relay, and DHT control operations flushed.

Automatic relay fallback is bounded to three distinct currently encrypted peers. The last rendezvous coordinator is preferred when available. A rejection or failed candidate advances the fallback state to another encrypted peer without retrying the same endpoint. The fallback state expires after 30 seconds and is removed immediately when either a direct peer session or a relay path to the target becomes active.

## 23. Direct and relay-inner session rekey

Direct KNP session rotation is initiated only by the endpoint with the lexicographically lower NodeID. A confirmed session becomes eligible for rekey after approximately ten minutes.

The initiator creates a fresh X25519 ephemeral key and sends encrypted `SessionRekeyInit(rekey_id, ephemeral_public_key)` through the existing current session. The same rekey ID and ephemeral key are reused for retry attempts. Retry cadence is one second with at most four sends.

The responder derives a new session with the existing authenticated identity-bound X25519/HKDF schedule and sends `SessionRekeyAck` encrypted specifically through the session ID that carried the init. Matching ACK state is cached for ten seconds so a duplicate init caused by a lost ACK receives the same responder ephemeral public key rather than creating a divergent key agreement.

After a valid ACK, the initiator derives the same new session. Both sides switch ordinary sends to the new session immediately and retain the previous session for a 30-second grace window. During that window the old session may decrypt authenticated in-flight frames; the responder may also use it to resend a cached rekey ACK. After expiry, old session keys are dropped/zeroized with the normal `SecureSession` lifecycle.

Relay-inner E2E sessions use the same lower-NodeID initiation rule, fresh X25519 material, one-second/four-send retry bound, cached responder ACK behavior, and 30-second previous-session grace. Rekey control remains inside the authenticated inner session and is bound to the active relay circuit; the relay never receives the derived endpoint-to-endpoint keys.

## 24. NodeID-centric application path migration

RelayApp message state is independent from a particular network path. For each outgoing application fragment or ACK, the runtime chooses:

1. confirmed direct KNP transport when available;
2. otherwise an active relay E2E circuit for the same peer NodeID.

Because message IDs, reassembly state, delivery ACKs, retransmission state, and deduplication are keyed by peer identity/message rather than path, transport may change between fragments or retries without restarting the application message. Direct transport is preferred automatically as soon as it becomes confirmed. If direct transport disappears while a relay E2E path remains active, later sends may use relay.

This migration currently covers RelayApp application traffic. Full migration of all KNP control-plane responsibilities and multi-relay route switching remain future work.

## 25. Versioning

Unknown protocol versions are rejected in the alpha implementation. Stable KNP will require explicit capability negotiation and documented compatibility semantics.
