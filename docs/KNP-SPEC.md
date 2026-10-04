# KonoNexus Protocol (KNP) — Draft Specification

Status: **Draft 0.1 / experimental**

## 1. Current scope

KNP currently implements cryptographic node identity, signed discovery, endpoint cookies, replay filtering, authenticated encrypted sessions, peer-reported external endpoint observations, peer-coordinated UDP rendezvous, a consented three-cell filtering-behavior matrix, and a signed DHT-style peer-record discovery foundation.

Bounded recursive multi-hop DHT routing now exists across established encrypted peers. Alpha.9 persists authenticated-peer routing hints across restarts and added the bounded single-hop cooperative relay circuit foundation. Alpha.10 adds an authenticated end-to-end session inside that relay transport plus deterministic fallback from a failed coordinated punch to the same relay-capable coordinator. Alpha.11 adds a live bounded application API, MTU-aware fragmentation/reassembly, and ACK-based backpressure on top of that relay E2E session. Alpha.12 adds bounded RelayApp retransmission, duplicate-delivery suppression, a 128-sequence sliding anti-replay window that tolerates authenticated UDP reordering, and relay circuit/bandwidth abuse quotas. Alpha.13 adds explicit RelayApp delivery-failure events, bounded direct-session handshake retransmission with cached responder ACKs, responder-side confirmation before deferred encrypted control traffic is flushed, and bounded alternate relay selection across existing encrypted peers. Alpha.14 adds periodic fresh-X25519 rekey for direct KNP sessions with previous-session grace, plus NodeID-centric RelayApp transport migration that prefers confirmed direct sessions and falls back to relay E2E without resetting application message state. The current branch also rotates relay-inner E2E sessions with the same bounded fresh-X25519 pattern, persists the complete bounded k-bucket membership snapshot for restart bootstrap, exchanges bounded endpoint attestations at runtime, and applies authenticated DHT ingress budgets and observed-prefix routing diversity. Alpha.23 adds a 32-node localhost runtime convergence/churn test using 30 leaves and two hubs. Multi-network validation, Sybil-resistant observer diversity, and production hardening remain incomplete; localhost results make no WAN/NAT/CGNAT claim.

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

### Bounded exact-candidate planning

Explicit application connection hints and independently attested endpoints from an exact DHT record use the same target-NodeID-bound plan. Input order is the priority order. The plan deduplicates endpoints, retains at most three, starts them with a four-second stagger, expires after 30 seconds, and never synthesizes another address or port. At most 256 target plans may exist at once.

Only the endpoint selected for an attempt is temporarily admitted as an expected discovery source. Its signed NodeID must equal the plan's target before ordinary peer admission, so a valid but different identity at a supplied address cannot satisfy the plan. The same endpoint cannot be active under two target NodeIDs. Port zero, unspecified, multicast and IPv4 broadcast connection hints are rejected.

A confirmed encrypted direct session removes every remaining exact candidate and pending handshake for that target, cancels sibling punch schedules and automatic rendezvous, and suppresses pending relay work. When exact candidates are exhausted, the target advances to one bounded automatic-rendezvous coordinator round. Relay fallback becomes eligible only after that round and its authorized punch work are exhausted. This is bounded exact-candidate selection, not ICE, port prediction or permission to scan neighboring endpoints.

## 9. Consent-based filtering matrix

KNP records a bounded three-cell filtering-behavior matrix. Each cell represents the source relationship of one authorized UDP probe to the coordinator endpoint that the target already contacted:

1. **Contacted endpoint control:** coordinator C sends from the exact endpoint already contacted by the target.
2. **Same address, different port:** C sends one datagram from the same IP address and a temporary, different source port.
3. **Different, previously uncontacted address:** helper H sends from an address that differs from C and the target and is absent from the target's bounded recent-egress history and direct-peer set.

The target asks C for a trial over their authenticated encrypted session. C proposes each source class and the exact target endpoint it observes. The target accepts only proposals matching its C-attributed endpoint observation and signs a short-lived, versioned Ed25519 authorization. The authorization binds the target NodeID/public key and endpoint, C's NodeID and baseline endpoint, the helper NodeID, source class, trial ID, random probe token, and validity window.

For the control and same-address cells, C verifies consent against pending coordinator state and sends from its normal socket or a temporary same-family socket respectively. For the different-address cell, C may forward the authorization only to a capability-advertising helper with an authenticated session and a different observed IP. H independently verifies the authorization and sends at most one datagram. Authorization reuse, pending state, per-coordinator, per-target, global send rates, and stored evidence are bounded.

The target accepts a result only when the signed sender, token, trial, class, and actual UDP source relationship match the pending authorization. A successful observation is positive evidence for that cell. Multiple positive different-address observations count as repeated endpoint-independent evidence only when they come from distinct observed IPv4 `/24` or IPv6 `/48` prefixes.

Every negative state remains deliberately non-diagnostic. Timeout, unavailable helper, and send failure are reported as **inconclusive**; even a control-correlated timeout can reflect loss or transient reachability and does not prove restrictive filtering. Localhost and CI coverage proves only protocol/state-machine behavior, not behavior on real WAN, NAT, or CGNAT paths.

## 10. Current limitations

The bounded planner tries only supplied, signed-offer or independently attested exact endpoints. It does not implement port prediction, broad ICE-like candidate gathering or arbitrary interface discovery. The filtering matrix records positive reachability across three source relationships, but it does not infer a restrictive filtering class from non-arrival. Real multi-network/NAT/CGNAT field validation remains open.

Destination-specific/symmetric NAT mappings may therefore still fail. Cooperative relay remains the planned fallback.

## 11. Security properties of rendezvous

Rendezvous control data is sent inside the existing AEAD session to the coordinator. Direct punch packets remain signed outer KNP messages so that a peer can authenticate a previously unseen direct source endpoint before a direct encrypted session exists.

A token alone is insufficient: the punch sender must also prove possession of the Ed25519 identity corresponding to the NodeID named in the encrypted rendezvous offer.

## 12. Planned next stages

1. real multi-network/NAT/CGNAT validation of the filtering matrix,
2. IPv6 direct-path preference,
3. broader DHT convergence and churn validation,
4. multi-relay/full-control-plane migration,
5. KonoMind learning and optimization from real path outcomes.

The bounded direct-candidate planner has partial IPv6 groundwork: among exact supplied and independently attested endpoints it tries native IPv6 before IPv4 and, when mixed-family input exceeds the initial three-candidate cap, reserves one slot for an IPv4 fallback. It preserves the signed/supplied socket addresses. Explicit connect hints with IPv6 link-local addresses require an interface scope; DHT records continue to require publishable endpoints and exact endpoint attestations. This does not provide dual-stack socket availability or multi-endpoint publication; the IPv6 direct-path preference stage remains open pending those changes and multi-network validation.

## 13. Signed DHT discovery foundation

A peer record contains NodeID and Ed25519 public key, up to four public socket endpoints, a time-based sequence/issue timestamp, an expiry timestamp, and an Ed25519 signature over the complete unsigned record.

The default lifetime is ten minutes and the maximum accepted lifetime is thirty minutes. Endpoints with port zero, loopback, private/link-local, multicast, broadcast, unspecified, IPv6 unique-local, or IPv6 link-local addresses are not publishable through the global DHT record format.

The local DHT table stores at most 4,096 records. A newer valid sequence replaces an older record for the same NodeID; rollback records are ignored. Expired records are never returned by exact or nearest reads and are removed during bounded maintenance.

DHT control travels inside encrypted SecurePayload messages: `DhtStore` carries one signed record, `DhtFind` carries a requested NodeID, and `DhtNodes` carries that target plus at most eight records. Responses return an exact record first when available and then a bounded nearest-record set ordered by XOR distance over SHA-256(NodeID).

Nearest records may be cached for future answers, but the current implementation does not automatically dial them. Only an exact valid record matching a locally pending NodeID lookup can contribute independently attested endpoints to the bounded candidate plan. At most three exact endpoints are tried in order, and each still passes through signed HELLO, anti-amplification cookie, expected-NodeID admission, and encrypted-session handshake.

This deliberately avoids turning untrusted nearest-record gossip into automatic outbound connection scanning.

## 14. Bounded multi-hop lookup and routing buckets

Each node maintains an in-memory routing table with 256 XOR-distance buckets derived from SHA-256(NodeID). A bucket stores at most 8 peers and at most 2 peers from one observed IPv4 `/24` or IPv6 `/48`; IPv4-mapped IPv6 is normalized to IPv4. Membership is created or refreshed only after an encrypted frame decrypts successfully and its outer sender matches the NodeID bound to that session. A new same-prefix peer replaces only the oldest peer from that prefix; a new prefix entering a full bucket evicts the oldest peer from the most represented prefix, with deterministic tie-breaking.

For a pending NodeID lookup, the origin orders active routing peers by XOR distance with one peer per observed prefix in the first pass and deterministic same-prefix fallback in the second pass. After session/source/capability filters it selects up to 2 and sends an encrypted `DhtFind` containing a random query ID, origin NodeID, target NodeID, and hop budget. The initial hop budget is 3. Intermediate forwarding and owner/transit replication use the same diverse ordering.

An intermediate node validates NodeID shape and hop bounds, applies ingress limits to the authenticated immediate sender before allocating seen/reverse state or answering, suppresses duplicate `(origin, query_id)` pairs, returns its current exact/nearest signed records, stores a short-lived reverse route toward the requester, and forwards the query to at most 2 other established encrypted peers when no exact record is known and hops remain. Query token buckets are keyed by authenticated NodeID (burst 8, refill one per 2 seconds), observed IPv4 `/24` or IPv6 `/48` (burst 32, refill one per 500 ms), and globally (burst 128, refill one per 125 ms). Peer and prefix state is capped at 4,096 and 1,024 entries, retained for ten minutes, and fails closed at capacity; a claimed origin NodeID never selects the rate-limit bucket.

`DhtNodes` is accepted only from a child endpoint to which that exact query and target were forwarded; each child may contribute at most the 15 responses possible in the bounded fanout-2/depth-3 tree. All returned records are verified before forwarding, while local cache admission is exact-target-first and limited to 2 records per response. If the node is not the origin, the original bounded response is forwarded along the encrypted reverse path. At the origin, only an exact current record for the requested NodeID with matching, unexpired attestations from at least two different Ed25519 identities can activate temporary discovery endpoints.

An authenticated peer signs a short-lived `EndpointAttestation` for the public source endpoint it observes after session confirmation and sends that evidence directly to the endpoint owner. Self-attestations are rejected. Attestations bind the subject NodeID, endpoint, observer NodeID/public key, observation time, expiry and signature; their maximum lifetime is ten minutes. Owners attach collected evidence to `DhtStore`, and `DhtNodes` carries at most four matching attestations so the encrypted envelope remains inside the 16 KiB packet bound. Receivers accept evidence only for a currently valid signed peer record containing that exact endpoint. Storage and rollback high-watermarks are bounded, newer observations replace older ones from the same observer, and replay of older still-valid evidence remains rejected after replacement or expiry.

Two independent identities provide reachability corroboration, not Sybil resistance. Stronger observer diversity remains required before production.

Fresh, quorum-attested `DhtStore` records use a replication hop budget of 2. A node forwards a newly accepted record or newly accepted matching evidence to at most 2 nearest confirmed routing peers, excluding the sender and record owner, and decrements the budget. Duplicate sequence/evidence observations do not forward again within the same confirmed-session generation. Replication is sent only to peers advertising `bounded-dht-replication-v1`; rolling-upgrade peers still receive the owner's record with a zero hop budget.

Topology refresh is also bounded: when a capable encrypted session is confirmed, each side may send at most 4 current quorum-attested cached records nearest to the new peer, with no further replication hops. Endpoint-attestation refresh causes owners to issue fresh signed records before the ten-minute record TTL. Owner publication has 8 reserved queue slots and at most 8 target identities per record sequence; all other replica work shares a 248-slot queue allowance. The 500 ms scheduler emits at most 4 stores per tick and at most one per target. A replica never extends or re-signs owner lifetime; records and evidence still expire under their original signatures.

Before any `DhtStore` or locally cached `DhtNodes` record can consume a DHT rollback watermark, a weighted admission guard charges the authenticated sender identity, its observed IPv4 `/24` or IPv6 `/48`, and a global bucket. The fixed 60-second bounds are respectively 32, 96, and 120 admitted records; at most 4,096 guard states survive for ten minutes. Combined with the 2-record response-cache limit, this preserves normal maximum-depth lookup fan-in while keeping sustained new-identity tombstones below half of the 8,192-entry rollback table's capacity, including the accepted clock-skew horizon.

To constrain amplification and loops, query state expires after 8 seconds, forwarding from the same immediate peer is throttled, the seen-query cache is capped, and stale forwarding cooldown state is removed. The design intentionally favors bounded reachability over aggressive flooding.

## 15. Remaining DHT work

- operator/identity diversity stronger than observed-prefix friction,
- large-mesh convergence and churn testing across independent networks and failure conditions beyond the localhost runtime harness.

## 16. Persistent routing bucket snapshot

The runtime persists the complete bounded routing-table membership snapshot: bucket index, NodeID, endpoint, and last-seen time. The file is bound to the local NodeID, stores at most 8 entries and at most 2 entries per observed `/24` or `/48` in each of the 256 XOR-distance buckets (2,048 entries total), independently deduplicates NodeIDs and endpoints, rejects future/stale entries older than seven days, validates that every stored NodeID maps back to the claimed bucket, and keeps atomic replace semantics. Legacy version-1 flat hint caches are accepted only through the same normalization and migrate on the next save.

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

## 25. Runtime path scoring and failure recovery

The control-plane route selector considers the already-confirmed direct path and at most three established relay E2E circuits. A healthy confirmed direct path is preferred. A hard send error marks that exact route failed and applies a five-second cooldown; if direct sending fails while an established relay is available, the same bounded send operation retries using a relay. Expired cooldowns make the confirmed direct path eligible and preferred again.

Relay candidates use the deterministic KonoMind baseline score. Per-peer, per-route health is retained in a 2,048-entry bounded table and includes saturating success/failure counts plus a finite RTT EWMA. Relay RTT and success evidence comes only from an authenticated RelayApp delivery ACK received on the same route as the latest fragment attempt for that peer/message. The attempt table is capped at 64, matching the outbound-message limit. A valid ACK received over a different route still acknowledges delivery but is excluded from route scoring. A local UDP send does not establish path success. Immediate send errors and terminal RelayApp retries/expiry report route failures. A current relay is retained when its score is within the fixed hysteresis margin of the best candidate.

This is a deterministic local scoring mechanism, not machine learning and not evidence of real NAT/CGNAT reachability. Existing authentication, admission, replay protections, exact endpoint rules, and relay-candidate construction are unchanged.

## 26. Versioning

Unknown protocol versions are rejected in the alpha implementation. Stable KNP will require explicit capability negotiation and documented compatibility semantics.
