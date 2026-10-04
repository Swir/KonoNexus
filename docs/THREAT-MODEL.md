# KonoNexus Threat Model — Draft

KonoNexus assumes that the public Internet, arbitrary peers, and future relay nodes may be hostile.

## Alpha protections already present

- Ed25519 node identity and signed outer envelopes,
- NodeID/public-key binding,
- timestamp and nonce replay filtering,
- stateless endpoint cookies before ordinary inbound admission,
- bounded peer/replay/NAT-observation state,
- authenticated ephemeral X25519 key agreement,
- HKDF-SHA256 directional key derivation,
- ChaCha20-Poly1305 secure frames,
- encrypted rendezvous request/offer messages,
- punch authorization bound to both a random short-lived token and expected signed NodeID,
- direct endpoint migration only after authenticated control,
- bounded seven-probe punch bursts with deterministic five-second expiry,
- bounded pending-punch state (128 schedules),
- rejection of loopback/unspecified/multicast/broadcast rendezvous targets,
- bounded automatic rendezvous coordinator attempts and per-requester coordinator cooldown,
- consent-based third-peer filtering probes with Ed25519 authorization bound to endpoint, helper and token,
- target-side verification that a coordinator proposal matches that coordinator's previously observed endpoint,
- signed short-lived DHT peer records with NodeID/public-key binding,
- bounded DHT table (4,096) and response size (8), TTL limits, and rollback rejection,
- DHT endpoints restricted to publishable public addresses,
- automatic dialing only for exact records matching a locally pending NodeID lookup, never arbitrary nearest-record gossip,
- in-memory 256-bucket routing state populated only after a session-bound encrypted frame decrypts successfully, with at most two peers from one observed IPv4 `/24` or IPv6 `/48` per bucket,
- recursive DHT lookup limited to fanout 2 and 3 hops with observed-prefix-diverse selection, deterministic availability fallback, duplicate-query suppression, short-lived reverse routes, forwarding cooldown, and bounded query state,
- persistent routing hints normalized to the same per-bucket prefix cap, saved only from authenticated encrypted sessions, and revalidated through the full handshake after restart,
- relay circuit setup bound to existing encrypted sessions, explicit target acceptance, and READY validation against pending local state,
- relay state limited to 256 circuits with 120-second idle expiry, 3 KiB opaque cells, and per-direction transport sequence rollback/replay rejection,
- inner relay handshake authenticated by Ed25519 and bound to circuit ID plus both endpoint NodeIDs,
- fresh inner X25519/HKDF/ChaCha20-Poly1305 session keys that are never disclosed to the forwarding relay,
- deterministic single-side punch-to-relay fallback to avoid duplicate circuit storms,
- alternate relay fallback limited to three distinct already-authenticated encrypted peers in a short-lived selection state,
- 128-sequence sliding anti-replay windows for encrypted sessions and relay transport, allowing bounded authenticated reordering while rejecting duplicates and stale sequences,
- inner secure-session replay/tamper checks in addition to outer relay transport sequencing,
- RelayApp message size, queue-byte, queue-count, reassembly-count, reassembly-byte, completed-queue, and expiry limits,
- strict fragment metadata/length validation, duplicate-content consistency checks, and encrypted application ACKs,
- bounded async application command/event channels so slow application consumers cannot create unbounded network-loop queues,
- one-second RelayApp ACK timeout with at most four retransmissions, bounded delivered-message deduplication, and explicit application-visible delivery-failure events,
- one-second direct-session INIT retransmission with at most four total attempts plus bounded ten-second responder ACK caching,
- responder application/control traffic deferred until an authenticated encrypted frame confirms the initiator completed the session,
- direct-session rekey uses fresh X25519 material, a deterministic single initiator, bounded retries, cached matching ACKs, and a 30-second previous-session grace window,
- RelayApp path selection prefers confirmed direct encryption and falls back to authenticated relay E2E while retaining identity/message-bound delivery state,
- relay per-NodeID circuit cap (16) plus per-direction rate quotas (128 cells/s and 256 KiB/s),
- session keys zeroized when sessions are dropped.

## NAT/rendezvous threats considered

- forged endpoint offers,
- UDP source spoofing,
- reflection/amplification,
- unsolicited punch traffic,
- malicious coordinators,
- stale punch tokens,
- peer endpoint changes.

A malicious coordinator can give peers incorrect candidate endpoints or refuse rendezvous. It cannot forge the target peer's Ed25519 identity or complete the target peer's X25519 session. KNP therefore treats rendezvous as a reachability hint, not identity authority.

Punch packets are accepted only for a pending token delivered over an encrypted coordinator session and for the expected signed NodeID. Pending punch authorizations expire.

## Current limitations

- timed hole punching is implemented but has not yet been validated across a wide NAT matrix,
- no port-prediction or safe alternate-candidate strategy exists,
- positive endpoint-independent filtering evidence is supported, but negative results remain intentionally inconclusive,
- authenticated secure frames tolerate reordering only within the 128-sequence receive window; duplicates and frames older than that window are rejected,
- periodic fresh-X25519 key rotation with bounded retries and previous-session grace is implemented for direct KNP and relay-inner E2E sessions,
- DHT endpoint activation requires matching short-lived attestations signed by two independent observer identities, but identity count alone is not a Sybil-resistant quorum,
- recursive DHT routing, full bounded bucket persistence, hop/fanout-bounded replica refresh, and observed-prefix routing diversity exist, but `/24`/`/48` grouping is only Sybil friction and neither proves independent operators nor makes endpoint-observer quorum Sybil-resistant,
- routing-cache files expose peer metadata on local disk even though they contain no private keys,
- relay control metadata remains visible to the forwarding node, including endpoint identities, circuit IDs, timing, and cell sizes,
- application payload APIs are now exposed only through the inner E2E RelayApp layer; raw relay cells are not the application API,
- whole-message RelayApp retransmission and explicit application delivery-failure callbacks are implemented, but selective fragment retransmission is not yet implemented,
- relay quotas are implemented, but long-window abuse accounting, adaptive quotas, and reputation/Sybil controls are not yet implemented,
- RelayApp direct↔relay path migration is implemented, but full control-plane migration and multi-relay policy are not yet implemented,
- no independent security audit has been completed.

## Required before production

- stronger long-window per-peer rendezvous/filter-test rate limits,
- wider NAT/filtering matrix validation and loss-tolerant repeated evidence,
- Sybil-resistant endpoint-attestation quorum and routing diversity stronger than observed-prefix grouping,
- selective RelayApp recovery, longer-window relay abuse accounting, adaptive per-peer quotas, and multi-relay/control-plane failover hardening,
- secure key-file permissions,
- parser fuzzing and dependency scanning,
- load testing,
- independent security review.

## Non-goals

KNP cannot guarantee a direct path through every NAT. When direct traversal is impossible, a cooperative encrypted relay path is required. KNP also cannot protect an endpoint after that endpoint itself is compromised.
