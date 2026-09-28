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
- in-memory 256-bucket routing state populated only by authenticated encrypted peers,
- recursive DHT lookup limited to fanout 2 and 3 hops with duplicate-query suppression, short-lived reverse routes, forwarding cooldown, and bounded query state,
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
- session receive ordering remains strict,
- session key rotation is not implemented,
- DHT endpoint records are self-asserted by their owning NodeID and are not yet independently endpoint-attested,
- recursive DHT routing exists, but bucket persistence, endpoint attestations, and Sybil resistance are not yet implemented,
- no independent security audit has been completed.

## Required before production

- stronger long-window per-peer rendezvous/filter-test rate limits,
- wider NAT/filtering matrix validation and loss-tolerant repeated evidence,
- bounded sliding anti-replay windows for UDP reordering,
- handshake retransmission and session key rotation,
- independent endpoint attestations for DHT records, persistent bucket storage, stronger query rate limits, and Sybil mitigation,
- relay abuse controls,
- secure key-file permissions,
- parser fuzzing and dependency scanning,
- load testing,
- independent security review.

## Non-goals

KNP cannot guarantee a direct path through every NAT. When direct traversal is impossible, a cooperative encrypted relay path is required. KNP also cannot protect an endpoint after that endpoint itself is compromised.
