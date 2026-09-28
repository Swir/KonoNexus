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

- one-shot hole punching is not yet resilient to timing differences,
- no port-prediction strategy exists,
- NAT mapping evidence does not yet characterize filtering behavior,
- session receive ordering remains strict,
- session key rotation is not implemented,
- no independent security audit has been completed.

## Required before production

- timed punch bursts/retry/backoff,
- rate limiting of rendezvous and punch attempts,
- bounded sliding anti-replay windows for UDP reordering,
- handshake retransmission and session key rotation,
- DHT signature/expiry rules and Sybil mitigation,
- relay abuse controls,
- secure key-file permissions,
- parser fuzzing and dependency scanning,
- load testing,
- independent security review.

## Non-goals

KNP cannot guarantee a direct path through every NAT. When direct traversal is impossible, a cooperative encrypted relay path is required. KNP also cannot protect an endpoint after that endpoint itself is compromised.
