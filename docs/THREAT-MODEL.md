# KonoNexus Threat Model — Draft

KonoNexus should assume that the public Internet and arbitrary relay nodes are hostile.

## Assets

- long-term node identity keys,
- ephemeral X25519 secrets,
- derived session keys,
- application message confidentiality,
- peer authenticity,
- availability and routing integrity,
- user metadata.

## Adversaries considered

- passive network observers,
- active packet injectors,
- malicious peers,
- malicious relay nodes,
- replay attackers,
- identity impersonators,
- Sybil participants,
- peers attempting resource exhaustion,
- attackers spoofing UDP source addresses to cause reflected traffic.

## Alpha protections already present

- Ed25519 identity keys,
- NodeID bound to public key,
- signatures over KNP control envelopes,
- explicit protocol version,
- datagram size ceiling,
- bounded timestamp/nonce replay filtering,
- stateless HMAC endpoint cookies before new inbound peer admission,
- bounded active peer table with oldest-peer eviction,
- authenticated ephemeral X25519 key agreement,
- all-zero X25519 shared-secret rejection,
- HKDF-SHA256 transcript-bound directional key derivation,
- ChaCha20-Poly1305 secure frames,
- authenticated session/sequence AEAD associated data,
- monotonic secure-frame replay rejection,
- session keys zeroized when the in-memory session is dropped,
- unverified packets rejected before peer acceptance.

## Current limitations

- secure-frame receive ordering is strict and may reject valid reordered UDP packets,
- session handshakes do not yet have a dedicated retransmission/timeout state machine,
- session keys are not yet periodically rotated,
- secure sessions have automated tests but no independent security audit,
- metadata such as peer IP endpoints remains observable to network participants on the path.

## Required before production

- handshake timeout/retransmission hardening,
- bounded sliding replay windows for encrypted UDP frames,
- session key rotation and teardown,
- rate limits per endpoint and identity,
- secure identity-key file permissions on each supported OS,
- load testing and audit of replay/cookie/session state limits,
- DHT record signatures and expiry,
- Sybil resistance / routing diversity,
- relay abuse controls,
- fuzzing of wire and encrypted-frame parsers,
- dependency and supply-chain scanning,
- independent security review.

## Non-goals

KNP cannot make an endpoint safe after the endpoint itself is compromised. It also cannot guarantee a connection when there is no physical Internet path and no reachable cooperative peer.
