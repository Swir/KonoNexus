# KonoNexus Threat Model — Draft

KonoNexus should assume that the public Internet and arbitrary relay nodes are hostile.

## Assets

- long-term node identity keys,
- session keys,
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
- unknown PING/PONG endpoints do not create peer entries,
- bounded active peer table with oldest-peer eviction,
- unverified packets rejected before peer acceptance.

## Required before production

- authenticated ephemeral key agreement,
- AEAD framing with monotonically checked sequence numbers,
- rate limits per endpoint and identity,
- secure key-file permissions on each supported OS,
- load testing and audit of replay/cookie windows and peer eviction policy,
- DHT record signatures and expiry,
- Sybil resistance / routing diversity,
- relay abuse controls,
- fuzzing of wire parsers,
- dependency and supply-chain scanning,
- independent security review.

## Non-goals

KNP cannot make an endpoint safe after the endpoint itself is compromised. It also cannot guarantee a connection when there is no physical Internet path and no reachable cooperative peer.
