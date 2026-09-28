# Changelog

Development log for KonoNexus.

## Unreleased

- Added authenticated ephemeral X25519 session establishment.
- Added transcript-bound HKDF-SHA256 directional session key derivation.
- Added ChaCha20-Poly1305 encrypted KNP frames with sequence-bound AEAD.
- Added secure encrypted PING/PONG after session establishment.
- Added encrypted-frame replay rejection and key zeroization on session drop.
- Added public and integration tests for bidirectional encrypted payload exchange, replay rejection, ciphertext tampering, and invalid X25519 shared secrets.
- Bumped the implementation package to 0.1.0-alpha.3.
- Integrated bounded replay protection into live UDP packet handling.
- Added stateless HMAC-SHA256 endpoint cookies before new inbound peer admission.
- Added a bounded active peer table and ignored unsolicited HELLO_ACK/PING/PONG admission attempts.
- Added the KonoMind adaptive-routing advisory scaffold.
- KonoMind remains advisory-only; no learned model is claimed yet.
