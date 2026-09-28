# Changelog

Development log for KonoNexus.

## Unreleased

- Added bounded peer-attributed external UDP endpoint observations.
- Added NAT mapping-behavior classification without overstating full NAT type detection.
- Added encrypted decentralized rendezvous requests/offers through ordinary KonoNexus peers.
- Added short-lived signed PUNCH_PROBE/PUNCH_ACK direct-path authorization.
- Added direct endpoint migration and fresh encrypted-session setup after successful punching.
- Added an experimental CLI rendezvous trigger for controlled multi-machine testing.
- Added tests for NAT observation/classification and rendezvous CLI parsing.
- Bumped the implementation package to 0.1.0-alpha.4.
- Added authenticated X25519/HKDF/ChaCha20-Poly1305 sessions.
- Integrated replay protection and endpoint cookies into live UDP handling.
- Added the KonoMind advisory scaffold; no learned model is claimed yet.
