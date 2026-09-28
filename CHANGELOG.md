# Changelog

Development log for KonoNexus.

## Unreleased

- Added a bounded seven-attempt UDP punch burst with increasing retry delays and a five-second authorization window.
- Added a 50 ms punch scheduler independent of the slower discovery timer.
- Added a hard limit of 128 pending punch schedules and deterministic expiry reporting.
- Rejected unsafe rendezvous candidates such as loopback, unspecified, multicast, broadcast and port-zero endpoints.
- Kept punching restricted to the coordinator-observed endpoint instead of spraying adjacent ports.
- Added unit tests for burst timing, identity binding, expiry and candidate safety.
- Bumped the implementation package to 0.1.0-alpha.5.

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
