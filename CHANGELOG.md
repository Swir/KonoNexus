# Changelog

Development log for KonoNexus.

## Unreleased

- Added Ed25519-signed short-lived DHT peer records with NodeID/public-key binding.
- Added a bounded 4,096-record DHT-style table with expiry and rollback rejection.
- Added encrypted `DhtStore`, `DhtFind`, and `DhtNodes` control messages.
- Added bounded nearest-record responses using XOR distance over SHA-256(NodeID).
- Added exact-match DHT discovery for pending `--connect-node` targets while refusing to auto-dial arbitrary nearest gossip records.
- Added temporary DHT discovery candidates that still pass through normal HELLO/cookie/session admission.
- Added DHT endpoint publishability checks and unit coverage for tampering, rollback, bounds, and unsafe/local endpoints.
- Bumped the implementation package to 0.1.0-alpha.7.

- Added automatic bounded rendezvous coordinator selection across existing encrypted peers.
- Added explicit rendezvous-miss responses and automatic retry/cooldown behavior.
- Added per-requester rendezvous and filtering-test cooldowns.
- Added consent-based endpoint-independent filtering evidence using short-lived Ed25519 authorization.
- Bound filter authorization to the tested NodeID/public key, exact coordinator-observed endpoint, helper NodeID, and random token.
- Added positive filtering-evidence tracking while keeping negative results inconclusive.
- Added CLI controls `--connect-node` and `--filter-test` for controlled validation.
- Bumped the implementation package to 0.1.0-alpha.6.

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
