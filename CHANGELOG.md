# Changelog

Development log for KonoNexus.

## Unreleased

- Integrated bounded replay protection into live UDP packet handling.
- Added stateless HMAC-SHA256 endpoint cookies before new inbound peer admission.
- Added a bounded active peer table and ignored unsolicited HELLO_ACK/PING/PONG admission attempts.
- Bumped the protocol implementation package to 0.1.0-alpha.2.
- Added the KonoMind adaptive-routing advisory scaffold.
- Added deterministic route scoring and bounded network metric inputs.
- Added observation counters and unit tests as groundwork for future local learning.
- KonoMind remains advisory-only; no learned model is claimed yet.
