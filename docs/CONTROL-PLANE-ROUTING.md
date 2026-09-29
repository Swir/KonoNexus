# Control-plane routing

This note documents the bounded route-selection layer used by KNP application traffic. It is intentionally limited to paths that already exist and have already passed KNP authentication.

## Route inputs

For a target NodeID the controller may receive:

- one confirmed direct KNP endpoint; and
- zero or more established relay E2E circuits whose relay-facing KNP session and inner E2E session are already active.

The controller never discovers arbitrary Internet ports, synthesizes port ranges, or dials relay addresses merely because they rank well. Candidate production remains the responsibility of authenticated rendezvous, DHT, session, and relay-control code.

## Selection invariants

1. A confirmed direct path always preempts relay transport.
2. Relay candidates are normalized deterministically by address family, endpoint, and circuit ID.
3. Duplicate relay candidates are removed.
4. At most three established relay candidates are considered for one selection.
5. If the currently selected relay still appears in the bounded candidate set, it remains selected. This stickiness avoids path churn caused only by input ordering.
6. A changed path increments the route generation exactly once. Stable re-selection keeps the generation unchanged.

These rules are deterministic and independent of KonoMind. KonoMind remains advisory-only and cannot alter packet authentication, cryptography, admission, replay validation, or the bounded safety limits above.

## Migration and failover

RelayApp transmission asks the controller for a route at send time.

- **relay → direct:** when a confirmed direct KNP session appears, the next selection migrates to direct.
- **direct → relay:** when the direct session is no longer confirmed, an already-established relay E2E circuit may be selected.
- **relay → relay:** when an active relay circuit is closed, rejected, expires, or a send fails, its client-side path state is removed and invalidated before another selection. A remaining established relay may then be selected.
- **no usable path:** the application message stays under the existing bounded RelayApp queue/backpressure/TTL behavior; no unbounded dialing loop is introduced.

A relay send failure also feeds the existing bounded automatic relay-fallback state. That fallback may attempt only already-authenticated relay peers under the existing three-candidate/30-second limits.

## Evidence

The deterministic unit tests cover:

- direct preemption and stable generation tracking;
- relay ordering and stickiness;
- failover from a failed relay to another established circuit;
- the three-candidate selection bound; and
- clearing control-plane state after all routes disappear.

CI verifies formatting, Clippy with warnings denied, and the complete Rust test suite. These tests prove the internal route-selection semantics only. They are **not** evidence that arbitrary NAT/CGNAT combinations work in the field.

The roadmap item **Real multi-network/NAT test matrix** therefore remains open until results are collected from actual independent networks.
