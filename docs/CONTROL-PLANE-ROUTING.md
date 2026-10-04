# Control-plane routing

This note documents the bounded route-selection layer used by KNP application traffic. It is intentionally limited to paths that already exist and have already passed KNP authentication.

## Route inputs

For a target NodeID the controller may receive:

- one confirmed direct KNP endpoint; and
- zero or more established relay E2E circuits whose relay-facing KNP session and inner E2E session are already active.

The controller never discovers arbitrary Internet ports, synthesizes port ranges, or dials relay addresses merely because they rank well. Candidate production remains the responsibility of authenticated rendezvous, DHT, session, and relay-control code.

## Selection invariants

1. A confirmed direct path preempts relay transport unless that exact route is in its five-second hard-failure cooldown.
2. Relay candidates are normalized deterministically by address family, endpoint, and circuit ID.
3. Duplicate relay candidates are removed.
4. At most three established relay candidates are considered for one selection.
5. If the currently selected relay remains within the fixed score hysteresis of the best bounded candidate, it remains selected. This avoids churn from small metric changes.
6. A changed path increments the route generation exactly once. Stable re-selection keeps the generation unchanged.

The controller uses KonoMind's deterministic baseline score for the established relay candidates. Route health is keyed by peer and exact route, bounded to 2,048 entries, and uses a sanitized 0.8/0.2 RTT EWMA plus a smoothed success/failure reliability estimate. Reliability feeds both loss and stability; unmeasured relay load stays at a neutral value rather than being presented as observed data. Failed routes are excluded for five seconds. Among relays, the current route remains active when its score is within 0.08 of the best candidate. A healthy confirmed direct route always takes precedence; after its failure cooldown expires it becomes preferred again.

RelayApp route evidence is bounded to 64 outbound messages. For each message, the latest successfully handed-off fragment attempt records its exact route and time. A delivery ACK contributes an RTT and success only when it is authenticated and received over that same direct endpoint or relay endpoint/circuit. An ACK on another route still confirms application delivery but is not used as route evidence. Local UDP send success alone is never scored as path success. Hard send errors and final retry exhaustion or TTL expiry mark the associated route failed.

These rules cannot alter packet authentication, cryptography, admission, replay validation, or the established three-candidate safety limit.

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
- cooldown-based selection and direct-path recovery;
- health-scored relay choice and hysteresis;
- peer/route health isolation, bounded RTT metrics, and bounded latest-attempt tracking;
- matching versus mismatching authenticated ACK route samples; and
- clearing control-plane state after all routes disappear.

CI verifies formatting, Clippy with warnings denied, and the complete Rust test suite. These tests prove the internal route-selection semantics only. They are **not** evidence that arbitrary NAT/CGNAT combinations work in the field.

The roadmap item **Real multi-network/NAT test matrix** therefore remains open until results are collected from actual independent networks.
