# Relay adaptive quota hardening

This note defines the next relay-abuse hardening step after the existing per-circuit one-second quotas and per-node circuit cap. It is a design/evidence contract, not WAN/NAT evidence.

## Goals

- keep longer-lived relay load accounting bounded in memory;
- aggregate usage by authenticated KNP NodeID rather than by arbitrary UDP source address;
- preserve the existing one-second per-circuit cell/byte ceilings;
- add a longer deterministic accounting window that catches sustained multi-circuit load;
- tighten quotas after repeated overload and recover them deterministically after quiet windows;
- keep KonoMind advisory-only: it may observe outcomes, but cannot bypass crypto, authentication, replay checks, packet validation, consent, or hard safety limits.

## Proposed bounded state

A relay keeps at most 512 NodeID accounting records. A record contains only:

- window start;
- last-seen timestamp;
- accepted cell count;
- accepted byte count;
- bounded penalty level 0..3.

The longer accounting window is 60 seconds. Base per-node limits are derived from the current per-second relay limits, so one normally behaving circuit does not become slower merely because the longer window exists.

When the tracker is full, a new NodeID is not admitted until an expired accounting record is pruned. State older than five minutes without traffic is eligible for pruning. There is no unbounded endpoint or port history.

## Adaptive quota rule

Penalty level is deterministic and bounded:

- level 0: 100% of the long-window allowance;
- level 1: 50%;
- level 2: 25%;
- level 3: 12.5%.

A rejected over-limit attempt increments the level by one, capped at 3. Each complete quiet accounting window decays the level by one. Counts reset only on a window transition; they never wrap.

The one-second per-circuit quota remains an independent hard ceiling. Adaptive accounting never raises a hard limit.

## Required deterministic tests

Implementation is not complete until CI covers all of the following:

1. aggregate load from two circuits owned by the same authenticated NodeID shares one long-window budget;
2. a different NodeID has an independent budget;
3. repeated overload reaches the bounded penalty cap and never exceeds it;
4. one and multiple quiet windows decay the penalty deterministically;
5. byte and cell limits both reject at their exact boundaries;
6. the tracker never exceeds 512 entries and stale entries are pruned before admitting a replacement;
7. invalid/replayed relay cells cannot bypass existing replay validation;
8. no adaptive decision changes cryptographic, authentication, consent, packet-validation, or KNP admission semantics.

## Evidence boundary

Green unit/integration tests prove only deterministic internal quota semantics. They do not prove real WAN, NAT, or CGNAT behavior. The roadmap item for the real multi-network/NAT matrix stays open until external evidence exists.
