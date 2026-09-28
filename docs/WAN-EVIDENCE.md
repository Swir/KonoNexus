# WAN evidence matrix

KonoNexus real-network validation must record evidence instead of treating localhost or CI as proof of Internet reachability.

## Required cases

| ID | Topology | Goal |
| --- | --- | --- |
| LAN | Two PCs on one LAN | Baseline authenticated delivery |
| NAT-NAT | Two unrelated home NATs | Hole-punch/direct evidence |
| NAT-MOBILE | Home NAT to mobile hotspot | Mixed-NAT evidence |
| MOBILE-MOBILE | Two mobile/CGNAT-style access networks | Relay fallback evidence |
| IPV6 | Public IPv6 on both sides where available | Native direct path evidence |
| DIRECT-DROP | Interrupt an established direct path | Direct-to-relay migration evidence |
| RELAY-DROP | Remove the active relay while an alternate is authenticated | Relay failover evidence |
| RESTART | Restart a node with persisted routing buckets | Re-authentication from untrusted hints |

A case is not marked as passed until both endpoints preserve their logs and the sender has a matching delivery receipt for the receiver's message. NAT labels are operator-provided topology descriptions, not inferred truth.

## Evidence bundle

For each run preserve:

- exact KonoNexus commit SHA and package version,
- case ID and machine role,
- local bind endpoint and observed external endpoint,
- NAT mapping/filtering evidence reported by KNP,
- selected path (direct, hole punch, or relay),
- peer NodeIDs,
- message ID and matching delivery or failure result,
- start/end timestamps,
- logs from both endpoints.

Do not store identity private keys or application payload contents in evidence bundles. Public endpoints and NodeIDs are metadata and should still be handled as potentially sensitive operational data.

## Current status

The repository has a green localhost three-node runtime harness. That remains useful regression coverage, but it is not real NAT/CGNAT evidence. The matrix above remains open until runs are collected from separate physical networks.
