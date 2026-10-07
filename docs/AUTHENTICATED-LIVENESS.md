# Authenticated peer liveness

The peer idle lease is four configured HELLO intervals. Before this fix, a valid
encrypted frame updated authenticated routing/session state but did not update
the admitted peer's `last_seen`. A peer could therefore expire while exchanging
fresh authenticated data if no HELLO/HELLO_ACK had recently renewed that lease.

The receive path now refreshes `last_seen` only after the outer signature and
nonce, session identity binding, AEAD and session replay window have passed.
The idle duration is unchanged. Unknown endpoints, wrong identities, invalid
ciphertext and replayed frames cannot renew or create a peer lease.

The regression establishes real paired session keys, backdates only the recorded
peer activity, and processes a signed encrypted Pong through `handle_datagram`.
It uses no sleep or external network. Against main
`a0d8232941d5f708a0f5ddb69cca07f5bbf99790` with only that test added, it fails at
`authenticated encrypted activity must refresh the peer lease` (0.02 s).
With the receive-path update it passes (0.08 s), including outer/frame replay,
wrong-identity, unadmitted-endpoint and ciphertext rejection followed by expiry.

This is an independently reproduced lease defect. It was found while examining
Konofix #181 receipt timeout/retry exhaustion, but has not been established as
the cause of either recorded stress failure or historical KNP restart hangs.
Konofix's pinned SDK commit is unchanged by this upstream patch. No WAN result,
production readiness, timeout increase or dependency upgrade is implied.
