# Changelog

## 0.1.0-alpha.16

- Added the Windows x64 KonoNexus Network Tester GUI as the normal two-PC test surface.
- Added signed, versioned, 24-hour `KNX1` invite codes containing NodeID/public key and bounded endpoint hints, never private key material.
- Added runtime `connect` and diagnostics APIs for authenticated path method (`DIRECT`, `UDP HOLE PUNCH`, `RELAY`), NAT mapping/filtering evidence, endpoint evidence, peer counts, DHT state, and pending punch state.
- Added authenticated delivery RTT and loss sampling with a large `CONNECTED` / `FAILED` result and collapsible technical log.
- Added an original embedded application icon and retained the console probe only as a diagnostic binary in the Windows package.
- Updated Windows release automation to publish the GUI EXE, diagnostic probe, and a combined ZIP as a prerelease.

Development log for KonoNexus.

## Unreleased

- Bumped the active source and external-testing candidate to `0.1.0-alpha.19`, removed stale alpha labels from runtime surfaces and test documentation, made Windows release naming derive from the package manifest, and prevented later commits from replacing assets under an older version tag.
- Reopened roadmap claims for full control-plane/multi-relay migration and runtime-integrated path scoring because the current implementation proves RelayApp migration, bounded relay fallback, and deterministic direct preference rather than those broader guarantees.
- Added bounded runtime exchange and refresh of signed endpoint attestations; exact DHT activation requires two independent observer identities while explicitly not claiming Sybil resistance.
- Added stable owner-record refresh, bounded hop/fanout replica propagation, rollback high-watermarks, capability-gated legacy behavior, and paced owner-reserved replication queues.
- Added DHT query and record admission guards keyed by authenticated peer, observed IPv4 `/24` or IPv6 `/48`, and global budgets; invalid signed-record attempts consume budget before signature verification.
- Prevented expired DHT records from being returned by exact or nearest reads between periodic maintenance ticks.
- Bound every encrypted outer sender to the NodeID authenticated by its session before secure dispatch or routing admission.
- Added per-bucket observed-prefix caps and prefix-diverse nearest-peer ordering for DHT lookup and replication, with deterministic same-prefix fallback for availability.
- Applied the same prefix cap plus independent NodeID/endpoint deduplication to current and legacy persistent routing snapshots.
- Added version-2 persistence for the full bounded 256×8 DHT k-bucket membership snapshot while keeping restart entries untrusted until normal KNP re-authentication.
- Added local-NodeID binding, bucket-index validation, seven-day freshness checks, atomic replacement, legacy v1 migration, and a 256-endpoint restart bootstrap cap.

- Promoted the current core to **0.1.0-alpha.15**, the first controlled external-testing candidate.
- Added periodic relay-inner E2E rekey state with fresh X25519 material, bounded retries, cached ACKs, and previous-session grace handling.
- Added the initial `KonofixTransport` / `KonofixSdkConfig` wrapper for application integration.
- Added RelayApp delivery receipts and unified runtime events for message, delivered, and failed outcomes.
- Added a live three-node runtime harness that verifies discovery and B→C application delivery through the running KonoNexus mesh.
- Added an explicit loopback-only local test mode used solely by the harness; production rendezvous security remains unchanged by default.
- Fixed the local harness blocker caused by the intentional production rejection of loopback punch candidates.

- Added alpha.14 direct KNP session key rotation using fresh X25519/HKDF/ChaCha20-Poly1305 session material.
- Added deterministic lower-NodeID rekey initiation, ten-minute rotation cadence, one-second retry cadence, and four-send rekey retry bound.
- Added cached responder rekey ACKs so lost ACK retransmission returns the same responder ephemeral public key.
- Added `SessionSlot` with a 30-second previous-session grace window for authenticated in-flight frames during rekey.
- Added unit coverage proving old in-flight frames survive the grace window while new traffic uses the rotated session.
- Added NodeID-centric RelayApp transport selection: confirmed direct sessions are preferred, relay E2E remains fallback.
- Added live direct↔relay application migration without resetting message IDs, reassembly, retransmission, or ACK state.
- Added path-selection tests confirming direct preference and relay fallback.
- Bumped the implementation package to 0.1.0-alpha.14.

- Added application-visible `RelayAppDeliveryFailure` events with `RetriesExhausted` and `Expired` reasons and a live `RelayAppHandle::recv_failure()` channel.
- Added bounded direct-session handshake retransmission: one-second retry interval and at most four `SESSION_INIT` sends using the same handshake ID/ephemeral key.
- Added a ten-second bounded responder ACK cache so duplicate session-init packets receive the same responder public key instead of deriving conflicting sessions.
- Deferred responder-side encrypted control/application flush until the first authenticated encrypted frame confirms the initiator completed the session.
- Added bounded alternate relay selection: prefer the last rendezvous coordinator, then try up to three distinct existing encrypted peers without repeating failed candidates.
- Added rejection-driven relay failover and automatic cleanup when a direct or relay path becomes active.
- Bumped the implementation package to 0.1.0-alpha.13.

- Added a reusable 128-sequence sliding replay window and applied it to encrypted KNP sessions, relay forwarding, and endpoint relay paths.
- Authenticated encrypted UDP frames may now arrive out of order within the replay window while duplicates and frames older than the window remain rejected.
- Added RelayApp ACK-timeout retransmission: one-second timeout, up to four bounded retries, and automatic queue release after retry exhaustion.
- Added bounded delivered-message deduplication so retransmission after a lost ACK re-sends the ACK without delivering the same application message twice.
- Added tests for missing-fragment recovery, lost-ACK recovery, retry exhaustion, reordered secure frames, reordered relay cells, and replay rejection.
- Added relay abuse controls: max 16 circuits per NodeID, 128 cells/second per circuit direction, and 256 KiB/second per circuit direction.
- Added rate-window reset and per-node circuit-limit tests.
- Bumped the implementation package to 0.1.0-alpha.12.

- Added `RelayAppHandle`, a bounded async runtime API that remains usable while `KonoNode::run()` owns the network loop.
- Added application command responses through Tokio mpsc/oneshot channels and bounded receive-event delivery without blocking the network loop.
- Added end-to-end relay application fragmentation at 512-byte payload chunks with a 256 KiB message ceiling.
- Added bounded outbound backpressure: max 64 queued messages / 2 MiB, with messages retained until encrypted `RelayAppAck`.
- Added bounded inbound reassembly: max 64 assemblies / 4 MiB reserved memory, 30-second expiry, duplicate validation, metadata consistency checks, and bounded completed-message storage.
- Added four-fragment-per-tick application pacing and 120-second outbound queue expiry.
- Added MTU coverage proving a maximum application fragment fits the 3 KiB relay-cell budget after inner E2E encryption/framing.
- Removed the raw application-facing relay-cell receive path in favor of the authenticated E2E RelayApp layer.
- Bumped the implementation package to 0.1.0-alpha.11.

- Added a separate Ed25519-authenticated relay inner handshake bound to circuit ID and both endpoint NodeIDs.
- Added fresh X25519/HKDF/ChaCha20-Poly1305 end-to-end sessions inside cooperative relay circuits; the relay never receives the derived keys.
- Added inner encrypted relay PING/PONG validation, ciphertext tamper tests, circuit-binding tests, and expected-peer identity tests.
- Added endpoint-side relay transport sequence checks and inner secure-session replay protection.
- Added deterministic automatic fallback from an expired hole-punch burst to the same rendezvous coordinator as a single-hop relay.
- Limited raw relay cells to 3 KiB so nested hex + AEAD framing stays inside the 16 KiB KNP datagram ceiling.
- Bumped the implementation package to 0.1.0-alpha.10.

- Added persistent routing hints saved only from currently authenticated encrypted peers.
- Added routing-cache age/bounds validation, restart loading, configurable cache path, periodic refresh, and shutdown persistence.
- Cached peers remain untrusted bootstrap hints and must repeat the full KNP admission and encrypted handshake after restart.
- Added bounded cooperative relay circuit management with OPEN/OFFER/ACCEPT/READY/CLOSE control flow.
- Added explicit target-side relay acceptance tracking so unsolicited READY messages cannot create a local relay path.
- Added opaque relay cells capped at 8 KiB, per-direction sequence replay/rollback protection, 256-circuit limit, and 120-second idle expiry.
- Added `--relay-via` and `--routing-cache` CLI controls plus relay/cache unit tests.
- Bumped the implementation package to 0.1.0-alpha.9.

- Added an in-memory 256-bucket XOR-distance routing table populated only by established encrypted peers.
- Added bounded recursive multi-hop DHT queries with fanout 2 and a maximum of 3 hops.
- Added random query IDs, origin binding, duplicate-query suppression, short-lived reverse routes, forwarding cooldowns, and 8-second query state.
- Added encrypted reverse-path propagation for `DhtNodes` responses through intermediate KonoNexus peers.
- Added query retry scheduling and routing-table cleanup when encrypted peer sessions disappear.
- Preserved the rule that only an exact signed record for a locally requested NodeID may trigger a new outbound discovery connection.
- Added routing-table unit coverage and kept nearest-record gossip non-dialable by default.
- Bumped the implementation package to 0.1.0-alpha.8.

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
