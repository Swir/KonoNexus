# Konofix Windows application integration evidence

The KonoNexus roadmap item **Konofix Windows application integration** is closed
by the application repository's merged runtime, exact SDK pin, regression suite and
qualified Windows artifact. This is application evidence, not a source-only claim.

## Integrated application path

Konofix main commit
[`628082b0cb1f227deb45cca8ef24ce33f053c21d`](https://github.com/Swir/Konofix/commit/628082b0cb1f227deb45cca8ef24ce33f053c21d)
pins both Windows-consumer manifests and the committed lockfile to KonoNexus
`ee97b8b6c56467eeff9aee9f93e9375582005541`. The Windows Tauri runtime:

- starts `KonofixTransport` with persistent identity and routing-cache paths;
- exposes connect, invite-connect, send, diagnostics and bounded shutdown commands;
- maps authenticated message, delivery and failure events into Tauri events;
- closes command admission before transport teardown and releases the UDP socket;
- preserves control responsiveness and event order while the frontend output is full.

Native libp2p remains Konofix's primary chat network. KNP remains the optional
transport/identity path; this evidence does not replace or weaken that architecture.

## Exact-head qualification

Konofix PR [#188](https://github.com/Swir/Konofix/pull/188) exact head
`6a2d8a43cd02abd045d4ba439716c3c7b8f90a22` passed:

- [Windows CI #1232](https://github.com/Swir/Konofix/actions/runs/37798063638):
  full Rust tests, the original captured 24-process KNP restart batch, timer
  cancellation, production Tauri build, installed Chat startup smoke, Node and
  Netprobe builds/smoke, bundle integrity and adversarial provenance checks;
- [Linux Node CI #974](https://github.com/Swir/Konofix/actions/runs/37798063699);
- [RustSec Audit #574](https://github.com/Swir/Konofix/actions/runs/37798063795).

The new consumer regression runs the SDK with event capacity one, fills the
**sender's** bridge output with a real inbound message, sends two authenticated
messages while output remains blocked, and requires both delivery receipts in FIFO
order. This directly covers the receipt-loss mechanism fixed by KonoNexus #31 while
retaining the earlier receiver-backpressure, lifecycle, ordering and socket-release
coverage.

The qualified Windows artifact is
`Konofix-Chat-0.5.2-Windows-8d37caec1041cd9f8fd2a0c30f60372fd0652d06`
(artifact ID `11560721173`, archive SHA-256
`1b33020092f589f6d02d8a62e4c6ad87d41ff9c155b7a0af447b27ea817e9c40`,
expires 2026-10-22). The retained original-harness evidence artifact is ID
`11560351049`, SHA-256
`3dd74b3111d402874138881d3f922895c226088179897849fdfa298de7049e35`.

## Boundary of this gate

This closes only the Windows **application integration** item. It does not claim a
stable 1.0 release, Android integration, public discovery readiness or a real
multi-network/NAT/CGNAT pass. The physical WAN failure and the separate seven-row
KonoNexus network matrix remain open and must not be inferred from localhost or CI
results.
