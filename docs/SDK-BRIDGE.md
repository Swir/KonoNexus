# KonoNexus SDK JSON bridge v1

Status: integration-ready local host contract for `0.1.0-alpha.28`.

The SDK bridge gives Konofix and future platform bindings a small, language-neutral JSON boundary around `KonofixTransport`. It is a local application ABI only: it does **not** change the KNP UDP wire format, relax transport admission, or prove that the Windows or Android application integration is complete.

Every envelope uses the exact domain `kononexus/sdk-bridge` and version `1`. Unknown fields, other domains and other versions are rejected. A `request_id` is supplied by the host, contains 1–64 bytes and has no control characters; the same value is returned in the response.

## Send

Request:

```json
{"domain":"kononexus/sdk-bridge","version":1,"request_id":"send-42","command":{"type":"send","peer_node_id":"knp1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","data_base64":"aGVsbG8="}}
```

Accepted response:

```json
{"domain":"kononexus/sdk-bridge","version":1,"request_id":"send-42","result":{"status":"sent","message_id":7}}
```

Payloads use canonical padded RFC 4648 Base64 and must contain 1 through 262144 decoded bytes. `peer_node_id` is the `knp1` prefix followed by exactly 40 hexadecimal characters. `sent` means the bounded RelayApp queue accepted the message; observe a later `delivered` or `failed` event for its terminal outcome.

## Connect

Request:

```json
{"domain":"kononexus/sdk-bridge","version":1,"request_id":"connect-9","command":{"type":"connect","peer_node_id":"knp1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","endpoints":["192.168.1.8:47000","[2001:db8::8]:47000"]}}
```

Accepted response:

```json
{"domain":"kononexus/sdk-bridge","version":1,"request_id":"connect-9","result":{"status":"connected"}}
```

One to three unique, exact `IP:port` endpoints are allowed. Port zero, unspecified, multicast and IPv4 broadcast addresses are rejected. The bridge never scans adjacent ports or derives additional endpoints. `connected` means that the request entered the existing bounded connection planner; authenticated session establishment and delivery remain asynchronous.

## Events

Incoming binary message:

```json
{"domain":"kononexus/sdk-bridge","version":1,"event":{"type":"message","peer_node_id":"knp1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","message_id":7,"data_base64":"AAH+/w=="}}
```

Terminal delivery events:

```json
{"domain":"kononexus/sdk-bridge","version":1,"event":{"type":"delivered","peer_node_id":"knp1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","message_id":7}}
```

```json
{"domain":"kononexus/sdk-bridge","version":1,"event":{"type":"failed","peer_node_id":"knp1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","message_id":7,"reason":"retries_exhausted"}}
```

Failure reasons in v1 are `retries_exhausted` and `expired`.

## Rust host flow

1. Deserialize untrusted host JSON with `KonofixSdkRequest::from_json_verified`.
2. Call `request.execute(&transport).await` and serialize the response with `to_json`.
3. Read `transport.next_event().await`, convert it using `KonofixSdkEventEnvelope::from_relay_event`, then serialize with `to_json`.

Malformed requests return a Rust error before any transport action. An accepted request whose transport operation fails receives a `rejected` result with code `transport_error`. Hosts should treat the `code` as stable and the human-readable `message` as diagnostic text.

## Process host

`kononexus_sdk_host` keeps the transport and identity alive for a native parent process. Start it with an application-owned state directory:

```powershell
.\kononexus_sdk_host.exe --identity .\state\node.key --routing-cache .\state\routing.json --bind 0.0.0.0:47000
```

Add reachable bootstrap peers with repeatable `--peer IP:PORT` options. The host writes a single readiness record containing its NodeID and bound address to stderr. Standard input and standard output are JSON Lines streams:

- write exactly one v1 request JSON object per input line;
- read exactly one correlated response or asynchronous event JSON object per output line;
- keep stdout machine-only; human-readable lifecycle diagnostics use stderr;
- close stdin for a clean shutdown, or send the normal console interrupt signal.

Malformed JSON and invalid envelopes produce a `rejected` response with code `invalid_request`; a safe supplied `request_id` is preserved, otherwise the host uses `invalid-request`. Each input line is capped at the Base64 size of one maximum RelayApp payload plus bounded envelope overhead. Oversized or non-UTF-8 input is drained through its newline, rejected, and cannot desynchronize later requests. The process continues accepting later requests. This recovery behavior is covered by unit and child-process integration tests.
