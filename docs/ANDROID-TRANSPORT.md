# Android transport bridge

KonoNexus can be embedded in an Android application through a small Kotlin/JNI boundary while the networking, identity, routing-cache, framing, encryption, receipts, and path-selection behavior remain in the Rust transport. The bridge does **not** define a second wire protocol: it accepts the existing versioned SDK request JSON and emits the existing SDK response/event JSON.

This is an integration slice, not yet evidence that the Android roadmap gate is complete. That gate requires a packaged Android consumer and device/emulator qualification.

## Build

Install the Android NDK, Rust Android targets, and `cargo-ndk`, then build the shared libraries:

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o android/src/main/jniLibs \
  build --release --locked --no-default-features --features android-jni --lib
```

Copy `android/src/main/java/com/swir/kononexus/KonoNexusNative.kt` into the consuming Android module (or package both the Kotlin source and `jniLibs` in an AAR). The JNI ABI is intentionally bound to the class name `com.swir.kononexus.KonoNexusNative`.

The application manifest needs network access:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

## Start a session

Use app-private persistent files for the identity and routing cache. Never put the identity file in shared/external storage.

```kotlin
val config = """
{
  "domain": "kononexus/android-transport",
  "version": 1,
  "identity_path": "${filesDir.resolve("kononexus-identity.key")}",
  "routing_cache_path": "${filesDir.resolve("kononexus-routing.json")}",
  "bind": "0.0.0.0:0",
  "seed_peers": ["203.0.113.10:47000"],
  "hello_interval_ms": 2000,
  "event_capacity": 64,
  "local_test_mode": false
}
""".trimIndent()

val session = KonoNexusNative.start(config)
val infoJson = session.info()
```

`local_test_mode` must remain `false` in production. It exists so the platform-neutral bridge can be exercised deterministically on loopback CI without weakening production validation.

## Requests, events, and lifecycle

`Session.request(requestJson)` accepts exactly the existing `konofix/sdk-request` envelope and returns a `konofix/sdk-response` envelope. `Session.pollEvent(timeoutMs)` returns an existing `konofix/sdk-event` envelope, or `null` when the bounded timeout expires. The timeout range is 0–60,000 ms.

All three calls—`request`, `pollEvent`, and `close`—may block. Invoke them from a coroutine dispatcher or worker thread, not the Android main thread. One session owns one durable node identity, one UDP socket, and one bounded event queue. Always close it:

```kotlin
withContext(Dispatchers.IO) {
    KonoNexusNative.start(config).use { session ->
        val response = session.request(requestJson)
        while (isActive) {
            session.pollEvent(1_000)?.let(::handleSdkEvent)
        }
    }
}
```

The Rust worker reserves event-queue capacity before consuming the next transport event. A slow Android consumer therefore applies bounded backpressure instead of silently dropping delivery receipts. Closing a session is idempotent from Kotlin and shuts down the transport before releasing its native handle.

## Version and compatibility contract

- Android config domain: `kononexus/android-transport`, version `1`.
- SDK requests/responses/events retain their existing domains and versions.
- Unknown config fields are rejected.
- Seed endpoints, event capacity, path lengths, and poll timeouts are bounded.
- This bridge adds no public KNP frame, packet type, or peer-visible behavior.
