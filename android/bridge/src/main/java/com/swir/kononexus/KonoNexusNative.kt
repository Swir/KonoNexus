package com.swir.kononexus

import java.io.Closeable
import java.util.concurrent.atomic.AtomicLong

/**
 * Lifecycle-safe Kotlin boundary for the KonoNexus JSON transport bridge.
 *
 * request(), pollEvent(), and close() may block and must run away from the Android main thread.
 * The JSON schema is versioned independently from this wrapper.
 */
object KonoNexusNative {
    const val BRIDGE_DOMAIN: String = "kononexus/android-transport"
    const val BRIDGE_VERSION: Int = 1
    const val MAX_POLL_TIMEOUT_MS: Long = 60_000L

    init {
        System.loadLibrary("kononexus")
    }

    @JvmStatic
    private external fun nativeStart(configJson: String): Long

    @JvmStatic
    private external fun nativeInfo(handle: Long): String

    @JvmStatic
    private external fun nativeRequest(handle: Long, requestJson: String): String

    @JvmStatic
    private external fun nativePollEvent(handle: Long, timeoutMs: Long): String?

    @JvmStatic
    private external fun nativeStop(handle: Long): Boolean

    @JvmStatic
    fun start(configJson: String): Session {
        require(configJson.isNotBlank()) { "configJson must not be blank" }
        val handle = nativeStart(configJson)
        check(handle > 0L) { "KonoNexus native bridge returned an invalid handle" }
        return Session(handle)
    }

    class Session internal constructor(handle: Long) : Closeable {
        private val nativeHandle = AtomicLong(handle)

        fun info(): String = nativeInfo(liveHandle())

        fun request(requestJson: String): String {
            require(requestJson.isNotBlank()) { "requestJson must not be blank" }
            return nativeRequest(liveHandle(), requestJson)
        }

        fun pollEvent(timeoutMs: Long): String? {
            require(timeoutMs in 0L..MAX_POLL_TIMEOUT_MS) {
                "timeoutMs must be between 0 and $MAX_POLL_TIMEOUT_MS"
            }
            return nativePollEvent(liveHandle(), timeoutMs)
        }

        val isClosed: Boolean
            get() = nativeHandle.get() == 0L

        override fun close() {
            val handle = nativeHandle.getAndSet(0L)
            if (handle != 0L) {
                check(nativeStop(handle)) { "KonoNexus native bridge did not stop cleanly" }
            }
        }

        private fun liveHandle(): Long {
            val handle = nativeHandle.get()
            check(handle != 0L) { "KonoNexus transport session is closed" }
            return handle
        }
    }
}
