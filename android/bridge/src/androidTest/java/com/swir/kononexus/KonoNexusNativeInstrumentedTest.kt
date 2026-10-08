package com.swir.kononexus

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KonoNexusNativeInstrumentedTest {
    @Test
    fun twoNativeSessionsExchangeMessageAndAuthenticatedReceipt() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "kononexus-${System.nanoTime()}").apply {
            check(mkdirs()) { "unable to create native test directory" }
        }
        val receiver = KonoNexusNative.start(config(root, "receiver"))
        val sender = KonoNexusNative.start(config(root, "sender"))

        try {
            val receiverInfo = JSONObject(receiver.info())
            val senderInfo = JSONObject(sender.info())
            assertEquals(KonoNexusNative.BRIDGE_DOMAIN, receiverInfo.getString("domain"))
            assertEquals(KonoNexusNative.BRIDGE_VERSION, receiverInfo.getInt("version"))
            assertTrue(senderInfo.getString("node_id").isNotBlank())

            val connect = request(
                id = "connect",
                command = JSONObject()
                    .put("type", "connect")
                    .put("peer_node_id", receiverInfo.getString("node_id"))
                    .put(
                        "endpoints",
                        JSONArray().put(receiverInfo.getString("local_addr")),
                    ),
            )
            val connectResponse = JSONObject(sender.request(connect.toString()))
            assertEquals("connected", connectResponse.getJSONObject("result").getString("status"))

            val payload = "android-emulator".toByteArray(Charsets.UTF_8)
            val send = request(
                id = "send",
                command = JSONObject()
                    .put("type", "send")
                    .put("peer_node_id", receiverInfo.getString("node_id"))
                    .put("data_base64", Base64.encodeToString(payload, Base64.NO_WRAP)),
            )
            val sendResponse = JSONObject(sender.request(send.toString()))
            val result = sendResponse.getJSONObject("result")
            assertEquals("sent", result.getString("status"))
            val messageId = result.getLong("message_id")

            val deadline = System.nanoTime() + 20_000_000_000L
            var received = false
            var delivered = false
            while (System.nanoTime() < deadline && !(received && delivered)) {
                receiver.pollEvent(100)?.let { json ->
                    val event = JSONObject(json).getJSONObject("event")
                    if (event.getString("type") == "message") {
                        received =
                            event.getLong("message_id") == messageId &&
                                event.getString("data_base64") ==
                                Base64.encodeToString(payload, Base64.NO_WRAP)
                    }
                }
                sender.pollEvent(100)?.let { json ->
                    val event = JSONObject(json).getJSONObject("event")
                    if (event.getString("type") == "delivered") {
                        delivered = event.getLong("message_id") == messageId
                    }
                }
            }

            assertTrue("receiver did not observe the native UDP message", received)
            assertTrue("sender did not observe the authenticated receipt", delivered)
        } finally {
            sender.close()
            receiver.close()
            assertTrue(sender.isClosed)
            assertTrue(receiver.isClosed)
            sender.close()
            receiver.close()
            root.deleteRecursively()
            assertFalse(root.exists())
        }
    }

    private fun config(root: File, name: String): String =
        JSONObject()
            .put("domain", KonoNexusNative.BRIDGE_DOMAIN)
            .put("version", KonoNexusNative.BRIDGE_VERSION)
            .put("identity_path", File(root, "$name.key").absolutePath)
            .put("routing_cache_path", File(root, "$name-routing.json").absolutePath)
            .put("bind", "127.0.0.1:0")
            .put("seed_peers", JSONArray())
            .put("hello_interval_ms", 100)
            .put("event_capacity", 8)
            .put("local_test_mode", true)
            .toString()

    private fun request(id: String, command: JSONObject): JSONObject =
        JSONObject()
            .put("domain", "kononexus/sdk-bridge")
            .put("version", 1)
            .put("request_id", id)
            .put("command", command)
}
