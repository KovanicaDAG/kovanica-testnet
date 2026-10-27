package io.kovanica.comms

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Non-2xx relay response. The relay error body is
 * `{"error":{"code":"<slug>","message":"..."}}` with slugs `bad_request`,
 * `too_large`, `not_found`, `rate_limited`, `internal`.
 */
class RelayException(val status: Int, val code: String, override val message: String) : Exception(message)

/**
 * Blocking JSON client for the off-chain comms relay (HTTP v1). Call it off
 * the UI thread — there is no async here, matching [NodeClient].
 *
 * `baseUrl` is the relay origin (e.g. `http://10.0.2.2:8787`); the `/v1` path
 * prefix is added here. A trailing slash on `baseUrl` is tolerated.
 */
class RelayClient(baseUrl: String) {
    private val base: String = baseUrl.trimEnd('/')

    /** `GET /v1/health` -> `ok`. */
    fun health(): Boolean {
        val reply = request("GET", "/v1/health", null)
        return try {
            JSONObject(reply.text).optBoolean("ok", false)
        } catch (_: Exception) {
            false
        }
    }

    /** `POST /v1/envelope` with a bare envelope -> the 64-hex envelope id. */
    fun postEnvelope(envelopeJson: String): String {
        val reply = request("POST", "/v1/envelope", envelopeJson)
        val id = try {
            JSONObject(reply.text).optString("id")
        } catch (_: Exception) {
            ""
        }
        if (id.isNotEmpty()) return id
        // The relay echoes `id` on success; fall back to the envelope's own id
        // (mirrors `relay.ts` `postEnvelope`) before giving up.
        val own = try {
            JSONObject(envelopeJson).optString("id")
        } catch (_: Exception) {
            ""
        }
        if (own.isNotEmpty()) return own
        throw RelayException(reply.status, "internal", "relay returned no envelope id")
    }

    /** `GET /v1/inbox/{comms_id}` -> raw envelope JSON strings, oldest-first. */
    fun getInbox(commsId: String, limit: Int = 50, sinceMs: Long? = null): List<String> {
        val path = StringBuilder("/v1/inbox/").append(commsId)
            .append("?limit=").append(limit)
        if (sinceMs != null) {
            path.append("&since=").append(sinceMs)
        }
        val reply = request("GET", path.toString(), null)
        val envelopes = try {
            JSONObject(reply.text).optJSONArray("envelopes")
        } catch (_: Exception) {
            null
        } ?: throw RelayException(reply.status, "internal", "relay inbox response missing envelopes")
        val out = ArrayList<String>(envelopes.length())
        for (i in 0 until envelopes.length()) {
            out.add(envelopes.get(i).toString())
        }
        return out
    }

    /** `POST /v1/ack` -> number of deleted envelopes. */
    fun ack(commsId: String, ids: List<String>): Int {
        val array = JSONArray()
        for (id in ids) {
            array.put(id)
        }
        val body = JSONObject()
            .put("to", commsId)
            .put("ids", array)
            .toString()
        val reply = request("POST", "/v1/ack", body)
        return try {
            JSONObject(reply.text).optInt("deleted", 0)
        } catch (_: Exception) {
            0
        }
    }

    private class Reply(val status: Int, val text: String)

    private fun request(method: String, path: String, body: String?): Reply {
        val connection = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        if (body != null) {
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
        if (status !in 200..299) {
            throw relayError(status, text)
        }
        return Reply(status, text)
    }

    /** Map `{"error":{"code","message"}}` to [RelayException]. */
    private fun relayError(status: Int, text: String): RelayException {
        val parsed = try {
            if (text.isNotEmpty()) JSONObject(text) else null
        } catch (_: Exception) {
            null
        }
        val error = parsed?.optJSONObject("error")
        val code = error?.optString("code").orEmpty().ifEmpty { "internal" }
        val message = error?.optString("message").orEmpty().ifEmpty { "relay HTTP $status" }
        return RelayException(status, code, message)
    }
}
